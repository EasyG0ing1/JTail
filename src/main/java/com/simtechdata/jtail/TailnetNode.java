package com.simtechdata.jtail;

import com.simtechdata.jtail.control.ControlClient;
import com.simtechdata.jtail.control.ControlException;
import com.simtechdata.jtail.control.Hostinfo;
import com.simtechdata.jtail.derp.DerpManager;
import com.simtechdata.jtail.crypto.Hex;
import com.simtechdata.jtail.filter.PacketFilter;
import com.simtechdata.jtail.magicsock.Magicsock;
import com.simtechdata.jtail.net.HttpProxy;
import com.simtechdata.jtail.net.TailnetDialer;
import com.simtechdata.jtail.net.TailnetServerSocket;
import com.simtechdata.jtail.net.TailnetSocketFactory;
import com.simtechdata.jtail.net.TailnetSocket;
import com.simtechdata.jtail.netstack.Netstack;
import com.simtechdata.jtail.netstack.TcpConn;
import com.simtechdata.jtail.netstack.TcpListener;
import com.simtechdata.jtail.netstack.UdpSocket;
import com.simtechdata.jtail.state.NodeIdentity;
import com.simtechdata.jtail.tailcfg.Derp;
import com.simtechdata.jtail.tailcfg.IpPrefix;
import com.simtechdata.jtail.tailcfg.MapResponse;
import com.simtechdata.jtail.tailcfg.NetMap;
import com.simtechdata.jtail.tailcfg.Node;
import com.simtechdata.jtail.wg.WgDevice;
import com.simtechdata.jtail.wg.WgPeer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.ServerSocket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** The live node: owns the control session, WireGuard device, path engine, DERP links and userspace stack. */
final class TailnetNode implements Tailnet {
    private static final System.Logger LOG = System.getLogger("com.simtechdata.jtail");

    private final JTailConfig cfg;
    private final NodeIdentity identity;
    private final Hostinfo hostinfo;
    private final ControlClient control;
    private volatile DerpManager derp;
    private volatile Magicsock ms;
    private volatile WgDevice dev;
    private final ExecutorService worker = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "jtail-node");
        t.setDaemon(true);
        return t;
    });
    private final CountDownLatch ready = new CountDownLatch(1);
    private final AtomicBoolean closed = new AtomicBoolean();
    /** Proxies started with {@code startHttpProxy}; closed with the node. Guarded by itself. */
    private final java.util.List<HttpProxy> proxies = new java.util.ArrayList<>();
    private final AtomicBoolean liteUpdatePending = new AtomicBoolean();

    private volatile Netstack stack;
    private volatile PacketFilter filter = PacketFilter.compile(List.of()); // deny until the netmap says otherwise
    private volatile NetMap.Snapshot snap = new NetMap.Snapshot(null, List.of(), null, null, "", List.of(), List.of());
    private volatile Map<String, InetAddress> names = Map.of();
    private final com.simtechdata.jtail.dns.DnsResolver dns = new com.simtechdata.jtail.dns.DnsResolver(
            port -> { try { return requireStack().bindUdp(port); } catch (IOException e) { throw new java.io.UncheckedIOException(e); } },
            ip -> dev != null && dev.routeFor(ip) != null);
    private volatile boolean homeChosen;
    private volatile long homeChosenAtNanos;
    private volatile Throwable controlFailure;
    private volatile boolean controlUp;   // true while the streaming netmap session is established
    private Thread controlThread;

    private TailnetNode(JTailConfig cfg) throws IOException {
        this.cfg = cfg;
        this.identity = cfg.stateDir() != null
                ? NodeIdentity.loadOrCreate(cfg.stateDir().resolve("identity.properties"))
                : NodeIdentity.generate();
        this.hostinfo = new Hostinfo(cfg.hostname());
        this.hostinfo.requestTags.addAll(cfg.advertiseTags());
        this.control = new ControlClient(cfg.controlUrl(), identity);
    }

    /** Builds the data plane. Done after registration because registration may rotate the node key. */
    private void initDataPlane() throws IOException {
        this.derp = new DerpManager(identity.nodePrivate(), (region, src, data) -> ms.onDerpPacket(region, src, data));
        this.ms = new Magicsock(identity, derp, cfg.udpPort(), cfg.includeLoopbackEndpoints());
        this.dev = new WgDevice(identity.nodePrivate(), ms::send, (peer, pkt) -> {
            Netstack s = stack;
            if (s != null) s.deliver(pkt);
        });
        ms.bind(dev);
        ms.setDirectPaths(cfg.directPaths());
        ms.setEndpointListener(eps -> requestLiteUpdate());
    }

    static Tailnet join(JTailConfig cfg) {
        TailnetNode n = null;
        try {
            n = new TailnetNode(cfg);
            n.start();
            return n;
        } catch (JTailException e) {
            if (n != null) n.close();
            throw e;
        } catch (IOException | RuntimeException e) {
            if (n != null) n.close();
            throw new JTailException("failed to join tailnet: " + e.getMessage(), e);
        }
    }

    // ---- startup ----

    private void start() throws IOException {
        ControlClient.RegisterResult r = registerWithRetry(null);
        if (r.nodeKeyExpired()) { // the server remembers this node but its key has expired: rotate and re-register
            byte[] old = identity.rotateNodeKey();
            r = registerWithRetry(old);
            if (r.nodeKeyExpired()) {
                throw new JTailException("the control server still reports this node's key as expired after rotating it; "
                        + "the node may need to be re-approved or removed in the admin console");
            }
        }
        if (!r.error().isEmpty()) throw new JTailException("control server refused registration: " + r.error());
        if (!r.authUrl().isEmpty()) {
            if (cfg.loginHandler() == null) {
                throw new JTailException("interactive login is required at " + r.authUrl()
                        + " (supply a reusable auth key, or an onLoginRequired handler)");
            }
            cfg.loginHandler().accept(r.authUrl());
            r = control.registerFollowup(hostinfo, cfg.ephemeral(), r.authUrl()); // blocks until the user finishes login
            if (!r.error().isEmpty()) throw new JTailException("control server refused registration: " + r.error());
            if (!r.authUrl().isEmpty()) throw new JTailException("login was not completed (still pending at " + r.authUrl() + ")");
        }
        if (!r.machineAuthorized()) LOG.log(System.Logger.Level.WARNING,
                "node registered but is awaiting administrator approval in the tailnet; peers will not be visible yet");

        initDataPlane();
        ms.start();
        if (cfg.directPaths()) ms.refreshEndpoints();   // DERP-only nodes advertise no UDP endpoints
        pushUpdateNow();                       // publishes our disco key and endpoints before streaming

        controlThread = new Thread(this::controlLoop, "jtail-control");
        controlThread.setDaemon(true);
        controlThread.start();

        try {
            if (!ready.await(cfg.joinTimeout().toMillis(), TimeUnit.MILLISECONDS)) {
                Throwable f = controlFailure;
                throw new JTailException("timed out waiting to join the tailnet" + (f != null ? ": " + f.getMessage() : ""), f);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new JTailException("interrupted while joining", e);
        }
        if (closed.get()) throw new JTailException("tailnet closed while joining");
        LOG.log(System.Logger.Level.INFO, "joined tailnet as {0} ({1})", name(), address().getHostAddress());
    }

    private ControlClient.RegisterResult registerWithRetry(byte[] oldNodeKey) throws IOException {
        IOException last = null;
        long deadline = System.nanoTime() + cfg.joinTimeout().toNanos();
        for (int attempt = 0; attempt < 6 && System.nanoTime() < deadline; attempt++) {
            try {
                return control.register(cfg.authKey(), hostinfo, cfg.ephemeral(), oldNodeKey);
            } catch (ControlException e) {
                if (e.status() >= 400 && e.status() < 500 && e.status() != 429) {
                    throw new JTailException("control server rejected registration (HTTP " + e.status() + "): " + e.getMessage());
                }
                last = e;
            } catch (IOException e) {
                last = e;
            }
            control.close();
            try { Thread.sleep(Math.min(5000, 500L << attempt)); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); break; }
        }
        throw new JTailException("could not reach the control server: " + (last == null ? "timeout" : last.getMessage()), last);
    }

    private void pushUpdateNow() {
        try {
            List<Magicsock.Endpoint> eps = ms.endpoints();
            control.sendUpdate(hostinfo, eps.stream().map(e -> fmt(e.addr())).toList(), eps.stream().map(Magicsock.Endpoint::type).toList());
        } catch (IOException e) {
            LOG.log(System.Logger.Level.DEBUG, "endpoint update failed: {0}", e.toString());
        }
    }

    private void requestLiteUpdate() {
        if (closed.get() || !liteUpdatePending.compareAndSet(false, true)) return;
        worker.execute(() -> {
            try { Thread.sleep(200); } catch (InterruptedException ignored) { }
            liteUpdatePending.set(false);
            if (!closed.get()) pushUpdateNow();
        });
    }

    private static String fmt(InetSocketAddress a) {
        String h = a.getAddress().getHostAddress();
        return (h.contains(":") ? "[" + h + "]" : h) + ":" + a.getPort();
    }

    // ---- control stream ----

    private void controlLoop() {
        long backoff = 1000;
        while (!closed.get()) {
            long started = System.nanoTime();
            try {
                NetMap fresh = new NetMap(); // every stream starts with full state
                List<Magicsock.Endpoint> eps = ms.endpoints();
                control.pollMap(hostinfo, eps.stream().map(e -> fmt(e.addr())).toList(), eps.stream().map(Magicsock.Endpoint::type).toList(),
                        true, (MapResponse mr) -> onMap(fresh.apply(mr)));
                controlUp = false;
                controlFailure = new IOException("control stream ended");
            } catch (IOException | RuntimeException e) {
                controlUp = false;
                controlFailure = e;
                if (!closed.get()) LOG.log(System.Logger.Level.WARNING, "control connection lost: {0}", e.toString());
            }
            if (closed.get()) return;
            control.close();
            if (System.nanoTime() - started > 30_000_000_000L) backoff = 1000;
            try { Thread.sleep(backoff); } catch (InterruptedException e) { return; }
            backoff = Math.min(backoff * 2, 30_000);
        }
    }

    private void onMap(NetMap.Snapshot s) {
        if (closed.get() || s.self() == null) return;
        controlUp = true;
        Node me = s.self();
        if (me.expired || (me.keyExpiry != null && me.keyExpiry.isBefore(java.time.Instant.now()))) {
            LOG.log(System.Logger.Level.WARNING, "this node's key has expired; peers will refuse its traffic until it re-registers");
        }
        this.snap = s;
        Derp.Map_ dm = s.derpMap();
        if (dm != null) derp.setMap(dm);
        ensureStack(s);
        PacketFilter pf = PacketFilter.compile(s.packetFilter());
        this.filter = pf;
        com.simtechdata.jtail.Trace.log("node", "netmap: " + s.peers().size() + " peers, " + s.packetFilter().size() + " packet-filter rules, derpMap="
                + (s.derpMap() == null ? "none" : s.derpMap().regions().size() + " regions"));
        syncPeers(s);
        if (!homeChosen && dm != null) {
            homeChosen = true;
            worker.execute(() -> chooseHome(dm));
        }
        checkReady();
    }

    private void ensureStack(NetMap.Snapshot s) {
        if (stack != null) return;
        List<byte[]> addrs = new ArrayList<>();
        for (IpPrefix p : s.self().addresses) addrs.add(p.addr());
        if (addrs.isEmpty()) return;
        Netstack ns = new Netstack(addrs, dev::sendPacket, Netstack.DEFAULT_MTU);
        ns.setInboundFilter(p -> filter.allowInbound(p));
        ns.setOutboundObserver(p -> filter.noteOutbound(p));
        stack = ns;
    }

    private void syncPeers(NetMap.Snapshot s) {
        Set<String> seen = new HashSet<>();
        Map<String, InetAddress> nm = new ConcurrentHashMap<>();
        boolean changed = false;
        for (Node n : s.peers()) {
            if (n.key == null || n.expired) continue;
            seen.add(Hex.of(n.key));
            List<IpPrefix> allowed = cfg.acceptRoutes() ? n.allowedIPs : n.addresses;
            WgPeer wp = dev.peer(n.key);
            if (wp == null) { wp = dev.addPeer(n.key, allowed); changed = true; }
            else if (!wp.allowedIPs().equals(allowed)) dev.setAllowedIPs(wp, allowed);
            ms.attach(wp, n.key);
            com.simtechdata.jtail.Trace.log("node", "peer " + n.name + " key=" + com.simtechdata.jtail.Trace.key(n.key) + " homeDerp=" + n.homeDerp + " endpoints=" + n.endpoints
                    + " online=" + n.online + " addrs=" + n.addresses);
            InetAddress ip = firstAddress(n);
            if (ip != null) {
                for (String nameKey : nameKeys(n, s.domain())) nm.put(nameKey, ip);
            }
        }
        for (WgPeer wp : dev.peers()) {
            if (!seen.contains(Hex.of(wp.publicKey()))) { dev.removePeer(wp.publicKey()); changed = true; }
        }
        ms.updatePeers(s.peers().stream().filter(n -> n.key != null && !n.expired).toList());
        names = nm;
        if (changed) ms.rediscoverAll();
    }

    private static InetAddress firstAddress(Node n) {
        for (IpPrefix p : n.addresses) if (p.isIPv4()) return p.address();
        return n.addresses.isEmpty() ? null : n.addresses.get(0).address();
    }

    private static List<String> nameKeys(Node n, String domain) {
        List<String> ks = new ArrayList<>();
        String fqdn = n.name.endsWith(".") ? n.name.substring(0, n.name.length() - 1) : n.name;
        ks.add(fqdn.toLowerCase(Locale.ROOT));
        ks.add(n.shortName().toLowerCase(Locale.ROOT));
        if (!n.hostname.isEmpty()) ks.add(n.hostname.toLowerCase(Locale.ROOT));
        return ks;
    }

    private void chooseHome(Derp.Map_ dm) {
        int best = 0;
        long bestNanos = Long.MAX_VALUE;
        for (Derp.Region r : dm.regions().values()) {
            if (r.avoid() || r.noMeasureNoHome() || r.nodes().isEmpty()) continue;
            Derp.Node n = r.nodes().stream().filter(x -> !x.stunOnly()).findFirst().orElse(null);
            if (n == null) continue;
            long t0 = System.nanoTime();
            try (Socket s = new Socket()) {
                String host = !n.ipv4().isEmpty() && !n.ipv4().equals("none") ? n.ipv4() : n.hostName();
                s.connect(new InetSocketAddress(host, n.port()), 2000);
                long dt = System.nanoTime() - t0;
                if (dt < bestNanos) { bestNanos = dt; best = r.regionId(); }
            } catch (IOException ignored) { }
        }
        if (best == 0 && !dm.regions().isEmpty()) best = dm.regions().firstKey();
        if (best == 0) { LOG.log(System.Logger.Level.WARNING, "no DERP relay regions available"); checkReady(); return; }
        hostinfo.preferredDerp = best;
        homeChosenAtNanos = System.nanoTime();
        derp.setHome(best);
        ms.probeStun(dm);
        pushUpdateNow();
        checkReady();
    }

    private void checkReady() {
        if (ready.getCount() == 0 || stack == null) return;
        int home = derp.home();
        boolean derpGaveUp = home != 0 && System.nanoTime() - homeChosenAtNanos > 10_000_000_000L;
        if (home != 0 && !derp.isConnected(home) && !derpGaveUp) {
            worker.execute(() -> { try { Thread.sleep(100); } catch (InterruptedException ignored) { } if (!closed.get()) checkReady(); });
            return;
        }
        if (derpGaveUp && !derp.isConnected(home)) {
            LOG.log(System.Logger.Level.WARNING, "DERP relay {0} is unreachable; continuing, direct connections may still work", home);
        }
        if (home != 0 || (snap.derpMap() != null && snap.derpMap().regions().isEmpty() && homeChosen)) ready.countDown();
    }

    // ---- Tailnet API ----

    private Netstack requireStack() throws IOException {
        Netstack s = stack;
        if (s == null || closed.get()) throw new IOException("tailnet is not connected");
        return s;
    }

    @Override public boolean connected() { return !closed.get() && stack != null && controlUp; }

    @Override public InetAddress address() {
        Node self = snap.self();
        if (self == null) throw new JTailException("not joined");
        for (IpPrefix p : self.addresses) if (p.isIPv4()) return p.address();
        return self.addresses.get(0).address();
    }

    @Override public List<InetAddress> addresses() {
        Node self = snap.self();
        if (self == null) throw new JTailException("not joined");
        List<InetAddress> out = new ArrayList<>();
        for (IpPrefix p : self.addresses) out.add(p.address());
        return out;
    }

    @Override public String name() {
        Node self = snap.self();
        if (self == null) return cfg.hostname();
        return self.name.endsWith(".") ? self.name.substring(0, self.name.length() - 1) : self.name;
    }

    @Override public List<Peer> peers() {
        List<Peer> out = new ArrayList<>();
        for (Node n : snap.peers()) {
            List<InetAddress> addrs = new ArrayList<>();
            for (IpPrefix p : n.addresses) addrs.add(p.address());
            String nm = n.name.endsWith(".") ? n.name.substring(0, n.name.length() - 1) : n.name;
            out.add(new Peer(nm, n.hostname, addrs, Boolean.TRUE.equals(n.online), List.copyOf(n.tags)));
        }
        return out;
    }

    @Override public InetAddress resolve(String host) throws IOException {
        String h = host.toLowerCase(Locale.ROOT);
        if (h.endsWith(".")) h = h.substring(0, h.length() - 1);
        try {
            if (looksLikeIp(h)) return InetAddress.getByAddress(IpPrefix.parseIp(h));
        } catch (RuntimeException | UnknownHostException ignored) { }
        InetAddress ip = names.get(h);
        if (ip == null) {
            String domain = snap.domain();
            if (domain != null && !domain.isEmpty() && !h.contains(".")) ip = names.get(h + "." + domain);
        }
        if (ip == null) {
            try {
                List<InetAddress> found = dns.resolve(h, snap.dns() == null ? com.simtechdata.jtail.tailcfg.DnsConfig.EMPTY : snap.dns());
                if (!found.isEmpty()) return found.get(0);
            } catch (UnknownHostException ignored) {
                // fall through to the unified error below
            } catch (java.io.UncheckedIOException e) {
                throw e.getCause();
            }
            throw new UnknownHostException(host + ": no such node in this tailnet and not found in tailnet DNS");
        }
        return ip;
    }

    private static boolean looksLikeIp(String h) {
        if (h.indexOf(':') >= 0) return true;
        for (int i = 0; i < h.length(); i++) if (!(Character.isDigit(h.charAt(i)) || h.charAt(i) == '.')) return false;
        return !h.isEmpty();
    }

    @Override public Socket dial(String host, int port) throws IOException { return dial(host, port, 30_000); }

    @Override public Socket dial(String host, int port, int connectTimeoutMillis) throws IOException {
        TailnetDialer.Dialed d = dialInternal(host, port, connectTimeoutMillis);
        return new TailnetSocket(d.conn(), d.local(), d.remote());
    }

    private TailnetDialer.Dialed dialInternal(String host, int port, int connectTimeoutMillis) throws IOException {
        Netstack s = requireStack();
        InetAddress ip = resolve(host);
        com.simtechdata.jtail.Trace.log("node", "dial " + host + " -> " + ip.getHostAddress() + ":" + port + " (timeout " + connectTimeoutMillis + " ms)");
        if (dev.routeFor(ip.getAddress()) == null) throw new java.net.NoRouteToHostException("no route to " + host + " (" + ip.getHostAddress() + ")");
        TcpConn c = s.dialTcp(ip.getAddress(), port, connectTimeoutMillis);
        com.simtechdata.jtail.Trace.log("node", "dial " + host + ":" + port + " ESTABLISHED");
        return new TailnetDialer.Dialed(c, new InetSocketAddress(InetAddress.getByAddress(c.localAddress()), c.localPort()),
                new InetSocketAddress(ip, port));
    }

    @Override public javax.net.SocketFactory socketFactory() { return new TailnetSocketFactory(this::dialInternal); }

    @Override public HttpProxy startHttpProxy(int port) throws IOException { return trackProxy(port, null, null); }

    @Override public HttpProxy startHttpProxy(int port, String username, String password) throws IOException {
        java.util.Objects.requireNonNull(username, "username");
        java.util.Objects.requireNonNull(password, "password");
        return trackProxy(port, username, password);
    }

    /** Starts a proxy and remembers it so {@link #close()} can close it; refuses once the node is closed. */
    private HttpProxy trackProxy(int port, String username, String password) throws IOException {
        synchronized (proxies) {
            if (closed.get()) throw new IOException("tailnet is closed");
            proxies.removeIf(HttpProxy::isClosed);   // drop proxies their owners already closed
            HttpProxy p = new HttpProxy(this::dialInternal, port, username, password);
            proxies.add(p);
            return p;
        }
    }

    @Override public ServerSocket listen(int port) throws IOException {
        Netstack s = requireStack();
        TcpListener l = s.listenTcp(port);
        InetAddress local = address();
        return new TailnetServerSocket(l, local, c -> {
            try { return new InetSocketAddress(InetAddress.getByAddress(c.remoteAddress()), c.remotePort()); }
            catch (UnknownHostException e) { throw new IllegalStateException(e); }
        });
    }

    @Override public long ping(String host, int timeoutMillis) throws IOException {
        return requireStack().ping(resolve(host).getAddress(), timeoutMillis);
    }

    @Override public UdpSocket openUdp(int port) throws IOException { return requireStack().bindUdp(port); }

    @Override public int connectionCount() {
        Netstack s = stack;
        return s == null ? 0 : s.connectionCount();
    }

    @Override public boolean isDirect(String host) {
        try {
            InetAddress ip = resolve(host);
            WgPeer p = dev.routeFor(ip.getAddress());
            return p != null && ms.isDirect(p.publicKey());
        } catch (IOException e) {
            return false;
        }
    }

    @Override public void close() {
        if (!closed.compareAndSet(false, true)) return;
        controlUp = false;
        java.util.List<HttpProxy> toClose;
        synchronized (proxies) { toClose = List.copyOf(proxies); proxies.clear(); }
        for (HttpProxy p : toClose) p.close();       // first, so in-flight tunnels end before the stack goes away
        if (cfg.ephemeral()) {
            try { control.logout(hostinfo); } catch (IOException | RuntimeException ignored) { }
        }
        if (controlThread != null) controlThread.interrupt();
        control.close();
        Netstack s = stack;
        if (s != null) s.close();
        if (ms != null) ms.close();
        if (derp != null) derp.close();
        if (dev != null) dev.close();
        worker.shutdownNow();
        ready.countDown();
    }
}
