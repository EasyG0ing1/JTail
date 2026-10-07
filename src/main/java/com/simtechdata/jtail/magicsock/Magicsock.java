package com.simtechdata.jtail.magicsock;

import com.simtechdata.jtail.crypto.Hex;
import com.simtechdata.jtail.crypto.NaClBox;
import com.simtechdata.jtail.derp.DerpManager;
import com.simtechdata.jtail.state.NodeIdentity;
import com.simtechdata.jtail.tailcfg.Derp;
import com.simtechdata.jtail.tailcfg.Node;
import com.simtechdata.jtail.wg.WgDevice;
import com.simtechdata.jtail.wg.WgPeer;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Chooses, per peer, how WireGuard datagrams travel: directly over UDP once disco has verified a path, otherwise
 * relayed through DERP. A condensed port of the ideas in Tailscale's magicsock: disco ping/pong path probing,
 * call-me-maybe hole punching via DERP, heartbeat-based path trust, and STUN for our own public endpoints.
 */
public final class Magicsock implements AutoCloseable {
    /** Our reachable UDP endpoint and how it was found. */
    public record Endpoint(InetSocketAddress addr, int type) {} // type: 1 = local interface, 2 = STUN

    private static final long TRUST_BEST_ADDR_NANOS = 6_500_000_000L;
    private static final long HEARTBEAT_MS = 3000;
    private static final long DISCOVER_MIN_INTERVAL_NANOS = 5_000_000_000L;
    private static final long ACTIVE_WINDOW_NANOS = 15_000_000_000L;

    private final byte[] discoPriv, discoPub, nodePub;
    private final DatagramSocket udp;
    private final DerpManager derp;
    private volatile WgDevice device;
    private final Map<String, MsPeer> byNodeKey = new ConcurrentHashMap<>();
    private final Map<String, MsPeer> byDiscoKey = new ConcurrentHashMap<>();
    private final ScheduledExecutorService timers = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "jtail-magicsock");
        t.setDaemon(true);
        return t;
    });
    private final SecureRandom rng = new SecureRandom();
    private final Map<String, InetSocketAddress> stunPending = new ConcurrentHashMap<>(); // txid hex -> server
    private final Set<InetSocketAddress> stunMapped = Collections.synchronizedSet(new LinkedHashSet<>());
    private final boolean includeLoopback;
    private volatile boolean directPaths = true;
    private volatile Consumer<List<Endpoint>> onEndpoints = e -> { };
    private volatile List<Endpoint> lastEndpoints = List.of();
    private volatile boolean closed;

    private final class MsPeer {
        final byte[] nodeKey;
        volatile byte[] discoKey;
        volatile NaClBox disco;
        volatile int homeDerp;
        volatile WgPeer wg;
        volatile List<InetSocketAddress> candidates = List.of();
        volatile InetSocketAddress bestAddr;
        volatile long bestTrustUntil;
        volatile long bestLatencyNanos = Long.MAX_VALUE;
        volatile long lastSendNanos;
        long lastDiscoverNanos;
        final Map<String, Object[]> pings = new ConcurrentHashMap<>(); // txid -> {InetSocketAddress|null(derp), sentNanos}

        MsPeer(byte[] nodeKey) { this.nodeKey = nodeKey; }
        boolean bestValid() { return bestAddr != null && System.nanoTime() < bestTrustUntil; }
    }

    public Magicsock(NodeIdentity id, DerpManager derp, int udpPort, boolean includeLoopback) throws SocketException {
        this.discoPriv = id.discoPrivate();
        this.discoPub = id.discoPublic();
        this.nodePub = id.nodePublic();
        this.derp = derp;
        this.includeLoopback = includeLoopback;
        this.udp = new DatagramSocket(udpPort);
        udp.setReceiveBufferSize(1 << 21);
    }

    public void bind(WgDevice device) { this.device = device; }

    /** When false, all traffic is relayed through DERP and no disco probing is done. */
    public void setDirectPaths(boolean enabled) { this.directPaths = enabled; }

    public void setEndpointListener(Consumer<List<Endpoint>> l) { this.onEndpoints = l; }

    public void start() {
        Thread t = new Thread(this::udpLoop, "jtail-udp-reader");
        t.setDaemon(true);
        t.start();
        timers.scheduleWithFixedDelay(this::heartbeat, HEARTBEAT_MS, HEARTBEAT_MS, TimeUnit.MILLISECONDS);
        timers.scheduleWithFixedDelay(this::refreshEndpoints, 30, 30, TimeUnit.SECONDS);
    }

    public int udpPort() { return udp.getLocalPort(); }

    // ---- peer configuration from the netmap ----

    /** Synchronises path state with the peers in a netmap snapshot (WireGuard peers are managed by the caller). */
    public void updatePeers(List<Node> peers) {
        Set<String> keep = new LinkedHashSet<>();
        for (Node n : peers) {
            if (n.key == null) continue;
            String k = Hex.of(n.key);
            keep.add(k);
            MsPeer p = byNodeKey.computeIfAbsent(k, x -> new MsPeer(n.key));
            p.homeDerp = n.homeDerp;
            if (n.discoKey != null && (p.discoKey == null || !Arrays.equals(p.discoKey, n.discoKey))) {
                if (p.discoKey != null) byDiscoKey.remove(Hex.of(p.discoKey));
                p.discoKey = n.discoKey;
                p.disco = new NaClBox(discoPriv, n.discoKey);
                byDiscoKey.put(Hex.of(n.discoKey), p);
            }
            p.candidates = List.copyOf(n.endpoints);
        }
        for (String k : new ArrayList<>(byNodeKey.keySet())) {
            if (!keep.contains(k)) {
                MsPeer gone = byNodeKey.remove(k);
                if (gone != null && gone.discoKey != null) byDiscoKey.remove(Hex.of(gone.discoKey));
            }
        }
    }

    /** Links the WireGuard peer object to its path state so {@link #send} can find it. */
    public void attach(WgPeer wg, byte[] nodeKey) {
        MsPeer p = byNodeKey.computeIfAbsent(Hex.of(nodeKey), x -> new MsPeer(nodeKey));
        p.wg = wg;
        wg.setUserData(p);
    }

    // ---- outbound WireGuard datagrams ----

    /** {@link WgDevice.Output}: sends directly if a verified path exists, else via DERP, and probes for a direct path. */
    public void send(WgPeer wg, byte[] datagram) {
        MsPeer p = wg.userData() instanceof MsPeer m ? m : null;
        if (p == null) return;
        p.lastSendNanos = System.nanoTime();
        if (directPaths && p.bestValid()) {
            try { udp.send(new DatagramPacket(datagram, datagram.length, p.bestAddr)); return; }
            catch (IOException e) { p.bestAddr = null; }
        }
        if (p.homeDerp != 0) derp.send(p.homeDerp, p.nodeKey, datagram);
        if (directPaths) timers.execute(() -> discover(p, false));
    }

    // ---- inbound ----

    private void udpLoop() {
        byte[] buf = new byte[65535];
        while (!closed) {
            try {
                DatagramPacket dp = new DatagramPacket(buf, buf.length);
                udp.receive(dp);
                byte[] d = Arrays.copyOf(dp.getData(), dp.getLength());
                InetSocketAddress from = (InetSocketAddress) dp.getSocketAddress();
                handleUdp(d, normalize(from));
            } catch (IOException e) {
                if (closed) return;
            } catch (RuntimeException e) {
                // a malformed datagram must never kill the receive loop
            }
        }
    }

    private static InetSocketAddress normalize(InetSocketAddress a) {
        InetAddress ip = a.getAddress();
        if (ip instanceof Inet6Address v6) {
            byte[] b = v6.getAddress();
            boolean mapped = true;
            for (int i = 0; i < 10; i++) if (b[i] != 0) mapped = false;
            if (mapped && b[10] == (byte) 0xff && b[11] == (byte) 0xff) {
                try { return new InetSocketAddress(InetAddress.getByAddress(Arrays.copyOfRange(b, 12, 16)), a.getPort()); }
                catch (java.net.UnknownHostException ignored) { }
            }
        }
        return a;
    }

    private void handleUdp(byte[] d, InetSocketAddress from) {
        if (Stun.looksLikeStun(d)) { handleStun(d); return; }
        if (!directPaths) return;                                   // DERP-only mode: ignore all direct UDP
        if (Disco.looksLikeDisco(d)) { handleDisco(d, from, 0, null); return; }
        WgDevice dev = device;
        if (dev != null) dev.receive(d, from);
    }

    /** Called by the DERP layer for every relayed packet. */
    public void onDerpPacket(int region, byte[] srcNodeKey, byte[] data) {
        if (Disco.looksLikeDisco(data)) { handleDisco(data, null, region, srcNodeKey); return; }
        WgDevice dev = device;
        if (dev != null) dev.receive(data, "derp:" + region);
    }

    private void handleDisco(byte[] d, InetSocketAddress fromUdp, int derpRegion, byte[] derpSrc) {
        MsPeer p = byDiscoKey.get(Hex.of(Disco.source(d)));
        if (p == null || p.disco == null) return;
        Disco.Message m = Disco.open(d, p.disco);
        if (m == null) return;
        if (m instanceof Disco.Ping ping) {
            Disco.Pong pong = new Disco.Pong(ping.txId(), fromUdp != null ? fromUdp : new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            sendDisco(p, pong, fromUdp, derpRegion != 0 ? derpRegion : p.homeDerp);
            if (fromUdp != null) learnCandidate(p, fromUdp);
        } else if (m instanceof Disco.Pong pong) {
            Object[] pending = p.pings.remove(Hex.of(pong.txId()));
            if (pending == null) return;
            if (fromUdp != null && pending[0] != null) {
                long rtt = System.nanoTime() - (Long) pending[1];
                boolean better = !p.bestValid() || fromUdp.equals(p.bestAddr) || rtt < p.bestLatencyNanos;
                if (better) {
                    p.bestAddr = fromUdp;
                    p.bestLatencyNanos = rtt;
                }
                if (fromUdp.equals(p.bestAddr)) p.bestTrustUntil = System.nanoTime() + TRUST_BEST_ADDR_NANOS;
                WgPeer wg = p.wg;
                if (wg != null) wg.setEndpoint(fromUdp);
            }
        } else if (m instanceof Disco.CallMeMaybe cmm) {
            List<InetSocketAddress> merged = new ArrayList<>(p.candidates);
            for (InetSocketAddress a : cmm.endpoints()) if (!merged.contains(a)) merged.add(a);
            p.candidates = merged;
            timers.execute(() -> pingCandidates(p));
        }
    }

    private void learnCandidate(MsPeer p, InetSocketAddress a) {
        if (p.candidates.contains(a)) return;
        List<InetSocketAddress> merged = new ArrayList<>(p.candidates);
        merged.add(a);
        p.candidates = merged;
        timers.execute(() -> pingAddr(p, a));
    }

    // ---- path discovery ----

    private void discover(MsPeer p, boolean force) {
        if (closed || p.disco == null || !directPaths) return;
        long now = System.nanoTime();
        synchronized (p) {
            if (!force && (p.bestValid() || now - p.lastDiscoverNanos < DISCOVER_MIN_INTERVAL_NANOS)) return;
            p.lastDiscoverNanos = now;
        }
        pingCandidates(p);
        // ask the peer to ping us back, opening any NAT mapping towards our endpoints
        List<Endpoint> eps = lastEndpoints;
        if (!eps.isEmpty() && p.homeDerp != 0) {
            List<InetSocketAddress> mine = new ArrayList<>();
            for (Endpoint e : eps) mine.add(e.addr());
            sendDisco(p, new Disco.CallMeMaybe(mine), null, p.homeDerp);
        }
    }

    private void pingCandidates(MsPeer p) {
        for (InetSocketAddress a : p.candidates) pingAddr(p, a);
    }

    private void pingAddr(MsPeer p, InetSocketAddress a) {
        if (p.disco == null) return;
        byte[] tx = new byte[12];
        rng.nextBytes(tx);
        p.pings.put(Hex.of(tx), new Object[]{a, System.nanoTime()});
        if (p.pings.size() > 256) p.pings.clear();
        sendDisco(p, new Disco.Ping(tx, nodePub, 0), a, 0);
    }

    private void sendDisco(MsPeer p, Disco.Message m, InetSocketAddress udpDest, int derpRegion) {
        if (p.disco == null) return;
        byte[] pkt = Disco.seal(discoPub, p.disco, m);
        if (udpDest != null && udpDest.getPort() != 0) {
            try { udp.send(new DatagramPacket(pkt, pkt.length, udpDest)); } catch (IOException ignored) { }
        } else if (derpRegion != 0) {
            derp.send(derpRegion, p.nodeKey, pkt);
        }
    }

    private void heartbeat() {
        if (!directPaths) return;
        long now = System.nanoTime();
        for (MsPeer p : byNodeKey.values()) {
            if (p.disco == null) continue;
            boolean active = now - p.lastSendNanos < ACTIVE_WINDOW_NANOS;
            if (!active) continue;
            if (p.bestValid()) {
                pingAddr(p, p.bestAddr);          // keeps the path trusted while traffic flows
            } else {
                p.bestAddr = null;
                discover(p, false);
            }
        }
    }

    // ---- our own endpoints ----

    /** Gathers local interface addresses (and previously learned STUN mappings), notifying the listener on change. */
    public List<Endpoint> refreshEndpoints() {
        if (!directPaths) return lastEndpoints;
        List<Endpoint> eps = new ArrayList<>();
        int port = udp.getLocalPort();
        try {
            Enumeration<NetworkInterface> ifs = NetworkInterface.getNetworkInterfaces();
            while (ifs != null && ifs.hasMoreElements()) {
                NetworkInterface ni = ifs.nextElement();
                if (!ni.isUp()) continue;
                if (ni.isLoopback() && !includeLoopback) continue;
                for (InetAddress a : Collections.list(ni.getInetAddresses())) {
                    if (a.isLinkLocalAddress() || a.isAnyLocalAddress() || a.isMulticastAddress()) continue;
                    if (a.isLoopbackAddress() && !includeLoopback) continue;
                    if (a instanceof Inet4Address || a instanceof Inet6Address) eps.add(new Endpoint(new InetSocketAddress(a, port), 1));
                }
            }
        } catch (SocketException ignored) { }
        synchronized (stunMapped) {
            for (InetSocketAddress a : stunMapped) eps.add(new Endpoint(a, 2));
        }
        Set<InetSocketAddress> seen = new LinkedHashSet<>();
        eps.removeIf(e -> !seen.add(e.addr()));
        if (!eps.equals(lastEndpoints)) {
            lastEndpoints = List.copyOf(eps);
            onEndpoints.accept(lastEndpoints);
        }
        return lastEndpoints;
    }

    public List<Endpoint> endpoints() { return lastEndpoints; }

    /** Sends STUN binding requests to the DERP nodes in {@code map}; mappings arrive asynchronously. */
    public void probeStun(Derp.Map_ map) {
        if (map == null || !directPaths) return;
        for (Derp.Region r : map.regions().values()) {
            for (Derp.Node n : r.nodes()) {
                if (n.stunPort() < 0 || n.ipv4().isEmpty() || n.ipv4().equals("none")) continue;
                try {
                    InetSocketAddress server = new InetSocketAddress(InetAddress.getByName(n.ipv4()), n.stunPort() == 0 ? 3478 : n.stunPort());
                    byte[] tx = Stun.newTxId();
                    stunPending.put(Hex.of(tx), server);
                    byte[] req = Stun.bindingRequest(tx);
                    udp.send(new DatagramPacket(req, req.length, server));
                } catch (IOException | RuntimeException ignored) { }
            }
        }
    }

    private void handleStun(byte[] d) {
        InetSocketAddress server = stunPending.remove(Hex.of(Stun.txId(d)));
        if (server == null) return;
        InetSocketAddress mapped = Stun.parseBindingResponse(d);
        if (mapped != null && stunMapped.add(mapped)) timers.execute(this::refreshEndpoints);
    }

    /** Forces a disco round with every peer (used after endpoint or netmap changes). */
    public void rediscoverAll() {
        if (!directPaths) return;
        for (MsPeer p : byNodeKey.values()) timers.execute(() -> discover(p, true));
    }

    /** Diagnostics: is traffic to this peer currently going direct? */
    public boolean isDirect(byte[] nodeKey) {
        MsPeer p = byNodeKey.get(Hex.of(nodeKey));
        return p != null && p.bestValid();
    }

    @Override public void close() {
        closed = true;
        udp.close();
        timers.shutdownNow();
    }
}
