package com.simtechdata.jtail.wg;

import static com.simtechdata.jtail.wg.WgConstants.*;

import com.simtechdata.jtail.crypto.X25519;
import com.simtechdata.jtail.crypto.XChaCha20Poly1305;
import com.simtechdata.jtail.tailcfg.IpPrefix;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import javax.crypto.AEADBadTagException;

/**
 * A pure-Java WireGuard device (the cryptographic core of a Tailscale node). It is transport-agnostic: encrypted
 * datagrams leave through {@link Output} and arrive through {@link #receive}; decrypted IP packets go to the
 * {@code onPacket} callback. Path selection (UDP direct vs. DERP relay) is the caller's concern.
 */
public final class WgDevice implements AutoCloseable {
    /** Sends an encrypted WireGuard datagram toward a peer using whatever path is currently best. */
    @FunctionalInterface
    public interface Output { void send(WgPeer peer, byte[] datagram); }

    private final byte[] privateKey, publicKey, mac1KeyOfUs;
    private final WgTiming timing;
    private final Output output;
    private final BiConsumer<WgPeer, byte[]> onPacket;
    private final SecureRandom rng = new SecureRandom();
    private final Map<ByteBuffer, WgPeer> peersByKey = new ConcurrentHashMap<>();
    private final Map<Integer, Object[]> indexTable = new ConcurrentHashMap<>(); // idx -> {peer, Keypair|null}
    private volatile List<Route> routes = List.of();
    private final ScheduledExecutorService timers = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "jtail-wg-timers");
        t.setDaemon(true);
        return t;
    });
    private volatile boolean closed;
    private static final System.Logger LOG = System.getLogger("com.simtechdata.jtail.wg");

    // Global limit on handshake initiations we are willing to process. Anyone who knows our public key can craft a
    // message that passes the cheap MAC check, and each one costs a Diffie-Hellman; WireGuard's cookie mechanism exists
    // for this reason. Excess initiations are simply dropped (a legitimate peer retries).
    private static final double INITIATION_RATE_PER_SEC = 200, INITIATION_BURST = 100;
    private double initiationTokens = INITIATION_BURST;
    private long initiationRefillNanos = System.nanoTime();

    private record Route(IpPrefix prefix, WgPeer peer) {}

    public WgDevice(byte[] privateKey, Output output, BiConsumer<WgPeer, byte[]> onPacket) {
        this(privateKey, output, onPacket, WgTiming.DEFAULT);
    }

    public WgDevice(byte[] privateKey, Output output, BiConsumer<WgPeer, byte[]> onPacket, WgTiming timing) {
        this.timing = timing;
        this.privateKey = privateKey.clone();
        this.publicKey = X25519.publicKey(privateKey);
        this.mac1KeyOfUs = Handshake.mac1Key(publicKey);
        this.output = output;
        this.onPacket = onPacket;
    }

    public byte[] publicKey() { return publicKey.clone(); }

    // ---- peer management ----

    public synchronized WgPeer addPeer(byte[] peerPublic, List<IpPrefix> allowedIPs) {
        ByteBuffer k = ByteBuffer.wrap(peerPublic.clone());
        WgPeer existing = peersByKey.get(k);
        if (existing != null) { setAllowedIPs(existing, allowedIPs); return existing; }
        WgPeer p = new WgPeer(peerPublic.clone(), X25519.scalarMult(privateKey, peerPublic), allowedIPs, timing);
        peersByKey.put(k, p);
        rebuildRoutes();
        return p;
    }

    public synchronized void removePeer(byte[] peerPublic) {
        WgPeer p = peersByKey.remove(ByteBuffer.wrap(peerPublic));
        if (p == null) return;
        synchronized (p) {
            cancel(p.retryTimer); cancel(p.keepaliveTimer); cancel(p.persistentTimer);
            for (Keypair kp : new Keypair[]{p.current, p.previous, p.next}) if (kp != null) indexTable.remove(kp.localIndex);
            if (p.pending != null) indexTable.remove(p.pending.localIndex);
            p.current = p.previous = p.next = null;
            p.pending = null;
            p.staged.clear();
        }
        rebuildRoutes();
    }

    public synchronized void setAllowedIPs(WgPeer p, List<IpPrefix> ips) {
        p.allowedIPs = List.copyOf(ips);
        rebuildRoutes();
    }

    public WgPeer peer(byte[] peerPublic) { return peersByKey.get(ByteBuffer.wrap(peerPublic)); }

    public List<WgPeer> peers() { return new ArrayList<>(peersByKey.values()); }

    private void rebuildRoutes() {
        List<Route> rs = new ArrayList<>();
        for (WgPeer p : peersByKey.values()) for (IpPrefix ip : p.allowedIPs) rs.add(new Route(ip, p));
        rs.sort(Comparator.comparingInt((Route r) -> r.prefix.bits()).reversed());
        routes = rs;
    }

    /** Longest-prefix match of a destination address against peers' allowed IPs. */
    public WgPeer routeFor(byte[] ip) {
        for (Route r : routes) if (r.prefix.contains(ip)) return r.peer;
        return null;
    }

    // ---- outbound ----

    /** Encrypts and sends one IP packet to whichever peer owns its destination. Returns false if unroutable. */
    public boolean sendPacket(byte[] ipPacket) {
        byte[] dst = IpHeader.dst(ipPacket);
        if (dst == null) return false;
        WgPeer peer = routeFor(dst);
        if (peer == null) return false;
        sendTo(peer, ipPacket);
        return true;
    }

    /** Sends an IP packet to a specific peer, handshaking first if needed. */
    public void sendTo(WgPeer peer, byte[] ipPacket) {
        byte[] out = null;
        boolean needHandshake = false;
        synchronized (peer) {
            Keypair kp = usableSendKeypair(peer);
            if (kp != null) {
                out = encrypt(peer, kp, ipPacket);
                if (kp.isInitiator && (kp.ageNanos() > timing.rekeyAfterNanos() || kp.sendCounter.get() > REKEY_AFTER_MESSAGES)) needHandshake = true;
            } else {
                if (peer.staged.size() >= MAX_QUEUED_PACKETS) peer.staged.pollFirst();
                peer.staged.addLast(ipPacket);
                needHandshake = true;
            }
        }
        if (out != null) output.send(peer, out);
        if (needHandshake) initiate(peer, false);
    }

    private Keypair usableSendKeypair(WgPeer p) {
        Keypair kp = p.current;
        if (kp == null) return null;
        if (kp.ageNanos() >= timing.rejectAfterNanos()) return null;
        if (Long.compareUnsigned(kp.sendCounter.get(), REJECT_AFTER_MESSAGES) >= 0) return null;
        return kp;
    }

    /** Must be called with the peer lock held. */
    private byte[] encrypt(WgPeer peer, Keypair kp, byte[] ipPacket) {
        long counter = kp.sendCounter.getAndIncrement();
        int padded = (ipPacket.length + 15) & ~15;
        byte[] pt = ipPacket.length == padded ? ipPacket : Arrays.copyOf(ipPacket, padded);
        byte[] nonce = new byte[12];
        Handshake.putLe64(nonce, 4, counter);
        byte[] ct = kp.send.seal(nonce, pt, null);
        byte[] msg = new byte[TRANSPORT_HEADER + ct.length];
        msg[0] = MSG_TRANSPORT;
        Handshake.putLe32(msg, 4, kp.remoteIndex);
        Handshake.putLe64(msg, 8, counter);
        System.arraycopy(ct, 0, msg, TRANSPORT_HEADER, ct.length);
        peer.txBytes.addAndGet(msg.length);
        peer.lastSendNanos = System.nanoTime();
        return msg;
    }

    private void sendKeepalive(WgPeer peer) {
        byte[] out = null;
        synchronized (peer) {
            Keypair kp = usableSendKeypair(peer);
            if (kp != null) out = encrypt(peer, kp, new byte[0]);
        }
        if (out != null) output.send(peer, out);
    }

    // ---- handshake initiation ----

    /** Starts a handshake with {@code peer}, honouring the REKEY_TIMEOUT rate limit unless {@code force}. */
    public void initiate(WgPeer peer, boolean force) {
        if (closed) return;
        byte[] msg;
        synchronized (peer) {
            long now = System.nanoTime();
            if (!force && peer.lastInitiationSentNanos != 0 && now - peer.lastInitiationSentNanos < timing.rekeyTimeoutNanos()) return;
            if (peer.handshakeAttemptStartNanos == 0) peer.handshakeAttemptStartNanos = now;
            peer.lastInitiationSentNanos = now;
            if (peer.pending != null) indexTable.remove(peer.pending.localIndex);
            int idx = newIndex();
            Handshake.InitiatorState st = new Handshake.InitiatorState();
            msg = Handshake.createInitiation(privateKey, publicKey, peer.publicKey, peer.staticStatic, idx, st);
            peer.pending = st;
            peer.pendingSentNanos = now;
            indexTable.put(idx, new Object[]{peer, null});
            byte[] mac1 = Handshake.mac(Handshake.mac1Key(peer.publicKey), msg, 116);
            System.arraycopy(mac1, 0, msg, 116, 16);
            peer.lastMac1Sent = mac1;
            if (peer.cookie != null && now - peer.cookieNanos < 120 * NANOS) {
                byte[] mac2 = Handshake.mac(peer.cookie, msg, 132);
                System.arraycopy(mac2, 0, msg, 132, 16);
            }
            cancel(peer.retryTimer);
            peer.retryTimer = timers.schedule(() -> retryHandshake(peer), timing.rekeyTimeoutNanos() + rng.nextInt(333) * 1_000_000L, TimeUnit.NANOSECONDS);
        }
        output.send(peer, msg);
    }

    private void retryHandshake(WgPeer peer) {
        if (closed) return;
        synchronized (peer) {
            if (peer.staged.isEmpty() && peer.persistentKeepaliveSeconds == 0) { peer.handshakeAttemptStartNanos = 0; return; }
            if (System.nanoTime() - peer.handshakeAttemptStartNanos > timing.rekeyAttemptNanos()) {
                peer.staged.clear();
                peer.handshakeAttemptStartNanos = 0;
                return;
            }
        }
        initiate(peer, true);
    }

    private int newIndex() {
        while (true) {
            int i = rng.nextInt();
            if (i != 0 && !indexTable.containsKey(i)) return i;
        }
    }

    // ---- inbound ----

    /**
     * Processes one datagram received from the network. {@code source} is an opaque path descriptor that becomes the
     * peer's {@link WgPeer#endpoint()} once the datagram authenticates (WireGuard roaming).
     */
    public void receive(byte[] d, Object source) {
        if (closed || d.length < 4) return;
        try {
            switch (d[0]) {
                case MSG_INITIATION -> { if (d.length == INITIATION_LEN) handleInitiation(d, source); }
                case MSG_RESPONSE -> { if (d.length == RESPONSE_LEN) handleResponse(d, source); }
                case MSG_COOKIE -> { if (d.length == COOKIE_LEN) handleCookie(d); }
                case MSG_TRANSPORT -> { if (d.length >= MIN_TRANSPORT) handleTransport(d, source); }
                default -> { }
            }
        } catch (AEADBadTagException ignored) {
            // unauthenticated traffic is silently dropped, as WireGuard specifies
        } catch (RuntimeException e) {
            // malformed input must not escape, but an unexpected exception is worth seeing when debugging
            LOG.log(System.Logger.Level.TRACE, "dropped datagram after exception", e);
        }
    }

    private boolean macOk(byte[] msg, int macOffset) {
        byte[] expect = Handshake.mac(mac1KeyOfUs, msg, macOffset);
        return MessageDigest.isEqual(expect, Arrays.copyOfRange(msg, macOffset, macOffset + 16));
    }

    private synchronized boolean takeInitiationToken() {
        long now = System.nanoTime();
        initiationTokens = Math.min(INITIATION_BURST, initiationTokens + (now - initiationRefillNanos) / 1e9 * INITIATION_RATE_PER_SEC);
        initiationRefillNanos = now;
        if (initiationTokens < 1) return false;
        initiationTokens -= 1;
        return true;
    }

    private void handleInitiation(byte[] msg, Object source) throws AEADBadTagException {
        if (!macOk(msg, 116)) return;
        if (!takeInitiationToken()) return;
        Handshake.Consumed c = Handshake.consumeInitiation(msg, privateKey, publicKey, pub -> {
            WgPeer p = peersByKey.get(ByteBuffer.wrap(pub));
            return p == null ? null : p.staticSecret();
        });
        WgPeer peer = peersByKey.get(ByteBuffer.wrap(c.peerStatic));
        if (peer == null) return;
        byte[] response;
        synchronized (peer) {
            if (compareTimestamps(c.timestamp, peer.lastTimestamp) <= 0) return; // replay
            long now = System.nanoTime();
            if (peer.lastInitiationConsumedNanos != 0 && now - peer.lastInitiationConsumedNanos < 20_000_000L) return; // flood
            peer.lastTimestamp = c.timestamp;
            peer.lastInitiationConsumedNanos = now;
            int idx = newIndex();
            Handshake.Response r = Handshake.createResponse(c, peer.publicKey, idx);
            byte[] mac1 = Handshake.mac(Handshake.mac1Key(peer.publicKey), r.message, 60);
            System.arraycopy(mac1, 0, r.message, 60, 16);
            Keypair kp = new Keypair(r.sendKey, r.recvKey, idx, c.peerIndex, false);
            if (peer.next != null) indexTable.remove(peer.next.localIndex);
            peer.next = kp;
            indexTable.put(idx, new Object[]{peer, kp});
            peer.endpoint = source;
            response = r.message;
        }
        output.send(peer, response);
    }

    private static int compareTimestamps(byte[] a, byte[] b) { return Arrays.compareUnsigned(a, b); }

    private void handleResponse(byte[] msg, Object source) throws AEADBadTagException {
        if (!macOk(msg, 60)) return;
        int receiver = Handshake.le32(msg, 8);
        Object[] ent = indexTable.get(receiver);
        if (ent == null) return;
        WgPeer peer = (WgPeer) ent[0];
        boolean flush;
        synchronized (peer) {
            Handshake.InitiatorState st = peer.pending;
            if (st == null || st.localIndex != receiver || ent[1] != null) return;
            byte[][] t = Handshake.consumeResponse(msg, st, privateKey);
            Keypair kp = new Keypair(t[0], t[1], receiver, Handshake.le32(msg, 4), true);
            peer.pending = null;
            cancel(peer.retryTimer);
            peer.handshakeAttemptStartNanos = 0;
            if (peer.previous != null) indexTable.remove(peer.previous.localIndex);
            peer.previous = peer.current;
            peer.current = kp;
            if (peer.next != null) { indexTable.remove(peer.next.localIndex); peer.next = null; }
            indexTable.put(receiver, new Object[]{peer, kp});
            peer.endpoint = source;
            peer.lastHandshake = Instant.now();
            flush = !peer.staged.isEmpty();
            schedulePersistent(peer);
        }
        // confirm to the responder with a keepalive (or real data), then drain staged packets
        if (flush) drainStaged(peer); else sendKeepalive(peer);
    }

    private void drainStaged(WgPeer peer) {
        List<byte[]> outs = new ArrayList<>();
        synchronized (peer) {
            Keypair kp = usableSendKeypair(peer);
            if (kp == null) return;
            byte[] pkt;
            while ((pkt = peer.staged.pollFirst()) != null) outs.add(encrypt(peer, kp, pkt));
        }
        for (byte[] o : outs) output.send(peer, o);
    }

    private void handleCookie(byte[] msg) throws AEADBadTagException {
        int receiver = Handshake.le32(msg, 4);
        Object[] ent = indexTable.get(receiver);
        if (ent == null) return;
        WgPeer peer = (WgPeer) ent[0];
        synchronized (peer) {
            if (peer.pending == null || peer.pending.localIndex != receiver || peer.lastMac1Sent == null) return;
            byte[] nonce = Arrays.copyOfRange(msg, 8, 32);
            byte[] enc = Arrays.copyOfRange(msg, 32, 64);
            byte[] cookie = new XChaCha20Poly1305(Handshake.cookieKey(peer.publicKey)).open(nonce, enc, peer.lastMac1Sent);
            peer.cookie = cookie;
            peer.cookieNanos = System.nanoTime();
        }
    }

    private void handleTransport(byte[] msg, Object source) {
        int receiver = Handshake.le32(msg, 4);
        Object[] ent = indexTable.get(receiver);
        if (ent == null || ent[1] == null) return;
        WgPeer peer = (WgPeer) ent[0];
        Keypair kp = (Keypair) ent[1];
        long counter = Handshake.le64(msg, 8);
        if (kp.ageNanos() >= timing.rejectAfterNanos() || Long.compareUnsigned(counter, REJECT_AFTER_MESSAGES) >= 0) return;
        byte[] nonce = new byte[12];
        Handshake.putLe64(nonce, 4, counter);
        byte[] pt;
        try {
            pt = kp.recv.open(nonce, Arrays.copyOfRange(msg, TRANSPORT_HEADER, msg.length), null);
        } catch (AEADBadTagException e) {
            return;
        }
        if (!kp.replay.check(counter)) return;

        boolean rekey = false;
        synchronized (peer) {
            if (kp == peer.next) { // first authenticated packet confirms the responder-side session
                if (peer.previous != null) indexTable.remove(peer.previous.localIndex);
                peer.previous = peer.current;
                peer.current = kp;
                peer.next = null;
                peer.lastHandshake = Instant.now();
                schedulePersistent(peer);
            } else if (kp != peer.current && kp != peer.previous) {
                return;
            }
            peer.endpoint = source;
            peer.lastReceiveNanos = System.nanoTime();
            peer.rxBytes.addAndGet(msg.length);
            if (pt.length > 0 && !peer.keepaliveScheduled) {
                peer.keepaliveScheduled = true;
                peer.keepaliveTimer = timers.schedule(() -> keepaliveFire(peer), timing.keepaliveTimeoutNanos(), TimeUnit.NANOSECONDS);
            }
            if (kp == peer.current && kp.isInitiator && kp.ageNanos() > timing.rejectAfterNanos() - timing.keepaliveTimeoutNanos() - timing.rekeyTimeoutNanos()) rekey = true;
        }
        if (peer.staged.size() > 0) drainStaged(peer);
        if (rekey) initiate(peer, false);
        if (pt.length == 0) return; // keepalive
        byte[] ip = IpHeader.trim(pt);
        if (ip == null) return;
        byte[] src = IpHeader.src(ip);
        if (src == null || !allowed(peer, src)) return;
        onPacket.accept(peer, ip);
    }

    private void keepaliveFire(WgPeer peer) {
        boolean send;
        synchronized (peer) {
            peer.keepaliveScheduled = false;
            send = System.nanoTime() - peer.lastSendNanos >= timing.keepaliveTimeoutNanos() - 1_000_000L;
        }
        if (send) sendKeepalive(peer);
    }

    private void schedulePersistent(WgPeer peer) {
        cancel(peer.persistentTimer);
        int s = peer.persistentKeepaliveSeconds;
        if (s <= 0) return;
        peer.persistentTimer = timers.scheduleWithFixedDelay(() -> {
            if (peer.hasSession()) sendKeepalive(peer); else initiate(peer, false);
        }, s, s, TimeUnit.SECONDS);
    }

    private static boolean allowed(WgPeer peer, byte[] src) {
        for (IpPrefix p : peer.allowedIPs) if (p.contains(src)) return true;
        return false;
    }

    private static void cancel(java.util.concurrent.Future<?> f) { if (f != null) f.cancel(false); }

    @Override public void close() {
        closed = true;
        timers.shutdownNow();
    }
}
