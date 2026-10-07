package com.simtechdata.jtail.netstack;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;

/**
 * A userspace IPv4/IPv6 stack with TCP, UDP and ICMP echo, sitting on top of the WireGuard device in place of a
 * kernel TUN interface. Inbound IP packets enter through {@link #deliver}; outbound ones leave through the sink.
 */
public final class Netstack implements TcpConn.Host, AutoCloseable {
    /** Receives fully formed outbound IP packets (typically {@code WgDevice::sendPacket}). */
    @FunctionalInterface
    public interface PacketSink { void send(byte[] ipPacket); }

    public static final int DEFAULT_MTU = 1280;
    private static final int MAX_HALF_OPEN = 256;
    private static final SecureRandom RNG = new SecureRandom();

    private final List<byte[]> localAddrs;
    private final PacketSink sink;
    private final int mtu;
    private volatile Predicate<IpPacket> inboundFilter = p -> true;
    private final ScheduledThreadPoolExecutor timers;

    private record ConnKey(ByteBuffer remoteIp, int remotePort, int localPort) {}

    private final Map<ConnKey, TcpConn> conns = new ConcurrentHashMap<>();
    private final Map<Integer, TcpListener> listeners = new ConcurrentHashMap<>();
    private final Map<Integer, UdpSocket> udpSockets = new ConcurrentHashMap<>();
    private final Map<String, BlockingQueue<Long>> pingWaiters = new ConcurrentHashMap<>();
    private volatile boolean closed;

    public Netstack(List<byte[]> localAddrs, PacketSink sink, int mtu) {
        this.localAddrs = List.copyOf(localAddrs);
        this.sink = sink;
        this.mtu = mtu;
        this.timers = new ScheduledThreadPoolExecutor(2, r -> {
            Thread t = new Thread(r, "jtail-netstack-timers");
            t.setDaemon(true);
            return t;
        });
        timers.setRemoveOnCancelPolicy(true);
    }

    /** Sets an ingress filter (the tailnet ACL packet filter); packets rejected by it are silently dropped. */
    public void setInboundFilter(Predicate<IpPacket> f) { this.inboundFilter = f; }

    public List<byte[]> localAddresses() { return localAddrs; }

    boolean isLocal(byte[] ip) {
        for (byte[] a : localAddrs) if (Arrays.equals(a, ip)) return true;
        return false;
    }

    byte[] localFor(byte[] remote) {
        for (byte[] a : localAddrs) if (a.length == remote.length) return a;
        return null;
    }

    int mssFor(byte[] ip) { return mtu - (ip.length == 4 ? 40 : 60); }

    // ---- TcpConn.Host ----

    @Override public void output(byte[] ipPacket) { if (!closed) sink.send(ipPacket); }
    @Override public java.util.concurrent.ScheduledExecutorService timers() { return timers; }

    @Override public void connectionClosed(TcpConn c) {
        conns.remove(new ConnKey(ByteBuffer.wrap(c.remoteIp), c.remotePort, c.localPort), c);
    }

    @Override public void passiveEstablished(TcpConn c) {
        TcpListener l = listeners.get(c.localPort);
        if (l == null || !l.offer(c)) c.abort();
    }

    // ---- inbound ----

    /** Processes one decrypted IP packet addressed to this node. */
    public void deliver(byte[] raw) {
        if (closed) return;
        IpPacket p = IpPacket.parse(raw);
        if (p == null || !isLocal(p.dst)) return;
        if (!inboundFilter.test(p)) return;
        switch (p.protocol) {
            case IpPacket.PROTO_TCP -> handleTcp(p);
            case IpPacket.PROTO_UDP -> handleUdp(p, raw);
            case IpPacket.PROTO_ICMP, IpPacket.PROTO_ICMPV6 -> handleIcmp(p);
            default -> { }
        }
    }

    private void handleTcp(IpPacket p) {
        TcpSegment seg = TcpSegment.parse(p.src, p.dst, p.payload);
        if (seg == null) return;
        TcpConn c = conns.get(new ConnKey(ByteBuffer.wrap(p.src), seg.srcPort, seg.dstPort));
        if (c != null) { c.onSegment(seg); return; }
        if (seg.has(TcpSegment.RST)) return;
        TcpListener l = listeners.get(seg.dstPort);
        if (seg.has(TcpSegment.SYN) && !seg.has(TcpSegment.ACK) && l != null && !l.isClosed()) {
            if (halfOpen() >= MAX_HALF_OPEN || l.full()) return; // shed load: the client will retry its SYN
            ConnKey k = new ConnKey(ByteBuffer.wrap(p.src), seg.srcPort, seg.dstPort);
            TcpConn nc = TcpConn.passive(this, p.dst, seg.dstPort, p.src, seg.srcPort, mssFor(p.src), seg);
            if (conns.putIfAbsent(k, nc) != null) nc.abort();
            return;
        }
        // no such connection: answer with RST (RFC 9293 3.10.7.1)
        TcpSegment rst = new TcpSegment();
        rst.srcPort = seg.dstPort;
        rst.dstPort = seg.srcPort;
        if (seg.has(TcpSegment.ACK)) { rst.seq = seg.ack; rst.flags = TcpSegment.RST; }
        else { rst.seq = 0; rst.ack = seg.seq + seg.seqLen(); rst.flags = TcpSegment.RST | TcpSegment.ACK; }
        output(IpPacket.build(p.dst, p.src, IpPacket.PROTO_TCP, rst.build(p.dst, p.src)));
    }

    private int halfOpen() {
        int n = 0;
        for (TcpConn c : conns.values()) if (c.state() == TcpConn.State.SYN_RCVD) n++;
        return n;
    }

    private void handleUdp(IpPacket p, byte[] raw) {
        byte[] u = p.payload;
        if (u.length < 8) return;
        int srcPort = ((u[0] & 0xFF) << 8) | (u[1] & 0xFF);
        int dstPort = ((u[2] & 0xFF) << 8) | (u[3] & 0xFF);
        int len = ((u[4] & 0xFF) << 8) | (u[5] & 0xFF);
        if (len < 8 || len > u.length) return;
        boolean hasChecksum = u[6] != 0 || u[7] != 0;
        if (hasChecksum || p.version == 6) {
            if (!IpPacket.verifyTransport(p.src, p.dst, IpPacket.PROTO_UDP, Arrays.copyOf(u, len))) return;
        }
        UdpSocket s = udpSockets.get(dstPort);
        if (s == null) { sendPortUnreachable(p, raw); return; }
        s.enqueue(new UdpSocket.Datagram(p.src, srcPort, Arrays.copyOfRange(u, 8, len)));
    }

    private void sendPortUnreachable(IpPacket p, byte[] raw) {
        byte[] quote = Arrays.copyOf(raw, Math.min(raw.length, p.version == 4 ? 28 : 48));
        byte[] icmp;
        if (p.version == 4) {
            icmp = new byte[8 + quote.length];
            icmp[0] = 3; icmp[1] = 3;
            System.arraycopy(quote, 0, icmp, 8, quote.length);
            int c = IpPacket.checksum(icmp, 0, icmp.length, 0);
            icmp[2] = (byte) (c >> 8); icmp[3] = (byte) c;
            output(IpPacket.build(p.dst, p.src, IpPacket.PROTO_ICMP, icmp));
        } else {
            icmp = new byte[8 + quote.length];
            icmp[0] = 1; icmp[1] = 4;
            System.arraycopy(quote, 0, icmp, 8, quote.length);
            int c = IpPacket.transportChecksum(p.dst, p.src, IpPacket.PROTO_ICMPV6, icmp);
            icmp[2] = (byte) (c >> 8); icmp[3] = (byte) c;
            output(IpPacket.build(p.dst, p.src, IpPacket.PROTO_ICMPV6, icmp));
        }
    }

    private void handleIcmp(IpPacket p) {
        byte[] m = p.payload;
        if (m.length < 8) return;
        boolean v6 = p.version == 6;
        if (v6 ? !IpPacket.verifyTransport(p.src, p.dst, IpPacket.PROTO_ICMPV6, m) : IpPacket.checksum(m, 0, m.length, 0) != 0) return;
        int type = m[0] & 0xFF;
        if ((!v6 && type == 8) || (v6 && type == 128)) { // echo request -> reply
            byte[] r = m.clone();
            r[0] = (byte) (v6 ? 129 : 0);
            r[2] = 0; r[3] = 0;
            int c = v6 ? IpPacket.transportChecksum(p.dst, p.src, IpPacket.PROTO_ICMPV6, r) : IpPacket.checksum(r, 0, r.length, 0);
            r[2] = (byte) (c >> 8); r[3] = (byte) c;
            output(IpPacket.build(p.dst, p.src, v6 ? IpPacket.PROTO_ICMPV6 : IpPacket.PROTO_ICMP, r));
        } else if ((!v6 && type == 0) || (v6 && type == 129)) { // echo reply
            String key = Arrays.toString(p.src) + ((m[4] & 0xFF) << 8 | (m[5] & 0xFF)) + ":" + ((m[6] & 0xFF) << 8 | (m[7] & 0xFF));
            BlockingQueue<Long> q = pingWaiters.get(key);
            if (q != null) q.offer(System.nanoTime());
        }
    }

    // ---- outbound API ----

    private int allocatePort(java.util.function.IntPredicate inUse) {
        for (int i = 0; i < 2000; i++) {
            int port = 49152 + RNG.nextInt(65536 - 49152);
            if (!inUse.test(port)) return port;
        }
        throw new IllegalStateException("no free ephemeral ports");
    }

    /** Opens a TCP connection and waits for the handshake. */
    public TcpConn dialTcp(byte[] remoteIp, int remotePort, int timeoutMs) throws IOException {
        byte[] local = localFor(remoteIp);
        if (local == null) throw new IOException("no local address for IPv" + (remoteIp.length == 4 ? 4 : 6));
        TcpConn c;
        while (true) {
            int lp = allocatePort(port -> listeners.containsKey(port) || conns.containsKey(new ConnKey(ByteBuffer.wrap(remoteIp), remotePort, port)));
            ConnKey k = new ConnKey(ByteBuffer.wrap(remoteIp.clone()), remotePort, lp);
            if (conns.containsKey(k)) continue;
            c = TcpConn.active(this, local, lp, remoteIp.clone(), remotePort, mssFor(remoteIp));
            if (conns.putIfAbsent(k, c) == null) break;
            c.abort();
        }
        c.awaitEstablished(timeoutMs);
        return c;
    }

    /** Starts listening on {@code port} (0 = pick a free one) at all local addresses. */
    public TcpListener listenTcp(int port) throws IOException {
        if (port == 0) port = allocatePort(listeners::containsKey);
        TcpListener l = new TcpListener(this, port);
        if (listeners.putIfAbsent(port, l) != null) throw new java.net.BindException("Address already in use: " + port);
        return l;
    }

    void removeListener(TcpListener l) { listeners.remove(l.port(), l); }

    public UdpSocket bindUdp(int port) throws IOException {
        if (port == 0) port = allocatePort(udpSockets::containsKey);
        UdpSocket s = new UdpSocket(this, port);
        if (udpSockets.putIfAbsent(port, s) != null) throw new java.net.BindException("Address already in use: " + port);
        return s;
    }

    void removeUdp(UdpSocket s) { udpSockets.remove(s.port(), s); }

    void sendUdp(int srcPort, byte[] dstIp, int dstPort, byte[] data) throws IOException {
        byte[] local = localFor(dstIp);
        if (local == null) throw new IOException("no local address for destination family");
        if (data.length > mtu - (dstIp.length == 4 ? 28 : 48)) throw new IOException("datagram too large for MTU " + mtu);
        byte[] u = new byte[8 + data.length];
        u[0] = (byte) (srcPort >> 8); u[1] = (byte) srcPort;
        u[2] = (byte) (dstPort >> 8); u[3] = (byte) dstPort;
        u[4] = (byte) (u.length >> 8); u[5] = (byte) u.length;
        System.arraycopy(data, 0, u, 8, data.length);
        int c = IpPacket.transportChecksum(local, dstIp, IpPacket.PROTO_UDP, u);
        if (c == 0) c = 0xFFFF;
        u[6] = (byte) (c >> 8); u[7] = (byte) c;
        output(IpPacket.build(local, dstIp, IpPacket.PROTO_UDP, u));
    }

    /** Sends an ICMP echo request and returns the round-trip time in milliseconds. */
    public long ping(byte[] ip, int timeoutMs) throws IOException {
        byte[] local = localFor(ip);
        if (local == null) throw new IOException("no local address for destination family");
        boolean v6 = ip.length == 16;
        int id = RNG.nextInt(0x10000), seq = RNG.nextInt(0x10000);
        byte[] m = new byte[8 + 16];
        m[0] = (byte) (v6 ? 128 : 8);
        m[4] = (byte) (id >> 8); m[5] = (byte) id; m[6] = (byte) (seq >> 8); m[7] = (byte) seq;
        int c = v6 ? IpPacket.transportChecksum(local, ip, IpPacket.PROTO_ICMPV6, m) : IpPacket.checksum(m, 0, m.length, 0);
        m[2] = (byte) (c >> 8); m[3] = (byte) c;
        String key = Arrays.toString(ip) + id + ":" + seq;
        BlockingQueue<Long> q = new ArrayBlockingQueue<>(1);
        pingWaiters.put(key, q);
        try {
            long t0 = System.nanoTime();
            output(IpPacket.build(local, ip, v6 ? IpPacket.PROTO_ICMPV6 : IpPacket.PROTO_ICMP, m));
            Long t1 = q.poll(timeoutMs, TimeUnit.MILLISECONDS);
            if (t1 == null) throw new SocketTimeoutException("ping timed out");
            return (t1 - t0) / 1_000_000;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException(e);
        } finally {
            pingWaiters.remove(key);
        }
    }

    @Override public void close() {
        closed = true;
        for (TcpConn c : conns.values()) c.abort();
        for (TcpListener l : listeners.values()) l.close();
        for (UdpSocket s : udpSockets.values()) s.close();
        timers.shutdownNow();
    }
}
