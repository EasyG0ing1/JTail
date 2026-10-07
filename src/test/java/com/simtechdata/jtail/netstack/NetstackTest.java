package com.simtechdata.jtail.netstack;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

class NetstackTest {
    static final byte[] IP_A = {100, 64, 0, 1}, IP_B = {100, 64, 0, 2};
    static final byte[] IP6_A = ip6(1), IP6_B = ip6(2);

    static byte[] ip6(int last) {
        byte[] b = new byte[16];
        b[0] = (byte) 0xfd; b[1] = 0x7a; b[2] = 0x11; b[3] = 0x5c;
        b[15] = (byte) last;
        return b;
    }

    /** One direction of an unreliable link: optional loss, base delay and jitter (which reorders packets). */
    static final class Wire implements AutoCloseable {
        final ScheduledExecutorService ex = Executors.newScheduledThreadPool(1, r -> { Thread t = new Thread(r); t.setDaemon(true); return t; });
        final Random rnd = new Random(42);
        volatile double loss;
        volatile int delayMs, jitterMs;
        volatile Netstack to;
        volatile boolean blackhole;

        void send(byte[] pkt) {
            if (blackhole || to == null) return;
            if (loss > 0 && rnd.nextDouble() < loss) return;
            int d = delayMs + (jitterMs > 0 ? rnd.nextInt(jitterMs + 1) : 0);
            byte[] copy = pkt.clone();
            if (d == 0) ex.execute(() -> to.deliver(copy));
            else ex.schedule(() -> to.deliver(copy), d, TimeUnit.MILLISECONDS);
        }

        @Override public void close() { ex.shutdownNow(); }
    }

    Wire ab = new Wire(), ba = new Wire();
    Netstack a, b;

    void link(List<byte[]> addrsA, List<byte[]> addrsB) {
        a = new Netstack(addrsA, ab::send, 1280);
        b = new Netstack(addrsB, ba::send, 1280);
        ab.to = b;
        ba.to = a;
    }

    void link() { link(List.of(IP_A, IP6_A), List.of(IP_B, IP6_B)); }

    @AfterEach void tearDown() {
        if (a != null) a.close();
        if (b != null) b.close();
        ab.close();
        ba.close();
    }

    static byte[] pattern(int n, long seed) {
        byte[] d = new byte[n];
        new Random(seed).nextBytes(d);
        return d;
    }

    /** Server that echoes everything it reads until EOF, then closes. */
    Future<Void> echoServer(TcpListener l, ExecutorService ex) {
        return ex.submit(() -> {
            TcpConn c = l.accept(10_000);
            byte[] buf = new byte[8192];
            int n;
            while ((n = c.read(buf, 0, buf.length, 0)) >= 0) c.write(buf, 0, n);
            c.close();
            return null;
        });
    }

    @Test @Timeout(30)
    void connectEchoAndCloseGracefully() throws Exception {
        link();
        ExecutorService ex = Executors.newCachedThreadPool();
        TcpListener l = b.listenTcp(7000);
        Future<Void> srv = echoServer(l, ex);
        TcpConn c = a.dialTcp(IP_B, 7000, 5000);
        c.write("hello netstack".getBytes(), 0, 14);
        byte[] r = new byte[14];
        int got = 0;
        while (got < 14) got += c.read(r, got, 14 - got, 5000);
        assertEquals("hello netstack", new String(r));
        c.shutdownOutput();                       // half-close: server sees EOF and closes its side
        assertEquals(-1, c.read(new byte[1], 0, 1, 5000));
        srv.get(5, TimeUnit.SECONDS);
        c.close();
        ex.shutdownNow();
    }

    @Test @Timeout(60)
    void bulkTransferBothDirectionsIntegrity() throws Exception {
        link();
        ExecutorService ex = Executors.newCachedThreadPool();
        int size = 8 * 1024 * 1024;
        byte[] up = pattern(size, 1), down = pattern(size, 2);
        TcpListener l = b.listenTcp(7001);
        Future<byte[]> srv = ex.submit(() -> {
            TcpConn c = l.accept(10_000);
            Future<?> w = ex.submit(() -> { c.write(down, 0, down.length); c.shutdownOutput(); return null; });
            byte[] got = readAll(c, size);
            w.get();
            c.close();
            return got;
        });
        TcpConn c = a.dialTcp(IP_B, 7001, 5000);
        Future<byte[]> reader = ex.submit(() -> readAll(c, size));
        long t0 = System.nanoTime();
        c.write(up, 0, up.length);
        c.shutdownOutput();
        assertArrayEquals(down, reader.get(40, TimeUnit.SECONDS));
        assertArrayEquals(up, srv.get(40, TimeUnit.SECONDS));
        double secs = (System.nanoTime() - t0) / 1e9;
        System.out.printf("netstack bulk: 2x%d MiB in %.2fs (%.0f Mbit/s each way)%n", size >> 20, secs, size * 8 / secs / 1e6);
        c.close();
        ex.shutdownNow();
    }

    static byte[] readAll(TcpConn c, int expect) throws IOException {
        byte[] out = new byte[expect];
        int off = 0;
        while (off < expect) {
            int n = c.read(out, off, expect - off, 30_000);
            if (n < 0) throw new IOException("EOF after " + off);
            off += n;
        }
        return out;
    }

    @Test @Timeout(120)
    void survivesLossAndReordering() throws Exception {
        link();
        ab.loss = 0.04; ba.loss = 0.04;
        ab.delayMs = 5; ba.delayMs = 5; ab.jitterMs = 8; ba.jitterMs = 8;   // jitter reorders
        ExecutorService ex = Executors.newCachedThreadPool();
        int size = 1_500_000;
        byte[] data = pattern(size, 7);
        TcpListener l = b.listenTcp(7002);
        Future<byte[]> srv = ex.submit(() -> {
            TcpConn c = l.accept(30_000);
            byte[] got = readAll(c, size);
            c.write(MessageDigest.getInstance("SHA-256").digest(got), 0, 32); // prove integrity back to the client
            c.close();
            return got;
        });
        TcpConn c = a.dialTcp(IP_B, 7002, 20_000);
        c.write(data, 0, data.length);
        byte[] digest = readAll(c, 32);
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(data), digest);
        assertArrayEquals(data, srv.get(30, TimeUnit.SECONDS));
        c.close();
        ex.shutdownNow();
    }

    @Test @Timeout(30)
    void connectionRefusedAndTimeout() throws Exception {
        link();
        SocketException e = assertThrows(SocketException.class, () -> a.dialTcp(IP_B, 9, 5000));
        assertTrue(e.getMessage().toLowerCase().contains("refused"), e.getMessage());
        ab.blackhole = true;
        assertThrows(SocketTimeoutException.class, () -> a.dialTcp(IP_B, 7003, 1500));
    }

    @Test @Timeout(30)
    void resetPropagatesToPeer() throws Exception {
        link();
        TcpListener l = b.listenTcp(7004);
        TcpConn c = a.dialTcp(IP_B, 7004, 5000);
        TcpConn s = l.accept(5000);
        s.abort();
        IOException ex = assertThrows(IOException.class, () -> { for (int i = 0; i < 50; i++) { c.read(new byte[10], 0, 10, 2000); } });
        assertTrue(ex.getMessage().toLowerCase().contains("reset") || ex instanceof SocketException, ex.getMessage());
    }

    @Test @Timeout(60)
    void manyConcurrentConnections() throws Exception {
        link();
        ExecutorService ex = Executors.newCachedThreadPool();
        TcpListener l = b.listenTcp(7005);
        int n = 100;
        ex.submit(() -> {
            for (int i = 0; i < n; i++) {
                TcpConn c = l.accept(20_000);
                ex.submit(() -> {
                    byte[] buf = new byte[64];
                    int k;
                    while ((k = c.read(buf, 0, buf.length, 20_000)) >= 0) c.write(buf, 0, k);
                    c.close();
                    return null;
                });
            }
            return null;
        });
        List<Future<Boolean>> fs = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            final int id = i;
            fs.add(ex.submit(() -> {
                TcpConn c = a.dialTcp(IP_B, 7005, 10_000);
                byte[] msg = ("conn-" + id).getBytes();
                c.write(msg, 0, msg.length);
                byte[] r = new byte[msg.length];
                int off = 0;
                while (off < r.length) off += c.read(r, off, r.length - off, 10_000);
                c.close();
                return new String(r).equals("conn-" + id);
            }));
        }
        for (Future<Boolean> f : fs) assertTrue(f.get(40, TimeUnit.SECONDS));
        ex.shutdownNow();
    }

    @Test @Timeout(30)
    void ipv6Connection() throws Exception {
        link();
        ExecutorService ex = Executors.newCachedThreadPool();
        TcpListener l = b.listenTcp(7006);
        Future<Void> srv = echoServer(l, ex);
        TcpConn c = a.dialTcp(IP6_B, 7006, 5000);
        byte[] msg = pattern(5000, 3);
        c.write(msg, 0, msg.length);
        assertArrayEquals(msg, readAll(c, msg.length));
        c.shutdownOutput();
        srv.get(5, TimeUnit.SECONDS);
        ex.shutdownNow();
    }

    @Test @Timeout(30)
    void udpIcmpAndPortUnreachable() throws Exception {
        link();
        UdpSocket sb = b.bindUdp(5353);
        UdpSocket sa = a.bindUdp(0);
        sa.send(IP_B, 5353, "ping-udp".getBytes());
        UdpSocket.Datagram d = sb.receive(3000);
        assertEquals("ping-udp", new String(d.data()));
        sb.send(d.srcIp(), d.srcPort(), "pong-udp".getBytes());
        assertEquals("pong-udp", new String(sa.receive(3000).data()));
        // IPv6 UDP (checksum mandatory)
        sa.send(IP6_B, 5353, "v6".getBytes());
        assertEquals("v6", new String(sb.receive(3000).data()));

        assertTrue(a.ping(IP_B, 3000) >= 0);
        assertTrue(a.ping(IP6_B, 3000) >= 0);
        assertThrows(SocketTimeoutException.class, () -> a.ping(new byte[]{100, 64, 0, 99}, 300));
    }

    @Test @Timeout(60)
    void zeroWindowBackpressureResumes() throws Exception {
        link();
        ExecutorService ex = Executors.newCachedThreadPool();
        TcpListener l = b.listenTcp(7007);
        int size = 3 * 1024 * 1024; // far beyond receive buffer + send buffer
        byte[] data = pattern(size, 11);
        Future<byte[]> srv = ex.submit(() -> {
            TcpConn c = l.accept(10_000);
            Thread.sleep(1500);                    // stall: advertise a zero window meanwhile
            byte[] got = readAll(c, size);
            c.close();
            return got;
        });
        TcpConn c = a.dialTcp(IP_B, 7007, 5000);
        c.write(data, 0, data.length);
        assertArrayEquals(data, srv.get(40, TimeUnit.SECONDS));
        c.close();
        ex.shutdownNow();
    }

    @Test @Timeout(30)
    void keepaliveProbesAnIdlePeerAndKeepsTheConnectionOpen() throws Exception {
        link();
        TcpListener l = b.listenTcp(7008);
        TcpConn c = a.dialTcp(IP_B, 7008, 5000);
        TcpConn s = l.accept(5000);
        c.setKeepAlive(true, 300, 100, 5);
        Thread.sleep(2000);                               // well past idle+interval*probes: probes are answered
        assertFalse(c.isClosed(), "answered keepalives must keep an idle connection alive");
        c.write("still-here".getBytes(), 0, 10);
        byte[] r = new byte[10];
        int off = 0;
        while (off < 10) off += s.read(r, off, 10 - off, 3000);
        assertEquals("still-here", new String(r));
    }

    @Test @Timeout(30)
    void keepaliveResetsAConnectionWhosePeerHasVanished() throws Exception {
        link();
        TcpListener l = b.listenTcp(7009);
        TcpConn c = a.dialTcp(IP_B, 7009, 5000);
        l.accept(5000);
        c.setKeepAlive(true, 200, 100, 3);
        ab.blackhole = true;                              // peer silently disappears
        ba.blackhole = true;
        IOException e = assertThrows(IOException.class, () -> c.read(new byte[1], 0, 1, 10_000));
        assertTrue(e instanceof SocketTimeoutException && e.getMessage().contains("keepalive"), String.valueOf(e));
    }
}
