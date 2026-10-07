package com.simtechdata.jtail.wg;

import static org.junit.jupiter.api.Assertions.*;

import com.simtechdata.jtail.crypto.X25519;
import com.simtechdata.jtail.tailcfg.IpPrefix;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

class WgDeviceTest {
    static byte[] ipv4(String src, String dst, byte[] payload) {
        byte[] p = new byte[20 + payload.length];
        p[0] = 0x45;
        p[2] = (byte) (p.length >> 8);
        p[3] = (byte) p.length;
        p[8] = 64;
        p[9] = 17;
        System.arraycopy(IpPrefix.parseIp(src), 0, p, 12, 4);
        System.arraycopy(IpPrefix.parseIp(dst), 0, p, 16, 4);
        System.arraycopy(payload, 0, p, 20, payload.length);
        return p;
    }

    /** Two devices joined by an in-memory "network" that can drop or capture datagrams. */
    static final class Pair implements AutoCloseable {
        final byte[] privA = X25519.generatePrivate(), privB = X25519.generatePrivate();
        final BlockingQueue<byte[]> gotA = new LinkedBlockingQueue<>(), gotB = new LinkedBlockingQueue<>();
        final List<byte[]> wire = new java.util.concurrent.CopyOnWriteArrayList<>();
        volatile WgDevice a, b;
        WgPeer peerOfA, peerOfB; // a's view of b, b's view of a
        volatile boolean dropAll;

        Pair(String aIp, String bIp) {
            a = new WgDevice(privA, (p, d) -> deliver(b, "a", d), (p, ip) -> gotA.add(ip));
            b = new WgDevice(privB, (p, d) -> deliver(a, "b", d), (p, ip) -> gotB.add(ip));
            peerOfA = a.addPeer(X25519.publicKey(privB), List.of(IpPrefix.parse(bIp + "/32")));
            peerOfB = b.addPeer(X25519.publicKey(privA), List.of(IpPrefix.parse(aIp + "/32")));
        }

        void deliver(WgDevice to, String from, byte[] d) {
            wire.add(d);
            if (!dropAll) to.receive(d.clone(), from);
        }

        @Override public void close() { a.close(); b.close(); }
    }

    @Test @Timeout(30)
    void handshakeAndBidirectionalData() throws Exception {
        try (Pair p = new Pair("100.64.0.1", "100.64.0.2")) {
            byte[] ping = ipv4("100.64.0.1", "100.64.0.2", "hello from a".getBytes());
            assertTrue(p.a.sendPacket(ping)); // queued, triggers handshake, then flushed
            assertArrayEquals(ping, p.gotB.poll(10, TimeUnit.SECONDS));
            assertTrue(p.peerOfA.hasSession());
            assertNotNull(p.peerOfA.lastHandshake());

            byte[] pong = ipv4("100.64.0.2", "100.64.0.1", "hello from b".getBytes());
            assertTrue(p.b.sendPacket(pong));
            assertArrayEquals(pong, p.gotA.poll(10, TimeUnit.SECONDS));
            assertEquals("a", p.peerOfB.endpoint()); // roaming: endpoint learned from authenticated traffic

            // many packets, odd sizes (padding must be stripped)
            for (int i = 1; i <= 50; i++) {
                byte[] pkt = ipv4("100.64.0.1", "100.64.0.2", new byte[i * 7]);
                p.a.sendPacket(pkt);
                assertArrayEquals(pkt, p.gotB.poll(5, TimeUnit.SECONDS));
            }
            assertTrue(p.peerOfA.txBytes() > 0 && p.peerOfB.rxBytes() > 0);
        }
    }

    @Test @Timeout(30)
    void rejectsReplayedAndTamperedDatagrams() throws Exception {
        try (Pair p = new Pair("100.64.0.1", "100.64.0.2")) {
            byte[] first = ipv4("100.64.0.1", "100.64.0.2", "x".getBytes());
            p.a.sendPacket(first);
            assertNotNull(p.gotB.poll(10, TimeUnit.SECONDS));
            p.a.sendPacket(ipv4("100.64.0.1", "100.64.0.2", "second".getBytes()));
            assertNotNull(p.gotB.poll(5, TimeUnit.SECONDS));

            byte[] transport = null;
            for (byte[] d : p.wire) if (d[0] == 4 && d.length > 40) transport = d;
            assertNotNull(transport);
            p.b.receive(transport.clone(), "evil");           // exact replay
            byte[] tampered = transport.clone();
            tampered[tampered.length - 1] ^= 1;
            p.b.receive(tampered, "evil");                    // corrupted tag
            assertNull(p.gotB.poll(500, TimeUnit.MILLISECONDS));
            assertNotEquals("evil", p.peerOfB.endpoint());     // unauthenticated traffic must not move the endpoint
        }
    }

    @Test @Timeout(30)
    void enforcesAllowedIpsOnReceiveAndRoutingOnSend() throws Exception {
        try (Pair p = new Pair("100.64.0.1", "100.64.0.2")) {
            assertFalse(p.a.sendPacket(ipv4("100.64.0.1", "100.64.9.9", new byte[8])), "no route -> not sent");
            // b's allowed IPs for a is only 100.64.0.1, so a spoofed source is dropped by b
            byte[] spoof = ipv4("100.64.0.77", "100.64.0.2", new byte[8]);
            p.a.sendTo(p.peerOfA, spoof);
            assertNull(p.gotB.poll(2, TimeUnit.SECONDS));
            byte[] ok = ipv4("100.64.0.1", "100.64.0.2", new byte[8]);
            p.a.sendTo(p.peerOfA, ok);
            assertArrayEquals(ok, p.gotB.poll(5, TimeUnit.SECONDS));
        }
    }

    @Test @Timeout(30)
    void unknownPeerHandshakeIsIgnored() throws Exception {
        try (Pair p = new Pair("100.64.0.1", "100.64.0.2")) {
            WgDevice stranger = new WgDevice(X25519.generatePrivate(), (peer, d) -> p.b.receive(d, "s"), (peer, ip) -> fail());
            WgPeer toB = stranger.addPeer(X25519.publicKey(p.privB), List.of(IpPrefix.parse("100.64.0.2/32")));
            stranger.sendPacket(ipv4("100.64.0.99", "100.64.0.2", new byte[8]));
            Thread.sleep(300);
            assertFalse(toB.hasSession());
            stranger.close();
        }
    }

    @Test
    void replayWindowSemantics() {
        ReplayWindow w = new ReplayWindow();
        assertTrue(w.check(0));
        assertFalse(w.check(0));
        assertTrue(w.check(5));
        assertTrue(w.check(3));
        assertFalse(w.check(3));
        assertTrue(w.check(10_000));
        assertFalse(w.check(5));      // now older than the window
        assertTrue(w.check(9_999));
        assertFalse(w.check(9_999));
    }
}
