package com.simtechdata.jtail.wg;

import static org.junit.jupiter.api.Assertions.*;

import com.simtechdata.jtail.crypto.Hex;
import com.simtechdata.jtail.crypto.X25519;
import com.simtechdata.jtail.tailcfg.IpPrefix;
import com.simtechdata.jtail.testutil.Oracles;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** Verifies the pure-Java WireGuard against Tailscale's wireguard-go over real UDP. */
class WireGuardGoInteropTest {
    static byte[] icmp(String src, String dst, int type, byte[] payload) {
        byte[] p = new byte[28 + payload.length];
        p[0] = 0x45; p[2] = (byte) (p.length >> 8); p[3] = (byte) p.length; p[8] = 64; p[9] = 1;
        System.arraycopy(IpPrefix.parseIp(src), 0, p, 12, 4);
        System.arraycopy(IpPrefix.parseIp(dst), 0, p, 16, 4);
        int c = checksum(p, 0, 20); p[10] = (byte) (c >> 8); p[11] = (byte) c;
        p[20] = (byte) type; p[25] = 1; p[27] = 1;
        System.arraycopy(payload, 0, p, 28, payload.length);
        c = checksum(p, 20, p.length - 20); p[22] = (byte) (c >> 8); p[23] = (byte) c;
        return p;
    }

    static int checksum(byte[] b, int off, int len) {
        long s = 0;
        for (int i = 0; i + 1 < len; i += 2) s += ((b[off + i] & 0xFF) << 8) | (b[off + i + 1] & 0xFF);
        if (len % 2 == 1) s += (b[off + len - 1] & 0xFF) << 8;
        while ((s >> 16) != 0) s = (s & 0xFFFF) + (s >> 16);
        return (int) (~s & 0xFFFF);
    }

    /** A Java WireGuard device bound to a real UDP socket. */
    static final class UdpNode implements AutoCloseable {
        final DatagramSocket sock;
        final WgDevice dev;
        final byte[] priv = X25519.generatePrivate();
        final BlockingQueue<byte[]> packets = new LinkedBlockingQueue<>();
        volatile InetSocketAddress remote;
        volatile boolean running = true;

        UdpNode() throws Exception {
            sock = new DatagramSocket(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            dev = new WgDevice(priv, (peer, d) -> {
                try {
                    InetSocketAddress to = peer.endpoint() instanceof InetSocketAddress a ? a : remote;
                    if (to != null) sock.send(new DatagramPacket(d, d.length, to));
                } catch (Exception ignored) { }
            }, (peer, ip) -> packets.add(ip));
            Thread t = new Thread(() -> {
                byte[] buf = new byte[65535];
                while (running) {
                    try {
                        DatagramPacket dp = new DatagramPacket(buf, buf.length);
                        sock.receive(dp);
                        dev.receive(java.util.Arrays.copyOf(dp.getData(), dp.getLength()), dp.getSocketAddress());
                    } catch (Exception e) { if (running) e.printStackTrace(); }
                }
            });
            t.setDaemon(true);
            t.start();
        }

        @Override public void close() { running = false; sock.close(); dev.close(); }
    }

    static int freeUdpPort() throws Exception {
        try (DatagramSocket s = new DatagramSocket(0, InetAddress.getLoopbackAddress())) { return s.getLocalPort(); }
    }

    @Test @Timeout(60)
    void javaInitiatesToWireguardGo() throws Exception {
        try (UdpNode j = new UdpNode()) {
            int port = freeUdpPort();
            // Tailscale's wireguard-go has no endpoint roaming (magicsock owns paths), so Go needs our address up front.
            try (Oracles.Running go = Oracles.start("go-wg", "-peer", Hex.of(X25519.publicKey(j.priv)), "-port", "" + port,
                    "-endpoint", "127.0.0.1:" + j.sock.getLocalPort())) {
                byte[] goPub = Hex.parse(go.line().substring(4));
                go.line(); // PORT
                InetSocketAddress goAddr = new InetSocketAddress(InetAddress.getLoopbackAddress(), port);
                j.remote = goAddr;
                WgPeer peer = j.dev.addPeer(goPub, List.of(IpPrefix.parse("100.64.0.1/32")));
                peer.setEndpoint(goAddr);

                byte[] payload = "java-initiated-ping-with-odd-size!".getBytes();
                j.dev.sendPacket(icmp("100.64.0.2", "100.64.0.1", 8, payload));
                byte[] reply = j.packets.poll(15, TimeUnit.SECONDS);
                assertNotNull(reply, "no reply from wireguard-go");
                assertEquals(0, reply[20], "ICMP echo reply expected");
                assertEquals(payload.length + 28, reply.length);
                assertArrayEquals(payload, java.util.Arrays.copyOfRange(reply, 28, reply.length));
                assertEquals("ECHO_REQ 100.64.0.2 100.64.0.1 " + payload.length, go.line());

                for (int i = 0; i < 20; i++) { // sustained traffic, varying sizes
                    byte[] pl = new byte[i * 50 + 1];
                    j.dev.sendPacket(icmp("100.64.0.2", "100.64.0.1", 8, pl));
                    assertNotNull(j.packets.poll(5, TimeUnit.SECONDS), "reply " + i);
                }
            }
        }
    }

    @Test @Timeout(60)
    void wireguardGoInitiatesToJava() throws Exception {
        try (UdpNode j = new UdpNode()) {
            int javaPort = j.sock.getLocalPort();
            try (Oracles.Running go = Oracles.start("go-wg", "-peer", Hex.of(X25519.publicKey(j.priv)),
                    "-endpoint", "127.0.0.1:" + javaPort, "-port", "" + freeUdpPort())) {
                byte[] goPub = Hex.parse(go.line().substring(4));
                go.line(); // PORT
                // Java only knows the peer's key + allowed IPs; Go initiates and Java learns the endpoint by roaming.
                j.dev.addPeer(goPub, List.of(IpPrefix.parse("100.64.0.1/32")));
                go.process.getOutputStream().write("ping 100.64.0.1 100.64.0.2\n".getBytes());
                go.process.getOutputStream().flush();
                byte[] req = j.packets.poll(15, TimeUnit.SECONDS);
                assertNotNull(req, "Java did not receive Go's initiated ping");
                assertEquals(8, req[20]);
                // answer it: swap addresses, echo reply
                j.dev.sendPacket(icmp("100.64.0.2", "100.64.0.1", 0, java.util.Arrays.copyOfRange(req, 28, req.length)));
                String line;
                do { line = go.line(); } while (line != null && !line.startsWith("PONG"));
                assertEquals("PONG 100.64.0.2 100.64.0.1 17", line);
            }
        }
    }
}
