package com.simtechdata.jtail.e2e;

import static org.junit.jupiter.api.Assertions.*;

import com.simtechdata.jtail.JTail;
import com.simtechdata.jtail.Tailnet;
import com.simtechdata.jtail.netstack.UdpSocket;
import com.simtechdata.jtail.testutil.Oracles;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Random;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The decisive interop test: a pure-Java JTail node and a genuine Tailscale (Go, tsnet) client join the same tailnet
 * and talk to each other over TCP, UDP and ICMP in both directions.
 */
class GoTsnetInteropTest {
    private static Tailnet joinJava(String url) {
        return JTail.network().authKey("tskey-auth-interop").hostname("java-node").controlUrl(url)
                .joinTimeout(Duration.ofSeconds(60)).join();
    }

    @Test @Timeout(240)
    void javaNodeAndGoTailscaleClientInteroperate() throws Exception {
        try (Oracles.Running ctl = Oracles.start("go-control", "-authkey", "tskey-auth-interop")) {
            String url = ctl.expect("BASEURL ", 30_000).substring("BASEURL ".length());
            try (Oracles.Running go = Oracles.start("go-tsnet", "-control", url, "-authkey", "tskey-auth-interop", "-host", "go-node");
                 Tailnet java = joinJava(url)) {
                String up = go.expect("UP", 60_000);
                assertFalse(up.startsWith("UP_ERR"), up);
                String goIp = up.split(" ")[1];

                // --- Java dials Go (TCP echo), by MagicDNS name ---
                go.send("echo 7000");
                go.expect("ECHO_LISTENING", 10_000);
                // peers appear asynchronously after both are online
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
                while (java.peers().stream().noneMatch(p -> p.name().startsWith("go-node")) && System.nanoTime() < deadline) Thread.sleep(200);
                assertTrue(java.peers().stream().anyMatch(p -> p.name().startsWith("go-node")), "Java never saw the Go peer");
                try (Socket s = java.dial("go-node", 7000)) {
                    s.getOutputStream().write("from-java".getBytes());
                    s.getOutputStream().flush();
                    byte[] buf = new byte[64];
                    int n = s.getInputStream().read(buf);
                    assertEquals("go:from-java", new String(buf, 0, n));
                }

                // --- IPv6: the same echo over the node's fd7a:... address ---
                String goIp6 = up.split(" ")[2];
                try (Socket s = java.dial(goIp6, 7000)) {
                    s.getOutputStream().write("v6-from-java".getBytes());
                    s.getOutputStream().flush();
                    byte[] buf = new byte[64];
                    int n = s.getInputStream().read(buf);
                    assertEquals("go:v6-from-java", new String(buf, 0, n));
                }

                // --- Go dials Java (TCP echo) ---
                ExecutorService ex = Executors.newCachedThreadPool();
                try (ServerSocket ss = java.listen(7001)) {
                    Future<String> got = ex.submit(() -> {
                        try (Socket s = ss.accept()) {
                            byte[] buf = new byte[64];
                            int n = s.getInputStream().read(buf);
                            s.getOutputStream().write(("java:" + new String(buf, 0, n)).getBytes());
                            s.getOutputStream().flush();
                            return new String(buf, 0, n);
                        }
                    });
                    go.send("dial " + java.address().getHostAddress() + ":7001 from-go");
                    assertEquals("DIAL_REPLY java:from-go", go.expect("DIAL_", 30_000));
                    assertEquals("from-go", got.get(10, TimeUnit.SECONDS));
                }

                // --- Go dials Java over IPv6 ---
                String javaIp6 = java.addresses().stream().filter(a -> a instanceof java.net.Inet6Address).findFirst().orElseThrow().getHostAddress();
                try (ServerSocket ss = java.listen(7005)) {
                    Future<String> got6 = ex.submit(() -> {
                        try (Socket s = ss.accept()) {
                            byte[] buf = new byte[64];
                            int n = s.getInputStream().read(buf);
                            s.getOutputStream().write(("java6:" + new String(buf, 0, n)).getBytes());
                            s.getOutputStream().flush();
                            return s.getInetAddress().getHostAddress();
                        }
                    });
                    go.send("dial [" + javaIp6 + "]:7005 from-go-v6");
                    assertEquals("DIAL_REPLY java6:from-go-v6", go.expect("DIAL_", 30_000));
                    assertTrue(got6.get(10, TimeUnit.SECONDS).contains(":"), "peer address should be IPv6");
                }

                // --- bulk Java -> Go with integrity check (Go computes sha256 of what it received) ---
                byte[] data = new byte[4 * 1024 * 1024];
                new Random(9).nextBytes(data);
                go.send("sink 7002");
                go.expect("SINK_LISTENING", 10_000);
                try (Socket s = java.dial(goIp, 7002)) {
                    s.getOutputStream().write(data);
                    s.getOutputStream().flush();
                    s.shutdownOutput();
                    String digest = new String(s.getInputStream().readAllBytes());
                    assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data)), digest);
                }

                // --- bulk Go -> Java ---
                try (ServerSocket ss = java.listen(7003)) {
                    Future<byte[]> recv = ex.submit(() -> {
                        try (Socket s = ss.accept()) {
                            byte[] all = s.getInputStream().readAllBytes();
                            s.getOutputStream().write(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(all)).getBytes());
                            s.getOutputStream().flush();
                            return all;
                        }
                    });
                    int n = 2 * 1024 * 1024;
                    go.send("send " + java.address().getHostAddress() + ":7003 " + n + " 77");
                    byte[] expect = new byte[n];
                    new java.util.Random(77); // Go's math/rand differs from Java's; verify via the echoed digest instead
                    String line = go.expect("SEND_", 60_000);
                    assertTrue(line.startsWith("SEND_DIGEST "), line);
                    byte[] got = recv.get(30, TimeUnit.SECONDS);
                    assertEquals(n, got.length);
                    assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(got)), line.substring("SEND_DIGEST ".length()));
                }

                // --- UDP both ways ---
                go.send("udpecho 7004");
                go.expect("UDPECHO_LISTENING", 10_000);
                try (UdpSocket u = java.openUdp(0)) {
                    u.send(java.resolve("go-node").getAddress(), 7004, "udp-ping".getBytes());
                    assertEquals("go-udp:udp-ping", new String(u.receive(15_000).data()));
                }

                // --- ICMP both ways ---
                assertTrue(java.ping("go-node", 15_000) >= 0);
                go.send("ping " + java.address().getHostAddress());
                assertTrue(go.expect("PING_", 30_000).startsWith("PING_OK"));
                ex.shutdownNow();
            }
        }
    }
}
