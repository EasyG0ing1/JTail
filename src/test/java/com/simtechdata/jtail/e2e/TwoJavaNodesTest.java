package com.simtechdata.jtail.e2e;

import static org.junit.jupiter.api.Assertions.*;

import com.simtechdata.jtail.JTail;
import com.simtechdata.jtail.Tailnet;
import com.simtechdata.jtail.testutil.Oracles;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.Random;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** Two pure-Java nodes join a tailnet run by Tailscale's own test control server and relay (go-control oracle). */
class TwoJavaNodesTest {
    static Tailnet join(String url, String host, boolean loopback) {
        return JTail.network().authKey("tskey-auth-e2e").hostname(host).controlUrl(url)
                .includeLoopbackEndpoints(loopback).joinTimeout(Duration.ofSeconds(45)).join();
    }

    @Test @Timeout(120)
    void nodesJoinAndTalkOverDerpByName() throws Exception {
        try (Oracles.Running o = Oracles.start("go-control", "-authkey", "tskey-auth-e2e")) {
            String url = o.line().substring("BASEURL ".length());
            try (Tailnet a = join(url, "node-a", false); Tailnet b = join(url, "node-b", false)) {
                assertNotEquals(a.address(), b.address());
                assertTrue(a.address().getHostAddress().startsWith("100."), a.address().toString());
                assertTrue(a.name().startsWith("node-a"), a.name());

                ExecutorService ex = Executors.newCachedThreadPool();
                try (ServerSocket server = a.listen(8080)) {
                    Future<String> srv = ex.submit(() -> {
                        try (Socket s = server.accept()) {
                            byte[] buf = new byte[64];
                            int n = s.getInputStream().read(buf);
                            String got = new String(buf, 0, n);
                            s.getOutputStream().write(("echo:" + got).getBytes());
                            s.getOutputStream().flush();
                            return got + "@" + s.getInetAddress().getHostAddress();
                        }
                    });
                    try (Socket c = b.dial("node-a", 8080)) {
                        c.getOutputStream().write("hello-tailnet".getBytes());
                        c.getOutputStream().flush();
                        byte[] buf = new byte[64];
                        int n = c.getInputStream().read(buf);
                        assertEquals("echo:hello-tailnet", new String(buf, 0, n));
                    }
                    assertEquals("hello-tailnet@" + b.address().getHostAddress(), srv.get(10, TimeUnit.SECONDS));
                }
                assertTrue(b.ping("node-a", 10_000) >= 0);
                assertTrue(b.peers().stream().anyMatch(p -> p.name().startsWith("node-a")));
                ex.shutdownNow();
            }
        }
    }

    @Test @Timeout(180)
    void bulkTransferAndDirectPathUpgrade() throws Exception {
        try (Oracles.Running o = Oracles.start("go-control", "-authkey", "tskey-auth-e2e")) {
            String url = o.line().substring("BASEURL ".length());
            try (Tailnet a = join(url, "bulk-a", true); Tailnet b = join(url, "bulk-b", true)) {
                ExecutorService ex = Executors.newCachedThreadPool();
                byte[] data = new byte[3 * 1024 * 1024];
                new Random(5).nextBytes(data);
                try (ServerSocket server = a.listen(9090)) {
                    Future<byte[]> srv = ex.submit(() -> {
                        try (Socket s = server.accept()) {
                            return s.getInputStream().readNBytes(data.length);
                        }
                    });
                    try (Socket c = b.dial("bulk-a", 9090)) {
                        OutputStream out = c.getOutputStream();
                        out.write(data);
                        out.flush();
                    }
                    assertArrayEquals(data, srv.get(60, TimeUnit.SECONDS));
                }
                // after traffic, disco should have found the loopback path and upgraded from DERP to direct
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
                while (!b.isDirect("bulk-a") && System.nanoTime() < deadline) {
                    b.ping("bulk-a", 5000);
                    Thread.sleep(500);
                }
                assertTrue(b.isDirect("bulk-a"), "expected a direct UDP path between nodes on the same host");
                ex.shutdownNow();
            }
        }
    }
}
