package com.simtechdata.jtail.e2e;

import static org.junit.jupiter.api.Assertions.*;

import com.simtechdata.jtail.JTail;
import com.simtechdata.jtail.JTailException;
import com.simtechdata.jtail.Tailnet;
import com.simtechdata.jtail.testutil.Oracles;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Random;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

class LifecycleTest {
    private static JTailBuilder b(String url, String host) { return new JTailBuilder(url, host); }

    /** Tiny helper so tests read like the README. */
    static final class JTailBuilder {
        final com.simtechdata.jtail.JTailConfig.Builder cfg;
        JTailBuilder(String url, String host) {
            cfg = JTail.network().authKey("tskey-auth-life").hostname(host).controlUrl(url).joinTimeout(Duration.ofSeconds(45));
        }
        Tailnet join() { return cfg.join(); }
    }

    @Test @Timeout(120)
    void restartWithSameStateKeepsTheSameTailnetAddress(@TempDir Path state) throws Exception {
        try (Oracles.Running o = Oracles.start("go-control", "-authkey", "tskey-auth-life")) {
            String url = o.expect("BASEURL ", 20_000).substring("BASEURL ".length());
            String first, second;
            try (Tailnet n = b(url, "persist").cfg.stateDir(state).join()) { first = n.address().getHostAddress(); }
            try (Tailnet n = b(url, "persist").cfg.stateDir(state).join()) { second = n.address().getHostAddress(); }
            assertEquals(first, second, "same identity must get the same address after restart");
            // without state, a fresh identity is a new node with a new address
            try (Tailnet n = b(url, "throwaway").join()) { assertNotEquals(first, n.address().getHostAddress()); }
        }
    }

    @Test @Timeout(60)
    void wrongAuthKeyFailsFastWithClearError() throws Exception {
        try (Oracles.Running o = Oracles.start("go-control", "-authkey", "tskey-auth-life")) {
            String url = o.expect("BASEURL ", 20_000).substring("BASEURL ".length());
            JTailException e = assertThrows(JTailException.class, () -> JTail.network().authKey("tskey-auth-WRONG")
                    .hostname("intruder").controlUrl(url).joinTimeout(Duration.ofSeconds(20)).join());
            assertNotNull(e.getMessage());
            System.out.println("wrong-key error: " + e.getMessage());
        }
    }

    @Test @Timeout(60)
    void unreachableControlServerFailsWithinTimeout() {
        long t0 = System.nanoTime();
        assertThrows(JTailException.class, () -> JTail.network().authKey("k").hostname("x")
                .controlUrl("http://127.0.0.1:1").joinTimeout(Duration.ofSeconds(5)).join());
        assertTrue((System.nanoTime() - t0) / 1e9 < 30);
    }

    @Test @Timeout(300)
    void throughputBenchmarkThroughDerpAndDirect() throws Exception {
        try (Oracles.Running o = Oracles.start("go-control", "-authkey", "tskey-auth-life")) {
            String url = o.expect("BASEURL ", 20_000).substring("BASEURL ".length());
            for (boolean direct : new boolean[]{false, true}) {
                try (Tailnet a = b(url, "bench-a" + direct).cfg.includeLoopbackEndpoints(direct).join();
                     Tailnet c = b(url, "bench-b" + direct).cfg.includeLoopbackEndpoints(direct).join()) {
                    byte[] data = new byte[24 * 1024 * 1024];
                    new Random(1).nextBytes(data);
                    ExecutorService ex = Executors.newCachedThreadPool();
                    try (ServerSocket ss = a.listen(5001)) {
                        Future<Long> rx = ex.submit(() -> {
                            try (Socket s = ss.accept()) {
                                long n = 0;
                                byte[] buf = new byte[65536];
                                int k;
                                while ((k = s.getInputStream().read(buf)) >= 0) n += k;
                                return n;
                            }
                        });
                        if (direct) { // let disco establish the direct path first
                            long dl = System.nanoTime() + 20_000_000_000L;
                            while (!c.isDirect("bench-a" + direct) && System.nanoTime() < dl) { c.ping("bench-a" + direct, 3000); Thread.sleep(300); }
                        }
                        long t0 = System.nanoTime();
                        try (Socket s = c.dial("bench-a" + direct, 5001)) {
                            s.getOutputStream().write(data);
                            s.getOutputStream().flush();
                        }
                        assertEquals(data.length, rx.get(120, TimeUnit.SECONDS));
                        double secs = (System.nanoTime() - t0) / 1e9;
                        System.out.printf("BENCH %s path: %d MiB in %.2fs = %.0f Mbit/s (direct=%b)%n",
                                direct ? "direct" : "DERP", data.length >> 20, secs, data.length * 8 / secs / 1e6, c.isDirect("bench-a" + direct));
                    }
                    ex.shutdownNow();
                }
            }
        }
    }
}
