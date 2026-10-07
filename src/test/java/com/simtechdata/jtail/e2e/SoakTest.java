package com.simtechdata.jtail.e2e;

import static org.junit.jupiter.api.Assertions.*;

import com.simtechdata.jtail.JTail;
import com.simtechdata.jtail.Tailnet;
import com.simtechdata.jtail.testutil.Oracles;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** Many short connections plus concurrent streams: results must be correct and nothing may leak. */
class SoakTest {
    @Test @Timeout(240)
    void manyConnectionsDoNotLeakThreadsOrConnectionState() throws Exception {
        try (Oracles.Running ctl = Oracles.start("go-control", "-authkey", "k")) {
            String url = ctl.expect("BASEURL ", 20_000).substring("BASEURL ".length());
            try (Tailnet a = JTail.network().authKey("k").hostname("soak-a").controlUrl(url).joinTimeout(Duration.ofSeconds(45)).join();
                 Tailnet b = JTail.network().authKey("k").hostname("soak-b").controlUrl(url).joinTimeout(Duration.ofSeconds(45)).join()) {
                ExecutorService ex = Executors.newCachedThreadPool();
                try (ServerSocket ss = a.listen(9100)) {
                    ex.submit(() -> {
                        while (!ss.isClosed()) {
                            Socket s = ss.accept();
                            ex.submit(() -> {
                                try (s) {
                                    byte[] buf = new byte[4096];
                                    int n;
                                    while ((n = s.getInputStream().read(buf)) >= 0) { s.getOutputStream().write(buf, 0, n); s.getOutputStream().flush(); }
                                }
                                return null;
                            });
                        }
                        return null;
                    });
                    // warm up so thread pools reach steady state before we count
                    try (Socket w = b.dial("soak-a", 9100)) { w.getOutputStream().write(1); w.getOutputStream().flush(); w.getInputStream().read(); }
                    int threadsBefore = Thread.activeCount();

                    int total = 400;
                    Semaphore gate = new Semaphore(16);   // 16 concurrent clients
                    List<Future<Boolean>> fs = new ArrayList<>();
                    for (int i = 0; i < total; i++) {
                        final int id = i;
                        gate.acquire();
                        fs.add(ex.submit(() -> {
                            try (Socket s = b.dial("soak-a", 9100)) {
                                byte[] msg = ("msg-" + id + "-" + "x".repeat(id % 700)).getBytes();
                                s.getOutputStream().write(msg);
                                s.getOutputStream().flush();
                                byte[] got = s.getInputStream().readNBytes(msg.length);
                                return java.util.Arrays.equals(msg, got);
                            } finally {
                                gate.release();
                            }
                        }));
                    }
                    int ok = 0;
                    for (Future<Boolean> f : fs) if (f.get(120, TimeUnit.SECONDS)) ok++;
                    assertEquals(total, ok);

                    // connection state drains once TIME_WAIT expires (10 s in this stack)
                    long deadline = System.nanoTime() + 40_000_000_000L;
                    while ((a.connectionCount() > 2 || b.connectionCount() > 2) && System.nanoTime() < deadline) Thread.sleep(500);
                    assertTrue(a.connectionCount() <= 2 && b.connectionCount() <= 2,
                            "connections leaked: a=" + a.connectionCount() + " b=" + b.connectionCount());
                    int threadsAfter = Thread.activeCount();
                    System.out.println("SOAK threads before=" + threadsBefore + " after=" + threadsAfter + " conns a/b="
                            + a.connectionCount() + "/" + b.connectionCount());
                    assertTrue(threadsAfter < threadsBefore + 40, "thread count grew from " + threadsBefore + " to " + threadsAfter);
                }
                ex.shutdownNow();
            }
        }
    }
}
