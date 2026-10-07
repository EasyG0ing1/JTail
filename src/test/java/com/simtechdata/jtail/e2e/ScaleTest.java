package com.simtechdata.jtail.e2e;

import static org.junit.jupiter.api.Assertions.*;

import com.simtechdata.jtail.JTail;
import com.simtechdata.jtail.Tailnet;
import com.simtechdata.jtail.testutil.Oracles;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

class ScaleTest {
    @Test @Timeout(240)
    void joinsAndStaysResponsiveInATailnetWithHundredsOfPeers() throws Exception {
        try (Oracles.Running ctl = Oracles.start("go-control", "-authkey", "k")) {
            String url = ctl.expect("BASEURL ", 20_000).substring("BASEURL ".length());
            ctl.send("addfake 600");
            ctl.expect("ADDED_FAKE", 20_000);
            long t0 = System.nanoTime();
            try (Tailnet a = JTail.network().authKey("k").hostname("scale-a").controlUrl(url).joinTimeout(Duration.ofSeconds(90)).join();
                 Tailnet b = JTail.network().authKey("k").hostname("scale-b").controlUrl(url).joinTimeout(Duration.ofSeconds(90)).join()) {
                double joinSecs = (System.nanoTime() - t0) / 1e9;
                long dl = System.nanoTime() + 60_000_000_000L;
                while (a.peers().size() < 601 && System.nanoTime() < dl) Thread.sleep(200);
                assertTrue(a.peers().size() >= 601, "peers visible: " + a.peers().size());
                System.out.printf("SCALE two nodes joined a 600-peer tailnet in %.1fs, %d peers visible%n", joinSecs, a.peers().size());

                // name lookup and real traffic still work with 600 WireGuard peers configured
                ExecutorService ex = Executors.newCachedThreadPool();
                try (ServerSocket ss = a.listen(9200)) {
                    Future<String> got = ex.submit(() -> {
                        try (Socket s = ss.accept()) { return new String(s.getInputStream().readNBytes(5)); }
                    });
                    long t1 = System.nanoTime();
                    try (Socket s = b.dial("scale-a", 9200)) {
                        s.getOutputStream().write("hello".getBytes());
                        s.getOutputStream().flush();
                    }
                    assertEquals("hello", got.get(30, TimeUnit.SECONDS));
                    System.out.printf("SCALE first connection in %d ms%n", (System.nanoTime() - t1) / 1_000_000);
                }
                Runtime rt = Runtime.getRuntime();
                rt.gc();
                System.out.printf("SCALE heap used ~%d MiB for two nodes with 600 peers each%n", (rt.totalMemory() - rt.freeMemory()) >> 20);
                ex.shutdownNow();
            }
        }
    }
}
