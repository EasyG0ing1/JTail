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
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** Recovery from severed DERP and control connections. */
class ResilienceTest {
    private static Tailnet join(String url, String host, boolean direct) {
        return JTail.network().authKey("k").hostname(host).controlUrl(url).directPaths(direct)
                .joinTimeout(Duration.ofSeconds(45)).join();
    }

    private static String roundTrip(Socket s, String msg) throws Exception {
        OutputStream out = s.getOutputStream();
        out.write(msg.getBytes());
        out.flush();
        byte[] buf = new byte[64];
        int n = s.getInputStream().read(buf);
        return new String(buf, 0, n);
    }

    @Test @Timeout(180)
    void derpOnlyModeWorksAndRecoversWhenTheRelayConnectionIsSevered() throws Exception {
        try (Oracles.Running ctl = Oracles.start("go-control", "-authkey", "k")) {
            String url = ctl.expect("BASEURL ", 20_000).substring("BASEURL ".length());
            try (Tailnet a = join(url, "relay-a", false); Tailnet b = join(url, "relay-b", false)) {
                ExecutorService ex = Executors.newCachedThreadPool();
                try (ServerSocket ss = a.listen(6000)) {
                    ex.submit(() -> { // echo until the peer closes
                        try (Socket s = ss.accept()) {
                            InputStream in = s.getInputStream();
                            byte[] buf = new byte[64];
                            int n;
                            while ((n = in.read(buf)) >= 0) { s.getOutputStream().write(buf, 0, n); s.getOutputStream().flush(); }
                        }
                        return null;
                    });
                    try (Socket c = b.dial("relay-a", 6000)) {
                        assertEquals("one", roundTrip(c, "one"));
                        assertFalse(b.isDirect("relay-a"), "directPaths(false) must keep traffic on DERP");

                        ctl.send("dropderp");
                        assertTrue(ctl.expect("DROPPED_DERP", 5000).matches("DROPPED_DERP [1-9].*"), "oracle should have severed relay connections");

                        // the very same TCP connection must come back after the relay reconnects
                        c.setSoTimeout(60_000);
                        assertEquals("two", roundTrip(c, "two"));
                        assertEquals("three", roundTrip(c, "three"));
                    }
                }
                ex.shutdownNow();
            }
        }
    }

    @Test @Timeout(180)
    void controlConnectionLossIsRecoveredAndNewPeersAppear() throws Exception {
        try (Oracles.Running ctl = Oracles.start("go-control", "-authkey", "k")) {
            String url = ctl.expect("BASEURL ", 20_000).substring("BASEURL ".length());
            try (Tailnet a = join(url, "ctl-a", false)) {
                ctl.send("dropctl");
                assertTrue(ctl.expect("DROPPED_CTL", 5000).matches("DROPPED_CTL [1-9].*"));
                // a late joiner after the outage must still become visible to A once A's control stream reconnects
                try (Tailnet c = join(url, "ctl-c", false)) {
                    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
                    while (a.peers().stream().noneMatch(p -> p.name().startsWith("ctl-c")) && System.nanoTime() < deadline) Thread.sleep(250);
                    assertTrue(a.peers().stream().anyMatch(p -> p.name().startsWith("ctl-c")), "A never re-synced its netmap");
                    assertTrue(a.ping("ctl-c", 20_000) >= 0);
                }
            }
        }
    }
}
