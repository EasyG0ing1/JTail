package com.simtechdata.jtail.e2e;

import static org.junit.jupiter.api.Assertions.*;

import com.simtechdata.jtail.JTail;
import com.simtechdata.jtail.Tailnet;
import com.simtechdata.jtail.testutil.Oracles;
import java.net.Socket;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

class FeaturesTest {
    @Test @Timeout(90)
    void interactiveLoginFlowCompletesOnceTheUserVisitsTheAuthUrl() throws Exception {
        try (Oracles.Running ctl = Oracles.start("go-control", "-requireauth")) {
            String url = ctl.expect("BASEURL ", 20_000).substring("BASEURL ".length());
            AtomicReference<String> shown = new AtomicReference<>();
            try (Tailnet n = JTail.network().hostname("interactive").controlUrl(url).joinTimeout(Duration.ofSeconds(40))
                    .onLoginRequired(authUrl -> {
                        shown.set(authUrl);
                        try { ctl.send("completeauth " + authUrl); } catch (Exception e) { throw new RuntimeException(e); }
                    }).join()) {
                assertNotNull(shown.get(), "login handler must receive the URL");
                assertTrue(shown.get().contains("/auth/"), shown.get());
                assertEquals("COMPLETEAUTH true", ctl.expect("COMPLETEAUTH", 5000));
                assertTrue(n.address().getHostAddress().startsWith("100."));
            }
        }
    }

    @Test @Timeout(90)
    void withoutAHandlerAnAuthUrlIsAnErrorNotAHang() throws Exception {
        try (Oracles.Running ctl = Oracles.start("go-control", "-requireauth")) {
            String url = ctl.expect("BASEURL ", 20_000).substring("BASEURL ".length());
            var e = assertThrows(com.simtechdata.jtail.JTailException.class, () -> JTail.network().authKey("tskey-whatever")
                    .hostname("x").controlUrl(url).joinTimeout(Duration.ofSeconds(20)).join());
            assertTrue(e.getMessage().contains("interactive login"), e.getMessage());
        }
    }

    @Test @Timeout(180)
    void magicDnsExtraRecordsAndSplitDnsOverTheTailnet() throws Exception {
        // Go node registers first, so the test control server gives it 100.64.0.1 - which we name as the split-DNS resolver.
        try (Oracles.Running ctl = Oracles.start("go-control", "-authkey", "k", "-extrarecord", "svc.jtail.test=100.64.5.5",
                "-dnsroute", "corp.test=100.64.0.1")) {
            String url = ctl.expect("BASEURL ", 20_000).substring("BASEURL ".length());
            try (Oracles.Running go = Oracles.start("go-tsnet", "-control", url, "-authkey", "k", "-host", "dns-go")) {
                String up = go.expect("UP", 60_000);
                assertFalse(up.startsWith("UP_ERR"), up);
                assertEquals("100.64.0.1", up.split(" ")[1], "test control hands out addresses in registration order");
                go.send("dnsserve 53");
                go.expect("DNSSERVE_LISTENING", 10_000);
                go.send("echo 7000");
                go.expect("ECHO_LISTENING", 10_000);
                try (Tailnet java = JTail.network().authKey("k").hostname("dns-java").controlUrl(url).joinTimeout(Duration.ofSeconds(60)).join()) {
                    // 1. MagicDNS extra record from the netmap
                    assertEquals("100.64.5.5", java.resolve("svc.jtail.test").getHostAddress());
                    // 2. split DNS: corp.test is delegated to the Go node's DNS server, queried over the tailnet itself
                    long dl = System.nanoTime() + 20_000_000_000L;
                    while (java.peers().isEmpty() && System.nanoTime() < dl) Thread.sleep(200);
                    assertEquals("100.64.0.1", java.resolve("db.corp.test").getHostAddress());
                    assertTrue(go.expect("DNS_QUERY", 10_000).contains("db.corp.test"));
                    // 3. ...and the resolved name is immediately dial-able
                    try (Socket s = java.dial("db.corp.test", 7000)) {
                        s.getOutputStream().write("via-dns".getBytes());
                        s.getOutputStream().flush();
                        byte[] buf = new byte[32];
                        int n = s.getInputStream().read(buf);
                        assertEquals("go:via-dns", new String(buf, 0, n));
                    }
                    assertThrows(java.net.UnknownHostException.class, () -> java.resolve("nonexistent.example.org"));
                }
            }
        }
    }
}
