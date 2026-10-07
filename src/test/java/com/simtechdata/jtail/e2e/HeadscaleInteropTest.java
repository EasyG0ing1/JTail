package com.simtechdata.jtail.e2e;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.simtechdata.jtail.JTail;
import com.simtechdata.jtail.Tailnet;
import com.simtechdata.jtail.testutil.Oracles;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

/**
 * Compatibility with Headscale, an independent open-source implementation of the Tailscale control server. Enabled with
 * -Djtail.headscale.bin=/path/to/headscale (plus the usual -Djtail.oracle.dir for the Go test peers).
 */
class HeadscaleInteropTest {
    static int freePort() throws IOException {
        try (ServerSocket s = new ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) { return s.getLocalPort(); }
    }

    static String run(Path bin, long timeoutSec, String... args) throws Exception {
        List<String> cmd = new java.util.ArrayList<>();
        cmd.add(bin.toString());
        cmd.addAll(List.of(args));
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(p.waitFor(timeoutSec, TimeUnit.SECONDS), "command timed out: " + cmd);
        assertEquals(0, p.exitValue(), "command failed: " + cmd + "\n" + out);
        return out;
    }

    @Test @Timeout(300)
    void javaNodeAndGoClientInteroperateThroughHeadscale(@TempDir Path dir) throws Exception {
        String hsBin = System.getProperty("jtail.headscale.bin");
        assumeTrue(hsBin != null && Files.isExecutable(Path.of(hsBin)), "headscale binary not configured");
        Path hs = Path.of(hsBin);

        try (Oracles.Running derp = Oracles.start("go-control")) { // only its DERP relay is used here
            derp.expect("BASEURL ", 20_000);
            int derpPort = Integer.parseInt(derp.expect("DERP ", 20_000).substring("DERP ".length()));
            int port = freePort(), metrics = freePort(), grpc = freePort();
            Files.writeString(dir.resolve("derp.yaml"), """
                    regions:
                      900:
                        regionid: 900
                        regioncode: test
                        regionname: Test
                        nodes:
                          - name: 900a
                            regionid: 900
                            hostname: 127.0.0.1
                            ipv4: 127.0.0.1
                            derpport: %d
                            stunport: -1
                            insecurefortests: true
                    """.formatted(derpPort));
            Files.writeString(dir.resolve("config.yaml"), """
                    server_url: http://127.0.0.1:%d
                    listen_addr: 127.0.0.1:%d
                    metrics_listen_addr: 127.0.0.1:%d
                    grpc_listen_addr: 127.0.0.1:%d
                    grpc_allow_insecure: true
                    noise:
                      private_key_path: %s/noise.key
                    prefixes:
                      v4: 100.64.0.0/10
                      v6: fd7a:115c:a1e0::/48
                    derp:
                      server:
                        enabled: false
                      urls: []
                      paths:
                        - %s/derp.yaml
                      auto_update_enabled: false
                    database:
                      type: sqlite
                      sqlite:
                        path: %s/db.sqlite
                    log:
                      level: warn
                    dns:
                      magic_dns: true
                      base_domain: jtail.test
                      override_local_dns: false
                      nameservers:
                        global: []
                    unix_socket: %s/hs.sock
                    logtail:
                      enabled: false
                    """.formatted(port, port, metrics, grpc, dir, dir, dir, dir));
            Path cfg = dir.resolve("config.yaml");
            Process server = new ProcessBuilder(hs.toString(), "serve", "-c", cfg.toString()).redirectErrorStream(true)
                    .redirectOutput(dir.resolve("headscale.log").toFile()).start();
            try {
                long deadline = System.nanoTime() + 40_000_000_000L;
                while (System.nanoTime() < deadline) {
                    try (Socket s = new Socket()) { s.connect(new InetSocketAddress("127.0.0.1", port), 500); break; }
                    catch (IOException e) { assertTrue(server.isAlive(), "headscale exited: " + Files.readString(dir.resolve("headscale.log"))); Thread.sleep(300); }
                }
                String url = "http://127.0.0.1:" + port;

                run(hs, 30, "-c", cfg.toString(), "users", "create", "jtail");
                String keyOut = run(hs, 30, "-c", cfg.toString(), "preauthkeys", "create", "--user", "1", "--reusable", "--expiration", "1h");
                String authKey = keyOut.lines().map(String::trim).filter(l -> !l.isEmpty()).reduce((a, b) -> b).orElseThrow();
                assertTrue(authKey.length() > 20, "unexpected preauthkey output: " + keyOut);

                try (Oracles.Running go = Oracles.start("go-tsnet", "-control", url, "-authkey", authKey, "-host", "hs-go");
                     Tailnet java = JTail.network().authKey(authKey).hostname("hs-java").controlUrl(url)
                             .joinTimeout(Duration.ofSeconds(60)).join()) {
                    String up = go.expect("UP", 60_000);
                    assertFalse(up.startsWith("UP_ERR"), up + "\n" + Files.readString(dir.resolve("headscale.log")));
                    go.send("echo 7000");
                    go.expect("ECHO_LISTENING", 10_000);

                    long dl = System.nanoTime() + 30_000_000_000L;
                    while (java.peers().stream().noneMatch(p -> p.name().startsWith("hs-go")) && System.nanoTime() < dl) Thread.sleep(200);
                    assertTrue(java.peers().stream().anyMatch(p -> p.name().startsWith("hs-go")),
                            "Java never saw the Go peer through Headscale; peers=" + java.peers());
                    System.out.println("HEADSCALE java=" + java.name() + " " + java.addresses() + " peers=" + java.peers().stream().map(p -> p.name()).toList());

                    // Java -> Go by MagicDNS name
                    try (Socket s = java.dial("hs-go", 7000)) {
                        s.getOutputStream().write("via-headscale".getBytes());
                        s.getOutputStream().flush();
                        byte[] buf = new byte[64];
                        int n = s.getInputStream().read(buf);
                        assertEquals("go:via-headscale", new String(buf, 0, n));
                    }
                    // Go -> Java
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
                        go.send("dial " + java.address().getHostAddress() + ":7001 hello-from-go");
                        assertEquals("DIAL_REPLY java:hello-from-go", go.expect("DIAL_", 30_000));
                        assertEquals("hello-from-go", got.get(10, TimeUnit.SECONDS));
                    }
                    assertTrue(java.ping("hs-go", 15_000) >= 0);
                    ex.shutdownNow();
                }
            } finally {
                server.destroy();
            }
        }
    }
}
