package com.simtechdata.jtail.e2e;

import static org.junit.jupiter.api.Assertions.*;

import com.simtechdata.jtail.JTail;
import com.simtechdata.jtail.Tailnet;
import com.simtechdata.jtail.net.HttpProxy;
import com.simtechdata.jtail.testutil.Oracles;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** The "plug into existing code" surfaces: SocketFactory and the local HTTP proxy. */
class IntegrationApiTest {
    /** A tiny HTTP/1.1 server on the tailnet: GET /hello -> "hello-from-a <query>"; closes after each response. */
    static void serveHttp(ServerSocket ss, ExecutorService ex) {
        ex.submit(() -> {
            while (!ss.isClosed()) {
                Socket s = ss.accept();
                ex.submit(() -> {
                    try (s) {
                        BufferedReader r = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.ISO_8859_1));
                        String line = r.readLine();
                        String host = "";
                        for (String h; (h = r.readLine()) != null && !h.isEmpty(); ) if (h.toLowerCase().startsWith("host:")) host = h.substring(5).trim();
                        String target = line.split(" ")[1];
                        byte[] body = ("hello-from-a target=" + target + " host=" + host).getBytes();
                        s.getOutputStream().write(("HTTP/1.1 200 OK\r\nContent-Length: " + body.length + "\r\nConnection: close\r\n\r\n").getBytes());
                        s.getOutputStream().write(body);
                        s.getOutputStream().flush();
                    }
                    return null;
                });
            }
            return null;
        });
    }

    @Test @Timeout(120)
    void socketFactoryAndHttpProxyReachTailnetHosts() throws Exception {
        try (Oracles.Running ctl = Oracles.start("go-control", "-authkey", "k")) {
            String url = ctl.expect("BASEURL ", 20_000).substring("BASEURL ".length());
            try (Tailnet a = JTail.network().authKey("k").hostname("api-a").controlUrl(url).joinTimeout(Duration.ofSeconds(45)).join();
                 Tailnet b = JTail.network().authKey("k").hostname("api-b").controlUrl(url).joinTimeout(Duration.ofSeconds(45)).join()) {
                ExecutorService ex = Executors.newCachedThreadPool();
                try (ServerSocket ss = a.listen(8080)) {
                    serveHttp(ss, ex);

                    // 1. SocketFactory: connected-by-name and unconnected-then-connect, as JDBC-style code does
                    javax.net.SocketFactory sf = b.socketFactory();
                    try (Socket s = sf.createSocket("api-a", 8080)) {
                        s.getOutputStream().write("GET /via-factory HTTP/1.1\r\nHost: api-a\r\n\r\n".getBytes());
                        s.getOutputStream().flush();
                        String resp = new String(s.getInputStream().readAllBytes());
                        assertTrue(resp.contains("target=/via-factory"), resp);
                    }
                    try (Socket s = sf.createSocket()) {
                        assertFalse(s.isConnected());
                        s.connect(InetSocketAddress.createUnresolved("api-a", 8080), 10_000);
                        assertTrue(s.isConnected());
                        s.getOutputStream().write("GET /late HTTP/1.1\r\nHost: api-a\r\n\r\n".getBytes());
                        s.getOutputStream().flush();
                        assertTrue(new String(s.getInputStream().readAllBytes()).contains("target=/late"));
                    }

                    // 2. HTTP proxy used by the JDK HttpClient (absolute-URI form)
                    try (HttpProxy proxy = b.startHttpProxy(0)) {
                        HttpClient client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
                                .proxy(ProxySelector.of(new InetSocketAddress("127.0.0.1", proxy.port()))).build();
                        HttpResponse<String> r = client.send(HttpRequest.newBuilder(URI.create("http://api-a:8080/hello?x=1")).build(),
                                HttpResponse.BodyHandlers.ofString());
                        assertEquals(200, r.statusCode());
                        assertEquals("hello-from-a target=/hello?x=1 host=api-a:8080", r.body());

                        // 3. CONNECT tunnel (what HTTPS clients use)
                        try (Socket t = new Socket("127.0.0.1", proxy.port())) {
                            t.getOutputStream().write("CONNECT api-a:8080 HTTP/1.1\r\nHost: api-a:8080\r\n\r\n".getBytes());
                            t.getOutputStream().flush();
                            BufferedReader br = new BufferedReader(new InputStreamReader(t.getInputStream()));
                            assertTrue(br.readLine().contains("200"));
                            while (!br.readLine().isEmpty()) { /* skip headers */ }
                            t.getOutputStream().write("GET /tunnel HTTP/1.1\r\nHost: api-a\r\n\r\n".getBytes());
                            t.getOutputStream().flush();
                            StringBuilder all = new StringBuilder();
                            for (String l; (l = br.readLine()) != null; ) all.append(l).append('\n');
                            assertTrue(all.toString().contains("target=/tunnel"), all.toString());
                        }

                        // 4. unknown host is a clean 502, not a hang
                        HttpResponse<String> bad = client.send(HttpRequest.newBuilder(URI.create("http://no-such-node:80/")).build(),
                                HttpResponse.BodyHandlers.ofString());
                        assertEquals(502, bad.statusCode());
                    }
                }
                ex.shutdownNow();
            }
        }
    }
}
