package com.simtechdata.jtail.net;

import static org.junit.jupiter.api.Assertions.*;

import com.simtechdata.jtail.testutil.NetstackPair;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

class HttpProxyTest {
    final NetstackPair net = new NetstackPair();
    final ExecutorService ex = Executors.newCachedThreadPool();
    HttpProxy proxy;

    @AfterEach void tearDown() {
        if (proxy != null) proxy.close();
        ex.shutdownNow();
        net.close();
    }

    HttpProxy start() throws IOException {
        proxy = new HttpProxy(net.dialerFromA(), 0);
        return proxy;
    }

    /** Sends {@code request} to the proxy and returns everything it sends back until it closes. */
    String exchange(String request) throws IOException {
        try (Socket s = new Socket("127.0.0.1", proxy.port())) {
            s.setSoTimeout(10_000);
            s.getOutputStream().write(request.getBytes(StandardCharsets.ISO_8859_1));
            s.getOutputStream().flush();
            return new String(s.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
        }
    }

    @Test
    void reportsWhetherItIsClosed() throws IOException {
        start();
        assertFalse(proxy.isClosed());
        proxy.close();
        assertTrue(proxy.isClosed());
        proxy.close();                                   // closing twice is harmless
        assertThrows(IOException.class, () -> new Socket("127.0.0.1", proxy.port()).close());
    }

    @Test
    void acceptsConnectionsOnTheLoopbackAddress() throws IOException {
        start();
        assertTrue(proxy.port() > 0);
        try (Socket s = new Socket("127.0.0.1", proxy.port())) {
            assertTrue(s.isConnected());
        }
    }

    @Test @Timeout(30)
    void forwardsAbsoluteUriGetToATailnetServer() throws Exception {
        start();
        Future<?> server = serveHttp(8080, "hello from b");
        String reply = exchange("GET http://b:8080/status?x=1 HTTP/1.1\r\nHost: b:8080\r\nProxy-Authorization: secret\r\n\r\n");
        assertTrue(reply.startsWith("HTTP/1.1 200 OK"), reply);
        assertTrue(reply.endsWith("hello from b"), reply);
        server.get(5, TimeUnit.SECONDS);
    }

    @Test @Timeout(30)
    void connectTunnelCarriesBytesBothWays() throws Exception {
        start();
        try (ServerSocket server = net.listenOnB(8443)) {
            Future<?> echo = ex.submit(() -> {
                try (Socket s = server.accept()) { s.getInputStream().transferTo(s.getOutputStream()); }
                return null;
            });
            try (Socket client = new Socket("127.0.0.1", proxy.port())) {
                client.setSoTimeout(10_000);
                client.getOutputStream().write("CONNECT b:8443 HTTP/1.1\r\nHost: b:8443\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
                client.getOutputStream().flush();
                String status = readHeaderLine(client.getInputStream());
                assertTrue(status.contains("200 Connection Established"), status);
                assertEquals("", readHeaderLine(client.getInputStream()), "the blank line that ends the response headers");
                client.getOutputStream().write("tunnelled".getBytes(StandardCharsets.US_ASCII));
                client.getOutputStream().flush();
                client.shutdownOutput();
                assertEquals("tunnelled", new String(client.getInputStream().readAllBytes(), StandardCharsets.US_ASCII));
            }
            echo.get(5, TimeUnit.SECONDS);
        }
    }

    @Test @Timeout(30)
    void unknownTailnetHostIsAnHttp502() throws Exception {
        start();
        String reply = exchange("GET http://nobody.example:80/ HTTP/1.1\r\nHost: nobody.example\r\n\r\n");
        assertTrue(reply.startsWith("HTTP/1.1 502"), reply);
        assertTrue(reply.contains("Bad Gateway"), reply);
    }

    @Test @Timeout(30)
    void malformedAndUnsupportedRequestsAreRejected() throws Exception {
        start();
        assertTrue(exchange("GET /relative HTTP/1.1\r\n\r\n").startsWith("HTTP/1.1 400"), "relative URIs are refused");
        assertTrue(exchange("GET https://b/ HTTP/1.1\r\n\r\n").startsWith("HTTP/1.1 400"), "only http:// is proxied");
        assertTrue(exchange("GET\r\n\r\n").startsWith("HTTP/1.1 400"), "a request line without a target is refused");
        assertTrue(exchange("GET http://[bad/ HTTP/1.1\r\n\r\n").startsWith("HTTP/1.1 400"), "unparseable URIs are refused");
    }

    @Test @Timeout(30)
    void closedProxyStopsAccepting() throws Exception {
        HttpProxy p = new HttpProxy(net.dialerFromA(), 0);
        int port = p.port();
        p.close();
        assertThrows(IOException.class, () -> new Socket("127.0.0.1", port).close());
    }

    // ---- authentication (opt-in) ----

    static String basic(String userAndPassword) {
        return "Basic " + java.util.Base64.getEncoder().encodeToString(userAndPassword.getBytes(StandardCharsets.UTF_8));
    }

    HttpProxy startWithAuth() throws IOException {
        proxy = new HttpProxy(net.dialerFromA(), 0, "jtail", "s3cret:with:colons");
        return proxy;
    }

    @Test
    void proxiesAreOpenByDefaultAndReportTheirAuthMode() throws IOException {
        assertFalse(start().requiresAuthentication());
        proxy.close();
        assertTrue(startWithAuth().requiresAuthentication());
    }

    @Test @Timeout(30)
    void withAuthenticationMissingOrWrongCredentialsGet407AndNothingIsDialled() throws Exception {
        startWithAuth();
        String none = exchange("GET http://b:8080/ HTTP/1.1\r\nHost: b\r\n\r\n");
        assertTrue(none.startsWith("HTTP/1.1 407"), none);
        assertTrue(none.contains("Proxy-Authenticate: Basic realm=\"JTail\""), none);

        for (String bad : new String[]{basic("jtail:wrong"), basic("other:s3cret:with:colons"), "Bearer abc", "Basic", "Basic !!!"}) {
            String reply = exchange("GET http://b:8080/ HTTP/1.1\r\nHost: b\r\nProxy-Authorization: " + bad + "\r\n\r\n");
            assertTrue(reply.startsWith("HTTP/1.1 407"), bad + " -> " + reply);
        }
        assertTrue(exchange("CONNECT b:8443 HTTP/1.1\r\nHost: b:8443\r\n\r\n").startsWith("HTTP/1.1 407"),
                "CONNECT needs credentials too");
        assertEquals(0, net.a.connectionCount(), "an unauthenticated request must never reach the tailnet");
    }

    @Test @Timeout(30)
    void withAuthenticationCorrectCredentialsAreForwardedAndNotLeakedUpstream() throws Exception {
        startWithAuth();
        ServerSocket upstream = net.listenOnB(8080);
        java.util.concurrent.atomic.AtomicReference<String> seen = new java.util.concurrent.atomic.AtomicReference<>();
        Future<?> server = ex.submit(() -> {
            try (upstream; Socket s = upstream.accept()) {
                ByteArrayOutputStream req = new ByteArrayOutputStream();
                InputStream in = s.getInputStream();
                int state = 0;
                for (int c; (c = in.read()) >= 0; ) {
                    req.write(c);
                    state = (c == '\r' && (state == 0 || state == 2)) ? state + 1 : (c == '\n' && (state == 1 || state == 3)) ? state + 1 : 0;
                    if (state == 4) break;
                }
                seen.set(req.toString(StandardCharsets.ISO_8859_1));
                s.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".getBytes(StandardCharsets.US_ASCII));
            }
            return null;
        });
        String reply = exchange("GET http://b:8080/ HTTP/1.1\r\nHost: b:8080\r\nproxy-AUTHORIZATION:   basic "
                + basic("jtail:s3cret:with:colons").substring(6) + "\r\n\r\n");
        assertTrue(reply.startsWith("HTTP/1.1 200 OK"), reply);
        server.get(5, TimeUnit.SECONDS);
        assertFalse(seen.get().toLowerCase().contains("proxy-authorization"), "credentials are for the proxy only:\n" + seen.get());
    }

    @Test
    void invalidCredentialConfigurationIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> new HttpProxy(net.dialerFromA(), 0, "user", null));
        assertThrows(IllegalArgumentException.class, () -> new HttpProxy(net.dialerFromA(), 0, null, "pw"));
        assertThrows(IllegalArgumentException.class, () -> new HttpProxy(net.dialerFromA(), 0, "", "pw"));
        assertThrows(IllegalArgumentException.class, () -> new HttpProxy(net.dialerFromA(), 0, "a:b", "pw"),
                "a colon in the user name would make the Basic credentials ambiguous");
    }

    // ---- header limits ----

    static String headers(int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) sb.append("X-H").append(i).append(": v\r\n");
        return sb.toString();
    }

    @Test @Timeout(30)
    void twoHundredHeaderLinesAreAcceptedAndTwoHundredAndOneAreNot() throws Exception {
        start();
        String ok = exchange("GET http://nobody.example:80/ HTTP/1.1\r\n" + headers(HttpProxy.MAX_HEADER_LINES) + "\r\n");
        assertTrue(ok.startsWith("HTTP/1.1 502"), "the request was accepted and failed only at the tailnet: " + ok);
        String tooMany = exchange("GET http://nobody.example:80/ HTTP/1.1\r\n" + headers(HttpProxy.MAX_HEADER_LINES + 1) + "\r\n");
        assertTrue(tooMany.startsWith("HTTP/1.1 431"), tooMany);
    }

    @Test @Timeout(30)
    void aHeaderLineOf128KbIsAcceptedAndOneByteMoreIsNot() throws Exception {
        start();
        String name = "X-Big: ";
        String atLimit = name + "a".repeat(HttpProxy.MAX_LINE_BYTES - name.length());
        assertEquals(HttpProxy.MAX_LINE_BYTES, atLimit.length());
        String ok = exchange("GET http://nobody.example:80/ HTTP/1.1\r\n" + atLimit + "\r\n\r\n");
        assertTrue(ok.startsWith("HTTP/1.1 502"), ok.substring(0, Math.min(80, ok.length())));
        String over = exchange("GET http://nobody.example:80/ HTTP/1.1\r\n" + atLimit + "a\r\n\r\n");
        assertTrue(over.startsWith("HTTP/1.1 431"), over.substring(0, Math.min(80, over.length())));
    }

    @Test @Timeout(30)
    void anOversizedRequestLineIsRejectedToo() throws Exception {
        start();
        String reply = exchange("GET http://b/" + "a".repeat(HttpProxy.MAX_LINE_BYTES) + " HTTP/1.1\r\n\r\n");
        assertTrue(reply.startsWith("HTTP/1.1 431"), reply.substring(0, Math.min(80, reply.length())));
    }

    /** Serves one plain HTTP response on b:{@code port}, then closes the connection. */
    Future<?> serveHttp(int port, String body) throws IOException {
        ServerSocket server = net.listenOnB(port);
        return ex.submit(() -> {
            try (server; Socket s = server.accept()) {
                readUntilBlankLine(s.getInputStream());
                String resp = "HTTP/1.1 200 OK\r\nContent-Length: " + body.length() + "\r\nConnection: close\r\n\r\n" + body;
                s.getOutputStream().write(resp.getBytes(StandardCharsets.ISO_8859_1));
                s.getOutputStream().flush();
            }
            return null;
        });
    }

    static void readUntilBlankLine(InputStream in) throws IOException {
        int state = 0;
        for (int c; (c = in.read()) >= 0; ) {
            state = switch (state) {
                case 0 -> c == '\r' ? 1 : 0;
                case 1 -> c == '\n' ? 2 : 0;
                case 2 -> c == '\r' ? 3 : 0;
                default -> c == '\n' ? 4 : 0;
            };
            if (state == 4) return;
        }
    }

    static String readHeaderLine(InputStream in) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        for (int c; (c = in.read()) >= 0 && c != '\n'; ) if (c != '\r') b.write(c);
        return b.toString(StandardCharsets.ISO_8859_1);
    }
}
