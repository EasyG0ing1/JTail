package com.simtechdata.jtail.net;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;

/**
 * A minimal local HTTP proxy (CONNECT tunnels plus absolute-URI GET/POST/...) that forwards through the tailnet, so
 * proxy-aware clients such as {@code java.net.http.HttpClient} can reach tailnet hosts:
 * <pre>{@code
 * HttpClient c = HttpClient.newBuilder().proxy(ProxySelector.of(new InetSocketAddress("127.0.0.1", proxy.port()))).build();
 * }</pre>
 * It listens on the loopback interface only. By default any local process can use it; pass a user name and password
 * to require HTTP Basic proxy authentication ({@code Proxy-Authorization}) from every client.
 *
 * <p>Request headers are bounded: at most {@value #MAX_HEADER_LINES} header lines per request and
 * {@value #MAX_LINE_BYTES} bytes per line. A request over either limit receives {@code 431}.
 */
public final class HttpProxy implements AutoCloseable {
    /** The most header lines (not counting the request line) accepted in one request. */
    public static final int MAX_HEADER_LINES = 200;
    /** The most bytes accepted in a single request or header line. */
    public static final int MAX_LINE_BYTES = 128 * 1024;
    /** How much unread request data is discarded after a 431 so the client can read the reply. */
    private static final int DRAIN_LIMIT = 64 * 1024;

    private final ServerSocket server;
    private final TailnetDialer dialer;
    private final byte[] expectedCredentials;   // base64 of "user:password" as ISO-8859-1 bytes; null = no authentication
    private final ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor();
    private volatile boolean closed;

    /** A request line or header block that exceeds {@link #MAX_LINE_BYTES} or {@link #MAX_HEADER_LINES}. */
    private static final class HeaderTooLarge extends IOException {
        private static final long serialVersionUID = 1L;
        HeaderTooLarge(String message) { super(message); }
    }

    /**
     * Starts the proxy without authentication. Applications normally call
     * {@link com.simtechdata.jtail.Tailnet#startHttpProxy(int)} instead.
     *
     * @param dialer opens the tailnet connections the proxy forwards to
     * @param port   the loopback port to listen on, or {@code 0} for any free port
     * @throws IOException if the port cannot be bound
     */
    public HttpProxy(TailnetDialer dialer, int port) throws IOException {
        this(dialer, port, null, null);
    }

    /**
     * Starts the proxy, optionally requiring HTTP Basic proxy authentication.
     *
     * @param dialer   opens the tailnet connections the proxy forwards to
     * @param port     the loopback port to listen on, or {@code 0} for any free port
     * @param username the user name clients must present, or {@code null} to require no authentication
     * @param password the password clients must present; must be {@code null} exactly when {@code username} is
     * @throws IllegalArgumentException if only one of the two is given, the user name is empty or contains a colon
     * @throws IOException              if the port cannot be bound
     */
    public HttpProxy(TailnetDialer dialer, int port, String username, String password) throws IOException {
        if (username == null) {
            if (password != null) throw new IllegalArgumentException("a password was given without a user name");
            this.expectedCredentials = null;
        } else {
            if (password == null) throw new IllegalArgumentException("a user name was given without a password");
            if (username.isEmpty() || username.indexOf(':') >= 0) {
                throw new IllegalArgumentException("the user name must be non-empty and must not contain ':'");
            }
            String token = Base64.getEncoder().encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
            this.expectedCredentials = token.getBytes(StandardCharsets.ISO_8859_1);
        }
        this.dialer = dialer;
        this.server = new ServerSocket(port, 50, InetAddress.getLoopbackAddress());
        Thread t = new Thread(this::acceptLoop, "jtail-http-proxy");
        t.setDaemon(true);
        t.start();
    }

    /** @return the loopback port the proxy listens on (useful when started with port {@code 0}) */
    public int port() { return server.getLocalPort(); }

    /** @return whether {@link #close()} has been called (a proxy is also closed by {@code Tailnet.close()}) */
    public boolean isClosed() { return closed; }

    /** @return whether clients must authenticate with a user name and password */
    public boolean requiresAuthentication() { return expectedCredentials != null; }

    private void acceptLoop() {
        while (!closed) {
            try {
                Socket c = server.accept();
                pool.execute(() -> handle(c));
            } catch (IOException e) {
                if (closed) return;
            }
        }
    }

    private void handle(Socket client) {
        try (client) {
            InputStream in = client.getInputStream();
            String requestLine;
            java.util.List<String> headers = new java.util.ArrayList<>();
            try {
                requestLine = readLine(in);
                if (requestLine == null || requestLine.isEmpty()) return;
                // Read the whole header block before any early reply: closing a socket that still has unread request
                // bytes makes the OS send a reset, which can discard the error response before the client reads it.
                for (String h; (h = readLine(in)) != null && !h.isEmpty(); ) {
                    if (headers.size() >= MAX_HEADER_LINES) {
                        throw new HeaderTooLarge("more than " + MAX_HEADER_LINES + " header lines");
                    }
                    headers.add(h);
                }
            } catch (HeaderTooLarge e) {
                reply(client, 431, "Request Header Fields Too Large");
                drain(client);
                return;
            }
            if (!authorized(headers)) {
                reply(client, 407, "Proxy Authentication Required", "Proxy-Authenticate: Basic realm=\"JTail\"");
                return;
            }
            String[] parts = requestLine.split(" ", 3);
            if (parts.length < 3) { reply(client, 400, "Bad Request"); return; }

            if (parts[0].equalsIgnoreCase("CONNECT")) {
                String[] hp = splitHostPort(parts[1], 443);
                Socket upstream;
                try {
                    upstream = openSocket(hp[0], Integer.parseInt(hp[1]));
                } catch (IOException | NumberFormatException e) { reply(client, 502, "Bad Gateway: " + e.getMessage()); return; }
                try (upstream) {
                    client.getOutputStream().write("HTTP/1.1 200 Connection Established\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
                    client.getOutputStream().flush();
                    pipe(client, upstream);
                }
                return;
            }

            java.net.URI uri;
            try { uri = java.net.URI.create(parts[1]); } catch (IllegalArgumentException e) { reply(client, 400, "Bad Request"); return; }
            if (uri.getHost() == null || !"http".equalsIgnoreCase(uri.getScheme())) { reply(client, 400, "Only absolute http:// URIs or CONNECT are supported"); return; }
            int port = uri.getPort() > 0 ? uri.getPort() : 80;
            Socket upstream;
            try { upstream = openSocket(uri.getHost(), port); }
            catch (IOException e) { reply(client, 502, "Bad Gateway: " + e.getMessage()); return; }
            try (upstream) {
                String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
                if (uri.getRawQuery() != null) path += "?" + uri.getRawQuery();
                StringBuilder req = new StringBuilder(parts[0]).append(' ').append(path).append(" HTTP/1.1\r\n");
                boolean hasHost = false;
                for (String h : headers) {
                    String lower = h.toLowerCase(java.util.Locale.ROOT);
                    if (lower.startsWith("proxy-") || lower.startsWith("connection:") || lower.startsWith("keep-alive:")) continue;
                    if (lower.startsWith("host:")) hasHost = true;
                    req.append(h).append("\r\n");
                }
                if (!hasHost) req.append("Host: ").append(uri.getHost()).append(port == 80 ? "" : ":" + port).append("\r\n");
                req.append("Connection: close\r\n\r\n");
                OutputStream uo = upstream.getOutputStream();
                uo.write(req.toString().getBytes(StandardCharsets.ISO_8859_1));
                uo.flush();
                pipe(client, upstream); // body (if any) flows client->upstream, response flows back until upstream closes
            }
        } catch (IOException ignored) {
            // client went away or tunnel ended
        }
    }

    /** True when no authentication is configured or a header carries the expected Basic credentials. */
    private boolean authorized(java.util.List<String> headers) {
        if (expectedCredentials == null) return true;
        for (String h : headers) {
            int colon = h.indexOf(':');
            if (colon <= 0 || !h.substring(0, colon).trim().equalsIgnoreCase("proxy-authorization")) continue;
            String value = h.substring(colon + 1).trim();
            int space = value.indexOf(' ');
            if (space > 0 && value.substring(0, space).equalsIgnoreCase("Basic")
                    && MessageDigest.isEqual(value.substring(space + 1).trim().getBytes(StandardCharsets.ISO_8859_1), expectedCredentials)) {
                return true;
            }
        }
        return false;
    }

    private Socket openSocket(String host, int port) throws IOException {
        Socket s = new TailnetSocket(dialer);
        s.connect(java.net.InetSocketAddress.createUnresolved(host, port), 15_000);
        return s;
    }

    private static String[] splitHostPort(String hp, int defPort) {
        int i = hp.lastIndexOf(':');
        if (i > 0 && !hp.endsWith("]")) return new String[]{hp.substring(0, i).replaceAll("^\\[|\\]$", ""), hp.substring(i + 1)};
        return new String[]{hp.replaceAll("^\\[|\\]$", ""), Integer.toString(defPort)};
    }

    /** Copies both directions until either side closes. */
    private void pipe(Socket a, Socket b) throws IOException {
        Thread t = Thread.ofVirtual().start(() -> {
            try { a.getInputStream().transferTo(b.getOutputStream()); b.shutdownOutput(); } catch (IOException ignored) { }
        });
        try { b.getInputStream().transferTo(a.getOutputStream()); a.getOutputStream().flush(); } catch (IOException ignored) { }
        try { a.shutdownOutput(); } catch (IOException ignored) { }
        try { t.join(5000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    /**
     * Sends a plain-text error response.
     *
     * @param extraHeaders complete header lines (without CRLF) to add, e.g. {@code Proxy-Authenticate: ...}
     */
    private static void reply(Socket c, int code, String msg, String... extraHeaders) throws IOException {
        byte[] body = (msg + "\n").getBytes(StandardCharsets.UTF_8);
        StringBuilder head = new StringBuilder("HTTP/1.1 ").append(code).append(' ').append(msg.split(":")[0])
                .append("\r\nContent-Type: text/plain\r\nContent-Length: ").append(body.length);
        for (String h : extraHeaders) head.append("\r\n").append(h);
        head.append("\r\nConnection: close\r\n\r\n");
        c.getOutputStream().write(head.toString().getBytes(StandardCharsets.US_ASCII));
        c.getOutputStream().write(body);
        c.getOutputStream().flush();
    }

    /**
     * After an oversized request, half-closes our side and discards a bounded amount of what the client is still
     * sending, so closing does not turn into a connection reset that hides the 431 from the client.
     */
    private static void drain(Socket c) {
        try {
            c.shutdownOutput();
            c.setSoTimeout(1000);
            InputStream in = c.getInputStream();
            byte[] buf = new byte[4096];
            int total = 0;
            for (int n; total < DRAIN_LIMIT && (n = in.read(buf)) >= 0; ) total += n;
        } catch (IOException ignored) {
            // client went away or stopped sending
        }
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) >= 0) {
            if (c == '\n') break;
            if (c != '\r') b.write(c);
            if (b.size() > MAX_LINE_BYTES) throw new HeaderTooLarge("header line longer than " + MAX_LINE_BYTES + " bytes");
        }
        if (c < 0 && b.size() == 0) return null;
        return b.toString(StandardCharsets.ISO_8859_1);
    }

    /** Stops the proxy and closes its listening socket. Connections already being relayed end with it. */
    @Override public void close() {
        closed = true;
        try { server.close(); } catch (IOException ignored) { }
        pool.shutdownNow();
    }
}
