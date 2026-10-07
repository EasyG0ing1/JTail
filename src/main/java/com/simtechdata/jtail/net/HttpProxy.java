package com.simtechdata.jtail.net;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;

/**
 * A minimal local HTTP proxy (CONNECT tunnels plus absolute-URI GET/POST/...) that forwards through the tailnet, so
 * proxy-aware clients such as {@code java.net.http.HttpClient} can reach tailnet hosts:
 * <pre>{@code
 * HttpClient c = HttpClient.newBuilder().proxy(ProxySelector.of(new InetSocketAddress("127.0.0.1", proxy.port()))).build();
 * }</pre>
 * It listens on the loopback interface only.
 */
public final class HttpProxy implements AutoCloseable {
    private final ServerSocket server;
    private final TailnetDialer dialer;
    private final ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor();
    private volatile boolean closed;

    public HttpProxy(TailnetDialer dialer, int port) throws IOException {
        this.dialer = dialer;
        this.server = new ServerSocket(port, 50, InetAddress.getLoopbackAddress());
        Thread t = new Thread(this::acceptLoop, "jtail-http-proxy");
        t.setDaemon(true);
        t.start();
    }

    /** The loopback port the proxy listens on. */
    public int port() { return server.getLocalPort(); }

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
            String requestLine = readLine(in);
            if (requestLine == null || requestLine.isEmpty()) return;
            String[] parts = requestLine.split(" ", 3);
            if (parts.length < 3) { reply(client, 400, "Bad Request"); return; }
            java.util.List<String> headers = new java.util.ArrayList<>();
            for (String h; (h = readLine(in)) != null && !h.isEmpty(); ) headers.add(h);

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

    private static void reply(Socket c, int code, String msg) throws IOException {
        byte[] body = (msg + "\n").getBytes(StandardCharsets.UTF_8);
        c.getOutputStream().write(("HTTP/1.1 " + code + " " + msg.split(":")[0] + "\r\nContent-Type: text/plain\r\nContent-Length: " + body.length
                + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
        c.getOutputStream().write(body);
        c.getOutputStream().flush();
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) >= 0) {
            if (c == '\n') break;
            if (c != '\r') b.write(c);
            if (b.size() > 65536) throw new SocketException("header line too long");
        }
        if (c < 0 && b.size() == 0) return null;
        return b.toString(StandardCharsets.ISO_8859_1);
    }

    @Override public void close() {
        closed = true;
        try { server.close(); } catch (IOException ignored) { }
        pool.shutdownNow();
    }
}
