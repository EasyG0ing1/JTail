package com.simtechdata.jtail.net;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;

/** Opens TCP connections to the control and DERP servers, honouring the JVM's HTTP proxy settings (CONNECT tunnels). */
public final class Outbound {
    private Outbound() {}

    /**
     * Connects to {@code port} on {@code directHost} (or, when a proxy applies, asks the proxy to tunnel to
     * {@code proxiedHost} so DNS and policy decisions happen there).
     *
     * @param selectorUri URI the proxy selector is consulted about (scheme https for TLS-bound destinations)
     */
    public static Socket connect(String directHost, String proxiedHost, int port, URI selectorUri, int timeoutMs) throws IOException {
        Proxy proxy = Proxy.NO_PROXY;
        try {
            List<Proxy> ps = ProxySelector.getDefault().select(selectorUri);
            if (ps != null && !ps.isEmpty()) proxy = ps.get(0);
        } catch (RuntimeException ignored) { }
        Socket s = new Socket();
        try {
            if (proxy.type() == Proxy.Type.HTTP && proxy.address() instanceof InetSocketAddress pa) {
                s.connect(new InetSocketAddress(pa.getHostString(), pa.getPort()), timeoutMs);
                OutputStream o = s.getOutputStream();
                String target = proxiedHost + ":" + port;
                o.write(("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                o.flush();
                InputStream i = s.getInputStream();
                String status = readLine(i);
                while (!readLine(i).isEmpty()) { /* skip proxy response headers */ }
                if (!status.contains(" 200")) throw new IOException("proxy CONNECT to " + target + " failed: " + status);
            } else {
                s.connect(new InetSocketAddress(directHost, port), timeoutMs);
            }
            s.setTcpNoDelay(true);
            return s;
        } catch (IOException | RuntimeException e) {
            try { s.close(); } catch (IOException ignored) { }
            throw e;
        }
    }

    /** Reads one CRLF-terminated line without buffering past it. */
    public static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) >= 0) {
            if (c == '\n') break;
            if (c != '\r') b.write(c);
            if (b.size() > 16384) throw new IOException("HTTP header line too long");
        }
        if (c < 0 && b.size() == 0) throw new EOFException("connection closed while reading HTTP headers");
        return b.toString(StandardCharsets.ISO_8859_1);
    }
}
