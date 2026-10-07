package com.simtechdata.jtail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.WeakHashMap;

/** Shared implementation of {@code Tailnet.waitFor...}: accept one connection and read it to the end. */
final class MessageReceiver {
    /** Upper bound on a received message; protects the receiver from a sender that streams without end. */
    static final int MAX_MESSAGE_BYTES = 64 * 1024 * 1024;

    private MessageReceiver() {}

    /**
     * @param timeout total time allowed for the whole operation, or {@code null} to wait forever
     */
    static byte[] receive(Tailnet tailnet, int port, Duration timeout) throws IOException {
        if (port < 1 || port > 65535) throw new IllegalArgumentException("port out of range: " + port);
        long deadline = 0;
        if (timeout != null) {
            if (timeout.isZero() || timeout.isNegative()) throw new IllegalArgumentException("timeout must be positive: " + timeout);
            deadline = System.nanoTime() + timeout.toNanos();
        }
        ServerSocket server = listener(tailnet, port);
        try {
            server.setSoTimeout(timeout == null ? 0 : remainingMillis(deadline, port));
            Trace.log("receive", "listening on tailnet port " + port + ", waiting for a connection...");
            try (Socket client = server.accept()) {
                Trace.log("receive", "connection accepted on port " + port + " from " + client.getRemoteSocketAddress());
                InputStream in = client.getInputStream();
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                while (true) {
                    if (timeout != null) client.setSoTimeout(remainingMillis(deadline, port));
                    int n = in.read(buf);
                    if (n < 0) { Trace.log("receive", "message complete: " + out.size() + " bytes on port " + port); return out.toByteArray(); }
                    if (out.size() + n > MAX_MESSAGE_BYTES) throw new IOException("message exceeds " + MAX_MESSAGE_BYTES + " bytes");
                    out.write(buf, 0, n);
                }
            }
        } catch (SocketTimeoutException e) {
            throw e;                                   // the listener stays open for the next call
        } catch (IOException e) {
            if (server.isClosed()) forget(tailnet, port);
            throw e;
        }
    }

    // One listener per (tailnet, port), kept open between calls so a sender that connects while the application is
    // busy handling the previous message is queued by the listener instead of being refused.
    private static final Map<Tailnet, Map<Integer, ServerSocket>> LISTENERS = new WeakHashMap<>();

    private static synchronized ServerSocket listener(Tailnet tailnet, int port) throws IOException {
        // drop entries of closed tailnets (their values would otherwise keep the tailnet reachable)
        LISTENERS.values().removeIf(m -> { m.values().removeIf(ServerSocket::isClosed); return m.isEmpty(); });
        Map<Integer, ServerSocket> byPort = LISTENERS.computeIfAbsent(tailnet, t -> new HashMap<>());
        ServerSocket s = byPort.get(port);
        if (s == null || s.isClosed()) {
            s = tailnet.listen(port);
            byPort.put(port, s);
        }
        return s;
    }

    private static synchronized void forget(Tailnet tailnet, int port) {
        Map<Integer, ServerSocket> byPort = LISTENERS.get(tailnet);
        if (byPort != null) byPort.remove(port);
    }

    private static int remainingMillis(long deadlineNanos, int port) throws SocketTimeoutException {
        long left = (deadlineNanos - System.nanoTime()) / 1_000_000L;
        if (left <= 0) throw new SocketTimeoutException("timed out waiting for a message on port " + port);
        return (int) Math.min(left, Integer.MAX_VALUE);
    }
}
