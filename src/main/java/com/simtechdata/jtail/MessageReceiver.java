package com.simtechdata.jtail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Duration;

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
        try (ServerSocket server = tailnet.listen(port)) {
            if (timeout != null) server.setSoTimeout(remainingMillis(deadline, port));
            try (Socket client = server.accept()) {
                InputStream in = client.getInputStream();
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                while (true) {
                    if (timeout != null) client.setSoTimeout(remainingMillis(deadline, port));
                    int n = in.read(buf);
                    if (n < 0) return out.toByteArray();
                    if (out.size() + n > MAX_MESSAGE_BYTES) throw new IOException("message exceeds " + MAX_MESSAGE_BYTES + " bytes");
                    out.write(buf, 0, n);
                }
            }
        }
    }

    private static int remainingMillis(long deadlineNanos, int port) throws SocketTimeoutException {
        long left = (deadlineNanos - System.nanoTime()) / 1_000_000L;
        if (left <= 0) throw new SocketTimeoutException("timed out waiting for a message on port " + port);
        return (int) Math.min(left, Integer.MAX_VALUE);
    }
}
