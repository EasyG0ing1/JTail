package com.simtechdata.jtail.netstack;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/** A listening TCP port on the tailnet address. */
public final class TcpListener implements AutoCloseable {
    private static final int BACKLOG = 128;
    private final Netstack stack;
    private final int port;
    private final BlockingQueue<TcpConn> accepted = new ArrayBlockingQueue<>(BACKLOG);
    private volatile boolean closed;
    private static final TcpConn POISON = null;

    TcpListener(Netstack stack, int port) { this.stack = stack; this.port = port; }

    public int port() { return port; }
    boolean isClosed() { return closed; }
    boolean full() { return accepted.remainingCapacity() == 0; }
    boolean offer(TcpConn c) { return !closed && accepted.offer(c); }

    /** Waits for the next established connection; {@code timeoutMs <= 0} waits forever. */
    public TcpConn accept(long timeoutMs) throws IOException {
        try {
            while (true) {
                if (closed) throw new java.net.SocketException("listener closed");
                TcpConn c = accepted.poll(timeoutMs <= 0 ? 500 : timeoutMs, TimeUnit.MILLISECONDS);
                if (c != null) return c;
                if (timeoutMs > 0) throw new SocketTimeoutException("accept timed out");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new java.io.InterruptedIOException("accept interrupted");
        }
    }

    @Override public void close() {
        closed = true;
        stack.removeListener(this);
        TcpConn c;
        while ((c = accepted.poll()) != null) c.abort();
    }
}
