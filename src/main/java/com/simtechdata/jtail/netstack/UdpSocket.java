package com.simtechdata.jtail.netstack;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/** A UDP socket on the tailnet address. */
public final class UdpSocket implements AutoCloseable {
    /** A received datagram. */
    public record Datagram(byte[] srcIp, int srcPort, byte[] data) {}

    private final Netstack stack;
    private final int port;
    private final BlockingQueue<Datagram> queue = new ArrayBlockingQueue<>(1024);
    private volatile boolean closed;

    UdpSocket(Netstack stack, int port) { this.stack = stack; this.port = port; }

    public int port() { return port; }

    void enqueue(Datagram d) { if (!closed) queue.offer(d); } // drop on overflow like a full socket buffer

    public void send(byte[] dstIp, int dstPort, byte[] data) throws IOException {
        if (closed) throw new java.net.SocketException("socket closed");
        stack.sendUdp(port, dstIp, dstPort, data);
    }

    /** Waits for a datagram; {@code timeoutMs <= 0} waits forever. */
    public Datagram receive(long timeoutMs) throws IOException {
        try {
            while (true) {
                if (closed) throw new java.net.SocketException("socket closed");
                Datagram d = queue.poll(timeoutMs <= 0 ? 500 : timeoutMs, TimeUnit.MILLISECONDS);
                if (d != null) return d;
                if (timeoutMs > 0) throw new SocketTimeoutException("receive timed out");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new java.io.InterruptedIOException("receive interrupted");
        }
    }

    @Override public void close() {
        closed = true;
        stack.removeUdp(this);
    }
}
