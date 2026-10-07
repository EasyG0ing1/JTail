package com.simtechdata.jtail.netstack;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * A UDP socket on the tailnet address, obtained from {@link com.simtechdata.jtail.Tailnet#openUdp(int)}.
 *
 * <p>UDP sends independent messages (datagrams) without a connection; delivery and ordering are not guaranteed. A
 * datagram must fit in the tailnet MTU (1280 bytes, about 1,250 bytes of payload for IPv4).
 *
 * <pre>{@code
 * try (UdpSocket udp = net.openUdp(0)) {
 *     udp.send(net.resolve("peer").getAddress(), 7004, "ping".getBytes());
 *     UdpSocket.Datagram reply = udp.receive(5000);
 * }
 * }</pre>
 */
public final class UdpSocket implements AutoCloseable {
    /**
     * A received datagram.
     *
     * @param srcIp   the sender's address as 4 (IPv4) or 16 (IPv6) bytes; pass it back to {@link #send} to reply
     * @param srcPort the sender's UDP port
     * @param data    the message payload
     */
    public record Datagram(byte[] srcIp, int srcPort, byte[] data) {}

    private final Netstack stack;
    private final int port;
    private final BlockingQueue<Datagram> queue = new ArrayBlockingQueue<>(1024);
    private volatile boolean closed;

    UdpSocket(Netstack stack, int port) { this.stack = stack; this.port = port; }

    /** @return the local UDP port this socket is bound to */
    public int port() { return port; }

    void enqueue(Datagram d) { if (!closed) queue.offer(d); } // drop on overflow like a full socket buffer

    /**
     * Sends one datagram.
     *
     * @param dstIp   the destination address as 4 (IPv4) or 16 (IPv6) bytes, for example from
     *                {@code tailnet.resolve(name).getAddress()}
     * @param dstPort the destination UDP port
     * @param data    the payload; must fit in the tailnet MTU
     * @throws IOException if the socket is closed, the payload is too large, or no local address matches the
     *                     destination's address family
     */
    public void send(byte[] dstIp, int dstPort, byte[] data) throws IOException {
        if (closed) throw new java.net.SocketException("socket closed");
        stack.sendUdp(port, dstIp, dstPort, data);
    }

    /**
     * Waits for the next datagram.
     *
     * @param timeoutMs how long to wait in milliseconds; zero or negative waits forever
     * @return the received datagram
     * @throws java.net.SocketTimeoutException if no datagram arrives within the timeout
     * @throws java.net.SocketException        if the socket is closed
     * @throws java.io.InterruptedIOException  if the waiting thread is interrupted
     */
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

    /** Closes the socket and frees its port. Pending and later {@link #receive} calls fail. */
    @Override public void close() {
        closed = true;
        stack.removeUdp(this);
    }
}
