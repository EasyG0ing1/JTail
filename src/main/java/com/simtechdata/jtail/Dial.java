package com.simtechdata.jtail;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;

/**
 * A fluent, one-shot "send this message to that node" request.
 *
 * <p>This is deliberately <em>not</em> named a builder: a builder only collects settings and hands back an object,
 * whereas the final call here, {@link #send()}, performs the work. It opens a TCP connection, writes the payload, and
 * closes the connection.
 *
 * <p>Create one with {@link Tailnet#dial()}:
 * <pre>{@code
 * net.dial()
 *    .to("database")                      // a peer name, an address, or a Peer
 *    .port(7000)
 *    .timeout(Duration.ofSeconds(5))
 *    .payload("hello")                    // a String (UTF-8) or a byte[]
 *    .send();
 * }</pre>
 *
 * <p>Instances are <strong>immutable</strong>: every setter returns a new {@code Dial} and leaves the original
 * untouched, so a partly configured request can be reused and shared between threads:
 * <pre>{@code
 * Dial toDb = net.dial().to("database").port(7000);
 * toDb.payload("first").send();
 * toDb.payload("second").send();
 * }</pre>
 *
 * <p>The receiving side can collect the message with {@link Tailnet#waitForString(int)} or
 * {@link Tailnet#waitForByteArray(int)}, or with an ordinary {@code ServerSocket} from {@link Tailnet#listen(int)}.
 * Closing the connection is what marks the end of the message, and the receiver must already be listening when
 * {@code send()} connects, so start the receiver first.
 *
 * <p>To keep a connection open or to read a reply, use {@link Tailnet#dial(String, int)}, which returns a
 * {@link Socket}.
 *
 * @see Tailnet#dial()
 * @see Tailnet#waitForString(int)
 */
public final class Dial {
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    private final Tailnet tailnet;
    private final String host;
    private final int port;
    private final Duration timeout;
    private final byte[] payload;

    /** Creates an empty request; use {@link Tailnet#dial()}. */
    Dial(Tailnet tailnet) {
        this(Objects.requireNonNull(tailnet, "tailnet"), null, -1, DEFAULT_TIMEOUT, null);
    }

    private Dial(Tailnet tailnet, String host, int port, Duration timeout, byte[] payload) {
        this.tailnet = tailnet;
        this.host = host;
        this.port = port;
        this.timeout = timeout;
        this.payload = payload;
    }

    /**
     * Returns a request addressed to a peer. Its first IPv4 tailnet address is used, or its first address if it has no
     * IPv4 address.
     *
     * @param peer a node from {@link Tailnet#peers()}
     * @return a new request with the destination set
     * @throws NullPointerException     if {@code peer} is {@code null}
     * @throws IllegalArgumentException if the peer has no addresses
     */
    public Dial to(Peer peer) {
        Objects.requireNonNull(peer, "peer");
        if (peer.addresses().isEmpty()) throw new IllegalArgumentException("peer has no addresses: " + peer.name());
        InetAddress chosen = peer.addresses().stream().filter(a -> a instanceof Inet4Address).findFirst()
                .orElse(peer.addresses().get(0));
        return new Dial(tailnet, chosen.getHostAddress(), port, timeout, payload);
    }

    /**
     * Returns a request addressed to a host.
     *
     * @param host a peer's short or fully qualified name, an IPv4 or IPv6 address, or a name resolvable through the
     *             tailnet's DNS configuration (see {@link Tailnet#resolve(String)})
     * @return a new request with the destination set
     * @throws NullPointerException     if {@code host} is {@code null}
     * @throws IllegalArgumentException if {@code host} is blank
     */
    public Dial to(String host) {
        Objects.requireNonNull(host, "host");
        if (host.isBlank()) throw new IllegalArgumentException("host must not be blank");
        return new Dial(tailnet, host, port, timeout, payload);
    }

    /**
     * Returns a request with the destination TCP port set.
     *
     * @param port the port, 1 to 65535
     * @return a new request
     * @throws IllegalArgumentException if the port is out of range
     */
    public Dial port(int port) {
        if (port < 1 || port > 65535) throw new IllegalArgumentException("port out of range: " + port);
        return new Dial(tailnet, host, port, timeout, payload);
    }

    /**
     * Returns a request with a timeout. It bounds both establishing the connection and each blocking write. The default
     * is 30 seconds.
     *
     * @param timeout a positive duration, at most {@link Integer#MAX_VALUE} milliseconds
     * @return a new request
     * @throws NullPointerException     if {@code timeout} is {@code null}
     * @throws IllegalArgumentException if the duration is zero, negative, or too long
     */
    public Dial timeout(Duration timeout) {
        Objects.requireNonNull(timeout, "timeout");
        if (timeout.isZero() || timeout.isNegative()) throw new IllegalArgumentException("timeout must be positive: " + timeout);
        if (timeout.compareTo(Duration.ofMillis(Integer.MAX_VALUE)) > 0) throw new IllegalArgumentException("timeout too long: " + timeout);
        return new Dial(tailnet, host, port, timeout, payload);
    }

    /**
     * Returns a request with the message to send, encoded as UTF-8.
     *
     * @param text the message; may be empty
     * @return a new request
     * @throws NullPointerException if {@code text} is {@code null}
     */
    public Dial payload(String text) {
        Objects.requireNonNull(text, "text");
        return new Dial(tailnet, host, port, timeout, text.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Returns a request with the message to send as raw bytes. The array is copied, so later changes to it do not
     * affect this request.
     *
     * @param bytes the message; may be empty
     * @return a new request
     * @throws NullPointerException if {@code bytes} is {@code null}
     */
    public Dial payload(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes");
        return new Dial(tailnet, host, port, timeout, bytes.clone());
    }

    /**
     * Opens a TCP connection to the destination, writes the payload, and closes the connection. The close is graceful:
     * the payload is delivered before the connection ends, which is how a receiver ({@code waitFor...}) knows the message
     * is complete. Each call makes a fresh connection, so the same request can be sent repeatedly.
     *
     * @throws IllegalStateException           if the destination, port or payload has not been set
     * @throws java.net.UnknownHostException   if the destination cannot be resolved inside the tailnet
     * @throws java.net.NoRouteToHostException if there is no route to the destination
     * @throws java.net.SocketTimeoutException if the connection or a write does not complete within the timeout
     * @throws java.net.SocketException        if the connection is refused (nothing is listening) or reset
     * @throws IOException                     for any other I/O failure
     */
    public void send() throws IOException {
        if (host == null) throw new IllegalStateException("destination not set: call to(...)");
        if (port < 0) throw new IllegalStateException("port not set: call port(...)");
        if (payload == null) throw new IllegalStateException("payload not set: call payload(...)");
        int millis = (int) timeout.toMillis();
        try (Socket socket = tailnet.dial(host, port, millis)) {
            socket.setSoTimeout(millis);
            OutputStream out = socket.getOutputStream();
            out.write(payload);
            out.flush();
        }
    }
}
