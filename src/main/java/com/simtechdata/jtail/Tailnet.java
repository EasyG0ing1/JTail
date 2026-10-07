package com.simtechdata.jtail;

import com.simtechdata.jtail.net.HttpProxy;
import com.simtechdata.jtail.netstack.UdpSocket;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import javax.net.SocketFactory;

/**
 * A live membership in a tailnet (a Tailscale or Headscale private network).
 *
 * <p>Obtain an instance by joining with {@link JTail#network()} (or {@link JTail#join(String)}). All traffic flows
 * through JTail's userspace WireGuard and TCP/IP implementation: no TUN device, no native code, no external
 * {@code tailscaled} process, and only your Java program joins the tailnet (other processes on the machine are
 * unaffected).
 *
 * <p>Typical use, with try-with-resources so the node leaves the tailnet when the block ends:
 * <pre>{@code
 * try (Tailnet net = JTail.network().authKey(System.getenv("TS_AUTHKEY")).hostname("worker-1").join()) {
 *     try (Socket s = net.dial("db-server", 5432)) {
 *         // use the socket like any other java.net.Socket
 *     }
 * }
 * }</pre>
 *
 * <p>Instances are thread-safe. Sockets returned by {@link #dial} and {@link #listen} follow the usual
 * {@code java.net} contracts (blocking streams, {@code setSoTimeout}, {@code shutdownOutput}) and are safe to use from
 * virtual threads.
 *
 * <p>Peer names are resolved using the tailnet's MagicDNS names, extra DNS records and split-DNS configuration; see
 * {@link #resolve(String)}. Names outside the tailnet (such as {@code example.com}) are not reachable through this API.
 *
 * @see JTail
 * @see JTailConfig
 */
public interface Tailnet extends AutoCloseable {

    /**
     * Returns this node's primary tailnet IPv4 address (in the {@code 100.64.0.0/10} range).
     *
     * @return the IPv4 address assigned to this node by the control server
     * @throws JTailException if the node has not finished joining
     * @see #addresses()
     */
    InetAddress address();

    /**
     * Returns every tailnet address of this node: normally one IPv4 address and one IPv6 address.
     *
     * @return the node's addresses, never empty once joined
     * @throws JTailException if the node has not finished joining
     */
    List<InetAddress> addresses();

    /**
     * Reports whether this instance is currently connected to its tailnet.
     *
     * <p>The value is {@code true} once the node has joined and its session with the control server is established. It
     * turns {@code false} if that session is lost (JTail reconnects in the background, after which the value returns to
     * {@code true}) and permanently {@code false} after {@link #close()}. Existing connections to peers may keep working
     * while the control server is briefly unreachable.
     *
     * <pre>{@code
     * if (net.connected()) {
     *     // safe to expect new peers and name updates
     * }
     * }</pre>
     *
     * @return {@code true} if joined, not closed, and the control session is up
     */
    boolean connected();

    /**
     * Returns this node's fully qualified name in the tailnet, without the trailing dot, for example
     * {@code worker-1.tail1234.ts.net}.
     *
     * @return the MagicDNS name, or the configured hostname if the node has not finished joining
     */
    String name();

    /**
     * Returns a snapshot of the other nodes currently visible to this node.
     *
     * <p>The list reflects the latest network map received from the control server and changes over time as nodes
     * come and go. Immediately after joining it may still be filling in; poll it if your program depends on a
     * particular peer.
     *
     * @return an unmodifiable list of peers, possibly empty
     */
    List<Peer> peers();

    /**
     * Opens a TCP connection to a node in the tailnet, waiting up to 30 seconds for it to be established.
     *
     * <p>The returned {@link Socket} is an ordinary connected socket. It can be wrapped in TLS with
     * {@link javax.net.ssl.SSLSocketFactory#createSocket(Socket, String, int, boolean)}.
     *
     * @param host the target: a peer's short name ({@code db}), its fully qualified name, an IPv4 or IPv6 address, or a
     *             name resolvable through the tailnet's DNS configuration (see {@link #resolve(String)})
     * @param port the TCP port on the target, 1 to 65535
     * @return a connected socket
     * @throws java.net.UnknownHostException   if {@code host} cannot be resolved inside the tailnet
     * @throws java.net.NoRouteToHostException if there is no route to the resolved address
     * @throws java.net.SocketTimeoutException if the connection is not established within 30 seconds
     * @throws java.net.SocketException        if the connection is refused or reset
     * @throws IOException                     for any other I/O failure, including a node that is not connected
     * @see #dial(String, int, int)
     */
    Socket dial(String host, int port) throws IOException;

    /**
     * Opens a TCP connection to a node in the tailnet with an explicit connect timeout.
     *
     * @param host                 the target; see {@link #dial(String, int)} for the accepted forms
     * @param port                 the TCP port on the target, 1 to 65535
     * @param connectTimeoutMillis the maximum time to wait for the connection to be established, in milliseconds
     * @return a connected socket
     * @throws java.net.UnknownHostException   if {@code host} cannot be resolved inside the tailnet
     * @throws java.net.NoRouteToHostException if there is no route to the resolved address
     * @throws java.net.SocketTimeoutException if the connection is not established within the timeout
     * @throws java.net.SocketException        if the connection is refused or reset
     * @throws IOException                     for any other I/O failure
     */
    Socket dial(String host, int port, int connectTimeoutMillis) throws IOException;

    /**
     * Starts listening for TCP connections arriving over the tailnet on this node's tailnet addresses.
     *
     * <p>Only tailnet nodes that the tailnet's access rules (ACLs) allow can connect. Use
     * {@link ServerSocket#setSoTimeout(int)} to bound {@code accept()}, and close the returned socket to stop listening.
     *
     * @param port the port to listen on, or {@code 0} to choose a free port (read it with
     *             {@link ServerSocket#getLocalPort()})
     * @return a server socket bound to the tailnet
     * @throws java.net.BindException if the port is already in use
     * @throws IOException            if the node is not connected
     */
    ServerSocket listen(int port) throws IOException;

    /**
     * Sends an ICMP echo request ("ping") to a node and waits for the reply.
     *
     * @param host          the target; see {@link #dial(String, int)} for the accepted forms
     * @param timeoutMillis how long to wait for the reply, in milliseconds
     * @return the round-trip time in milliseconds
     * @throws java.net.SocketTimeoutException if no reply arrives in time (the peer may be offline or its ACLs may
     *                                         block ICMP)
     * @throws java.net.UnknownHostException   if {@code host} cannot be resolved
     * @throws IOException                     for any other I/O failure
     */
    long ping(String host, int timeoutMillis) throws IOException;

    /**
     * Opens a UDP socket on this node's tailnet address, for small messages where low overhead matters more than
     * guaranteed delivery.
     *
     * <p>A datagram must fit within the tailnet MTU of 1280 bytes (about 1,250 bytes of payload for IPv4, slightly less
     * for IPv6).
     *
     * @param port the local UDP port, or {@code 0} to choose a free port (read it with {@link UdpSocket#port()})
     * @return a UDP socket; close it when finished
     * @throws java.net.BindException if the port is already in use
     * @throws IOException            if the node is not connected
     */
    UdpSocket openUdp(int port) throws IOException;

    /**
     * Resolves a name to a tailnet address.
     *
     * <p>The lookup order is: an IP address literal (returned as is); the names of peers in the tailnet (short or fully
     * qualified); extra DNS records configured for the tailnet; and finally the tailnet's split-DNS and resolver
     * configuration, queried through the tailnet itself.
     *
     * @param host a peer name, address literal, or DNS name
     * @return the resolved address
     * @throws java.net.UnknownHostException if the name is not found in the tailnet
     * @throws IOException                   for any other I/O failure
     */
    InetAddress resolve(String host) throws IOException;

    /**
     * Returns the number of TCP connections currently tracked by the userspace network stack, including connections
     * that are closing. Intended for diagnostics and leak checks.
     *
     * @return the number of tracked connections
     */
    int connectionCount();

    /**
     * Reports whether traffic to a node currently flows over a direct UDP path rather than through a DERP relay.
     *
     * <p>Traffic starts on a relay and upgrades to a direct path in the background when one can be established, so the
     * result can change a few seconds after the first traffic. It is always {@code false} when direct paths are
     * disabled with {@link JTailConfig.Builder#directPaths(boolean)}.
     *
     * @param host the node to check; see {@link #dial(String, int)} for the accepted forms
     * @return {@code true} if a verified direct path is in use; {@code false} if relayed, unknown, or unresolvable
     */
    boolean isDirect(String host);

    /**
     * Returns a {@link SocketFactory} whose sockets live on the tailnet, so libraries that accept a
     * {@code SocketFactory} (JDBC drivers, Apache HttpClient, OkHttp, JavaMail, and others) can reach tailnet hosts
     * without knowing about JTail.
     *
     * <p>Sockets from the factory may be created unconnected and connected later with
     * {@link Socket#connect(java.net.SocketAddress, int)}. Pass host names with
     * {@link java.net.InetSocketAddress#createUnresolved(String, int)} so the name is resolved by the tailnet.
     *
     * @return a socket factory bound to this tailnet
     */
    SocketFactory socketFactory();

    /**
     * Starts a local HTTP proxy that forwards through the tailnet, so proxy-aware clients such as
     * {@link java.net.http.HttpClient} can reach tailnet hosts.
     *
     * <p>The proxy listens on {@code 127.0.0.1} only and supports {@code CONNECT} tunnels and absolute-URI
     * {@code http://} requests. Requests for hosts outside the tailnet receive a {@code 502 Bad Gateway} response.
     *
     * <pre>{@code
     * try (HttpProxy proxy = net.startHttpProxy(0)) {
     *     HttpClient client = HttpClient.newBuilder()
     *             .proxy(ProxySelector.of(new InetSocketAddress("127.0.0.1", proxy.port())))
     *             .build();
     * }
     * }</pre>
     *
     * @param port the loopback port to listen on, or {@code 0} to choose a free port
     * @return the running proxy; close it when it is no longer needed
     * @throws java.net.BindException if the port is already in use
     * @throws IOException            if the proxy cannot be started
     */
    HttpProxy startHttpProxy(int port) throws IOException;

    /**
     * Leaves the tailnet and releases all resources (threads, sockets, relay connections).
     *
     * <p>Waits up to about two seconds for data you have just written to be delivered. If the node is ephemeral it is
     * logged out so the control server removes it immediately. Calling this method more than once is safe.
     */
    @Override
    void close();
}
