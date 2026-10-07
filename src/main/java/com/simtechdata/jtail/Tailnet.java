package com.simtechdata.jtail;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;

/**
 * A live membership in a tailnet. Obtained from {@link JTail}. All traffic flows through JTail's userspace
 * WireGuard/TCP stack; no TUN device, no native code, no external tailscaled.
 */
public interface Tailnet extends AutoCloseable {
    /** This node's Tailscale IPv4 address (100.x.y.z). */
    InetAddress address();

    /** This node's name inside the tailnet (e.g. {@code worker-1.tail1234.ts.net}). */
    String name();

    /** Snapshot of the other nodes currently visible to this node. */
    List<Peer> peers();

    /** Opens a TCP connection to {@code host} (a peer name, short hostname, or tailnet IP) on {@code port}. */
    Socket dial(String host, int port) throws IOException;

    /** Accepts TCP connections arriving on this node's tailnet address at {@code port}. */
    ServerSocket listen(int port) throws IOException;

    /** Round-trip time in milliseconds of an ICMP echo to {@code host}; throws on timeout. */
    long ping(String host, int timeoutMillis) throws IOException;

    /** Opens a UDP socket on this node's tailnet address ({@code port} 0 picks a free one). */
    com.simtechdata.jtail.netstack.UdpSocket openUdp(int port) throws IOException;

    /** Resolves a peer name, short hostname, or IP literal to its tailnet address (MagicDNS semantics). */
    InetAddress resolve(String host) throws IOException;

    /** True if traffic to {@code host} currently flows over a direct UDP path rather than a DERP relay. */
    boolean isDirect(String host);

    /** Leaves the tailnet and releases all resources. Ephemeral nodes are removed from the tailnet by the server. */
    @Override
    void close();
}
