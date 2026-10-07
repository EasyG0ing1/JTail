package com.simtechdata.jtail;

import java.net.InetAddress;
import java.util.List;

/**
 * Another node in the tailnet, as last reported by the control server.
 *
 * @param name      fully qualified MagicDNS name without the trailing dot, e.g. {@code db.tail1234.ts.net}
 * @param hostname  the hostname the node reported about itself
 * @param addresses the node's tailnet addresses (IPv4 and IPv6)
 * @param online    whether the control server currently considers the node online
 * @param tags      ACL tags applied to the node, e.g. {@code tag:worker}
 */
public record Peer(String name, String hostname, List<InetAddress> addresses, boolean online, List<String> tags) {}
