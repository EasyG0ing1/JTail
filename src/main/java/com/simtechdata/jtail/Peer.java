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
public record Peer(String name, String hostname, List<InetAddress> addresses, boolean online, List<String> tags) {

  /**
   * Whether this peer is connected to the tailnet, according to the control server.
   *
   * <p>This is a snapshot taken when {@link Tailnet#peers()} was called; call {@code peers()} again for a fresh
   * value. It reflects the control plane's view (the peer holds an open connection to the control server). For a
   * data-path check use {@link Tailnet#ping(String, int)}.
   *
   * @return {@code true} if the peer is currently online, {@code false} if offline or its state is unknown
   */
  public boolean connected() {
    return online;
  }
}
