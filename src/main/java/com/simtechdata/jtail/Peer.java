package com.simtechdata.jtail;

import java.net.InetAddress;
import java.util.List;

/** Another node in the tailnet. */
public record Peer(String name, String hostname, List<InetAddress> addresses, boolean online, List<String> tags) {}
