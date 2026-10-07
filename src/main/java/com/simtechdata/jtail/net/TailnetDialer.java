package com.simtechdata.jtail.net;

import com.simtechdata.jtail.netstack.TcpConn;
import java.io.IOException;
import java.net.InetSocketAddress;

/** Opens tailnet TCP connections on behalf of {@link TailnetSocket} (implemented by the node runtime). */
@FunctionalInterface
public interface TailnetDialer {
    /** An established connection with its endpoints. */
    record Dialed(TcpConn conn, InetSocketAddress local, InetSocketAddress remote) {}

    Dialed dial(String host, int port, int timeoutMillis) throws IOException;
}
