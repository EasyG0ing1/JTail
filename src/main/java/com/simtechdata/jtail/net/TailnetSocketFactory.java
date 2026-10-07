package com.simtechdata.jtail.net;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import javax.net.SocketFactory;

/**
 * A {@link SocketFactory} whose sockets live on the tailnet, so libraries that accept a {@code SocketFactory} (JDBC
 * drivers, Apache HttpClient, OkHttp, JavaMail, ...) can reach tailnet hosts without knowing about JTail.
 */
public final class TailnetSocketFactory extends SocketFactory {
    private final TailnetDialer dialer;

    /**
     * @param dialer opens tailnet connections; applications normally use {@link com.simtechdata.jtail.Tailnet#socketFactory()}
     */
    public TailnetSocketFactory(TailnetDialer dialer) { this.dialer = dialer; }

    /**
     * Creates an unconnected socket; connect it with {@link Socket#connect(java.net.SocketAddress, int)}, passing host
     * names via {@link InetSocketAddress#createUnresolved(String, int)} so they resolve inside the tailnet.
     */
    @Override public Socket createSocket() { return new TailnetSocket(dialer); }

    /**
     * Creates a socket connected to a tailnet node by name or address.
     *
     * @throws java.net.UnknownHostException if the name is not in the tailnet
     * @throws IOException                   if the connection fails
     */
    @Override public Socket createSocket(String host, int port) throws IOException {
        Socket s = new TailnetSocket(dialer);
        s.connect(InetSocketAddress.createUnresolved(host, port));
        return s;
    }

    @Override public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        return createSocket(host, port);
    }

    @Override public Socket createSocket(InetAddress host, int port) throws IOException {
        Socket s = new TailnetSocket(dialer);
        s.connect(new InetSocketAddress(host, port));
        return s;
    }

    @Override public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return createSocket(address, port);
    }
}
