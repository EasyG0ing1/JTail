package com.simtechdata.jtail.net;

import com.simtechdata.jtail.netstack.TcpConn;
import com.simtechdata.jtail.netstack.TcpListener;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.ServerSocketChannel;

/** A {@link ServerSocket} that accepts connections arriving over the tailnet. */
public final class TailnetServerSocket extends ServerSocket {
    private final TcpListener listener;
    private final InetAddress localAddr;
    private final java.util.function.Function<TcpConn, InetSocketAddress> remoteOf;
    private volatile boolean closed;
    private volatile int soTimeout;

    public TailnetServerSocket(TcpListener listener, InetAddress localAddr,
                               java.util.function.Function<TcpConn, InetSocketAddress> remoteOf) throws IOException {
        super();
        this.listener = listener;
        this.localAddr = localAddr;
        this.remoteOf = remoteOf;
    }

    @Override public Socket accept() throws IOException {
        if (closed) throw new SocketException("Socket is closed");
        TcpConn c = listener.accept(soTimeout);
        InetSocketAddress remote = remoteOf.apply(c);
        return new TailnetSocket(c, new InetSocketAddress(localAddr, listener.port()), remote);
    }

    @Override public void bind(SocketAddress endpoint) throws IOException { throw new SocketException("already bound"); }
    @Override public void bind(SocketAddress endpoint, int backlog) throws IOException { throw new SocketException("already bound"); }
    @Override public void close() { closed = true; listener.close(); }
    @Override public boolean isClosed() { return closed; }
    @Override public boolean isBound() { return true; }
    @Override public int getLocalPort() { return listener.port(); }
    @Override public InetAddress getInetAddress() { return localAddr; }
    @Override public SocketAddress getLocalSocketAddress() { return new InetSocketAddress(localAddr, listener.port()); }
    @Override public void setSoTimeout(int timeout) throws SocketException { soTimeout = timeout; }
    @Override public int getSoTimeout() { return soTimeout; }
    @Override public void setReuseAddress(boolean on) { }
    @Override public boolean getReuseAddress() { return false; }
    @Override public ServerSocketChannel getChannel() { return null; }
    @Override public String toString() { return "TailnetServerSocket[addr=" + localAddr + ",port=" + listener.port() + "]"; }
}
