package com.simtechdata.jtail.net;

import com.simtechdata.jtail.netstack.TcpConn;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketOption;
import java.net.StandardSocketOptions;
import java.nio.channels.SocketChannel;
import java.util.Set;

/**
 * A {@link Socket} whose bytes travel over a JTail userspace TCP connection instead of the host network stack.
 * Every method that would touch the platform socket is overridden; it is safe to wrap in {@code SSLSocket}.
 */
public final class TailnetSocket extends Socket {
    private final TcpConn conn;
    private final InetSocketAddress remote, local;
    private volatile int soTimeout;
    private volatile boolean closed, inShut, outShut;
    private boolean noDelay = true, keepAlive;

    public TailnetSocket(TcpConn conn, InetSocketAddress local, InetSocketAddress remote) {
        super();
        this.conn = conn;
        this.local = local;
        this.remote = remote;
    }

    @Override public InputStream getInputStream() throws IOException {
        if (closed) throw new SocketException("Socket is closed");
        if (inShut) throw new SocketException("Socket input is shutdown");
        return new InputStream() {
            @Override public int read() throws IOException {
                byte[] one = new byte[1];
                int n = read(one, 0, 1);
                return n < 0 ? -1 : one[0] & 0xFF;
            }

            @Override public int read(byte[] b, int off, int len) throws IOException {
                if (closed) throw new SocketException("Socket closed");
                java.util.Objects.checkFromIndexSize(off, len, b.length);
                return conn.read(b, off, len, soTimeout);
            }

            @Override public int available() { return conn.available(); }
            @Override public void close() { TailnetSocket.this.closeQuietly(); }
        };
    }

    @Override public OutputStream getOutputStream() throws IOException {
        if (closed) throw new SocketException("Socket is closed");
        if (outShut) throw new SocketException("Socket output is shutdown");
        return new OutputStream() {
            @Override public void write(int b) throws IOException { write(new byte[]{(byte) b}, 0, 1); }

            @Override public void write(byte[] b, int off, int len) throws IOException {
                if (closed) throw new SocketException("Socket closed");
                java.util.Objects.checkFromIndexSize(off, len, b.length);
                conn.write(b, off, len);
            }

            @Override public void close() { TailnetSocket.this.closeQuietly(); }
        };
    }

    private void closeQuietly() { try { close(); } catch (IOException ignored) { } }

    @Override public synchronized void close() throws IOException {
        if (closed) return;
        closed = true;
        conn.close();
    }

    @Override public void shutdownInput() { inShut = true; conn.shutdownInput(); }
    @Override public void shutdownOutput() { outShut = true; conn.shutdownOutput(); }

    @Override public void connect(SocketAddress endpoint) throws IOException { throw new SocketException("already connected"); }
    @Override public void connect(SocketAddress endpoint, int timeout) throws IOException { throw new SocketException("already connected"); }
    @Override public void bind(SocketAddress bindpoint) throws IOException { throw new SocketException("already bound"); }

    @Override public boolean isConnected() { return true; }
    @Override public boolean isBound() { return true; }
    @Override public boolean isClosed() { return closed; }
    @Override public boolean isInputShutdown() { return inShut; }
    @Override public boolean isOutputShutdown() { return outShut; }

    @Override public InetAddress getInetAddress() { return remote.getAddress(); }
    @Override public InetAddress getLocalAddress() { return local.getAddress(); }
    @Override public int getPort() { return remote.getPort(); }
    @Override public int getLocalPort() { return local.getPort(); }
    @Override public SocketAddress getRemoteSocketAddress() { return remote; }
    @Override public SocketAddress getLocalSocketAddress() { return local; }
    @Override public SocketChannel getChannel() { return null; }

    @Override public void setSoTimeout(int timeout) throws SocketException {
        if (timeout < 0) throw new IllegalArgumentException("timeout < 0");
        soTimeout = timeout;
    }
    @Override public int getSoTimeout() { return soTimeout; }
    @Override public void setTcpNoDelay(boolean on) { noDelay = on; }
    @Override public boolean getTcpNoDelay() { return noDelay; }
    @Override public void setKeepAlive(boolean on) { keepAlive = on; conn.setKeepAlive(on); }
    @Override public boolean getKeepAlive() { return keepAlive; }
    @Override public void setSoLinger(boolean on, int linger) { }
    @Override public int getSoLinger() { return -1; }
    @Override public void setOOBInline(boolean on) { }
    @Override public boolean getOOBInline() { return false; }
    @Override public void setSendBufferSize(int size) { }
    @Override public int getSendBufferSize() { return 512 * 1024; }
    @Override public void setReceiveBufferSize(int size) { }
    @Override public int getReceiveBufferSize() { return 256 * 1024; }
    @Override public void setReuseAddress(boolean on) { }
    @Override public boolean getReuseAddress() { return false; }
    @Override public void setTrafficClass(int tc) { }
    @Override public int getTrafficClass() { return 0; }
    @Override public void sendUrgentData(int data) throws IOException { throw new SocketException("urgent data not supported"); }
    @Override public void setPerformancePreferences(int a, int b, int c) { }

    @Override public <T> Socket setOption(SocketOption<T> name, T value) throws IOException {
        if (name == StandardSocketOptions.SO_KEEPALIVE) setKeepAlive((Boolean) value);
        else if (name == StandardSocketOptions.TCP_NODELAY) noDelay = (Boolean) value;
        return this;
    }

    @SuppressWarnings("unchecked")
    @Override public <T> T getOption(SocketOption<T> name) throws IOException {
        if (name == StandardSocketOptions.SO_KEEPALIVE) return (T) Boolean.valueOf(keepAlive);
        if (name == StandardSocketOptions.TCP_NODELAY) return (T) Boolean.valueOf(noDelay);
        return null;
    }

    @Override public Set<SocketOption<?>> supportedOptions() {
        return Set.of(StandardSocketOptions.SO_KEEPALIVE, StandardSocketOptions.TCP_NODELAY);
    }

    @Override public String toString() {
        return "TailnetSocket[addr=" + remote.getAddress() + ",port=" + remote.getPort() + ",localport=" + local.getPort() + "]";
    }
}
