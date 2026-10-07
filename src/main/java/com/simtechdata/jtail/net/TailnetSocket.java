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
    private final TailnetDialer dialer;           // null for sockets created already connected
    private volatile TcpConn conn;
    private volatile InetSocketAddress remote, local;
    private volatile int soTimeout;
    private volatile boolean closed, inShut, outShut;
    private boolean noDelay = true, keepAlive;

    public TailnetSocket(TcpConn conn, InetSocketAddress local, InetSocketAddress remote) {
        super();
        this.dialer = null;
        this.conn = conn;
        this.local = local;
        this.remote = remote;
    }

    /** An unconnected socket; {@link #connect} dials through the tailnet. Used by {@link TailnetSocketFactory}. */
    public TailnetSocket(TailnetDialer dialer) {
        super();
        this.dialer = dialer;
    }

    private TcpConn requireConn() throws SocketException {
        TcpConn c = conn;
        if (c == null) throw new SocketException("Socket is not connected");
        return c;
    }

    @Override public InputStream getInputStream() throws IOException {
        if (closed) throw new SocketException("Socket is closed");
        if (inShut) throw new SocketException("Socket input is shutdown");
        requireConn();
        return new InputStream() {
            @Override public int read() throws IOException {
                byte[] one = new byte[1];
                int n = read(one, 0, 1);
                return n < 0 ? -1 : one[0] & 0xFF;
            }

            @Override public int read(byte[] b, int off, int len) throws IOException {
                if (closed) throw new SocketException("Socket closed");
                java.util.Objects.checkFromIndexSize(off, len, b.length);
                return requireConn().read(b, off, len, soTimeout);
            }

            @Override public int available() { TcpConn c = conn; return c == null ? 0 : c.available(); }
            @Override public void close() { TailnetSocket.this.closeQuietly(); }
        };
    }

    @Override public OutputStream getOutputStream() throws IOException {
        if (closed) throw new SocketException("Socket is closed");
        if (outShut) throw new SocketException("Socket output is shutdown");
        requireConn();
        return new OutputStream() {
            @Override public void write(int b) throws IOException { write(new byte[]{(byte) b}, 0, 1); }

            @Override public void write(byte[] b, int off, int len) throws IOException {
                if (closed) throw new SocketException("Socket closed");
                java.util.Objects.checkFromIndexSize(off, len, b.length);
                requireConn().write(b, off, len);
            }

            @Override public void close() { TailnetSocket.this.closeQuietly(); }
        };
    }

    private void closeQuietly() { try { close(); } catch (IOException ignored) { } }

    @Override public synchronized void close() throws IOException {
        if (closed) return;
        closed = true;
        TcpConn c = conn;
        if (c != null) c.close();
    }

    @Override public void shutdownInput() { inShut = true; TcpConn c = conn; if (c != null) c.shutdownInput(); }
    @Override public void shutdownOutput() { outShut = true; TcpConn c = conn; if (c != null) c.shutdownOutput(); }

    @Override public void connect(SocketAddress endpoint) throws IOException { connect(endpoint, 0); }

    @Override public synchronized void connect(SocketAddress endpoint, int timeout) throws IOException {
        if (closed) throw new SocketException("Socket is closed");
        if (conn != null || dialer == null) throw new SocketException("already connected");
        if (!(endpoint instanceof InetSocketAddress isa)) throw new IllegalArgumentException("unsupported address type");
        String host = isa.isUnresolved() ? isa.getHostString() : isa.getAddress().getHostAddress();
        TailnetDialer.Dialed d = dialer.dial(host, isa.getPort(), timeout > 0 ? timeout : 30_000);
        this.local = d.local();
        this.remote = d.remote();
        this.conn = d.conn();
        if (keepAlive) d.conn().setKeepAlive(true);
    }

    @Override public void bind(SocketAddress bindpoint) throws IOException {
        if (conn != null) throw new SocketException("already bound");
        // the tailnet address is chosen by the node; a requested local address is accepted and ignored
    }

    @Override public boolean isConnected() { return conn != null; }
    @Override public boolean isBound() { return conn != null; }
    @Override public boolean isClosed() { return closed; }
    @Override public boolean isInputShutdown() { return inShut; }
    @Override public boolean isOutputShutdown() { return outShut; }

    @Override public InetAddress getInetAddress() { return remote == null ? null : remote.getAddress(); }
    @Override public InetAddress getLocalAddress() { return local == null ? null : local.getAddress(); }
    @Override public int getPort() { return remote == null ? 0 : remote.getPort(); }
    @Override public int getLocalPort() { return local == null ? -1 : local.getPort(); }
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
    @Override public void setKeepAlive(boolean on) { keepAlive = on; TcpConn c = conn; if (c != null) c.setKeepAlive(on); }
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
        if (remote == null) return "TailnetSocket[unconnected]";
        return "TailnetSocket[addr=" + remote.getAddress() + ",port=" + remote.getPort() + ",localport=" + local.getPort() + "]";
    }
}
