package com.simtechdata.jtail.testutil;

import com.simtechdata.jtail.net.TailnetDialer;
import com.simtechdata.jtail.net.TailnetServerSocket;
import com.simtechdata.jtail.netstack.Netstack;
import com.simtechdata.jtail.netstack.TcpConn;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

/**
 * Two userspace TCP/IP stacks wired back to back in memory: node "a" (100.64.0.1) and node "b" (100.64.0.2). Gives
 * tests real {@link TcpConn}s, sockets and listeners without WireGuard, a control server or the host network.
 */
public final class NetstackPair implements AutoCloseable {
    public static final byte[] IP_A = {100, 64, 0, 1}, IP_B = {100, 64, 0, 2};

    public final Netstack a, b;
    private final ExecutorService toB = wire(), toA = wire();

    public NetstackPair() {
        Netstack[] peer = new Netstack[2];
        a = new Netstack(List.of(IP_A), p -> carry(toB, peer, 1, p), Netstack.DEFAULT_MTU);
        b = new Netstack(List.of(IP_B), p -> carry(toA, peer, 0, p), Netstack.DEFAULT_MTU);
        peer[0] = a;
        peer[1] = b;
    }

    private static ExecutorService wire() {
        return Executors.newSingleThreadExecutor(r -> { Thread t = new Thread(r, "netstack-pair-wire"); t.setDaemon(true); return t; });
    }

    private static void carry(ExecutorService wire, Netstack[] peer, int to, byte[] packet) {
        byte[] copy = packet.clone();
        try { wire.execute(() -> peer[to].deliver(copy)); } catch (RejectedExecutionException closed) { /* link is down */ }
    }

    public static InetAddress inet(byte[] ip) {
        try { return InetAddress.getByAddress(ip); } catch (UnknownHostException e) { throw new IllegalArgumentException(e); }
    }

    /** Dials from node a; resolves the names "b" and "100.64.0.2" and nothing else. */
    public TailnetDialer dialerFromA() {
        return (host, port, timeoutMillis) -> {
            if (!host.equals("b") && !host.equals("100.64.0.2")) throw new UnknownHostException(host + ": not in the test tailnet");
            TcpConn c = a.dialTcp(IP_B, port, timeoutMillis);
            return new TailnetDialer.Dialed(c, new InetSocketAddress(inet(c.localAddress()), c.localPort()),
                    new InetSocketAddress(inet(c.remoteAddress()), c.remotePort()));
        };
    }

    /** Listens on node b, the way {@code Tailnet.listen} does. */
    public TailnetServerSocket listenOnB(int port) throws IOException {
        return new TailnetServerSocket(b.listenTcp(port), inet(IP_B),
                c -> new InetSocketAddress(inet(c.remoteAddress()), c.remotePort()));
    }

    @Override public void close() {
        a.close();
        b.close();
        toA.shutdownNow();
        toB.shutdownNow();
    }
}
