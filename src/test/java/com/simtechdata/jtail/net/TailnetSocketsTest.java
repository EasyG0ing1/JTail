package com.simtechdata.jtail.net;

import static org.junit.jupiter.api.Assertions.*;

import com.simtechdata.jtail.testutil.NetstackPair;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.StandardSocketOptions;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** {@link TailnetSocket}, {@link TailnetServerSocket} and {@link TailnetSocketFactory} over two in-memory stacks. */
class TailnetSocketsTest {
    final NetstackPair net = new NetstackPair();
    final ExecutorService ex = Executors.newCachedThreadPool();

    @AfterEach void tearDown() {
        ex.shutdownNow();
        net.close();
    }

    /** Accepts one connection on b, echoes everything until EOF, then closes. */
    Future<Socket> echoOnce(ServerSocket server) {
        return ex.submit(() -> {
            try (Socket s = server.accept()) {
                s.getInputStream().transferTo(s.getOutputStream());
                return s;
            }
        });
    }

    @Test @Timeout(30)
    void factorySocketReachesServerSocketAndReportsBothEnds() throws Exception {
        try (TailnetServerSocket server = net.listenOnB(7000)) {
            Future<Socket> accepted = echoOnce(server);
            byte[] msg = new byte[100_000];
            new Random(7).nextBytes(msg);
            try (Socket s = new TailnetSocketFactory(net.dialerFromA()).createSocket("b", 7000)) {
                assertTrue(s.isConnected());
                assertTrue(s.isBound());
                assertEquals("100.64.0.2", s.getInetAddress().getHostAddress());
                assertEquals(7000, s.getPort());
                assertEquals("100.64.0.1", s.getLocalAddress().getHostAddress());
                assertTrue(s.getLocalPort() > 0);
                assertTrue(s.toString().contains("port=7000"), s.toString());

                Future<byte[]> echoed = ex.submit(() -> s.getInputStream().readAllBytes());
                OutputStream out = s.getOutputStream();
                out.write(msg);
                out.flush();
                s.shutdownOutput();                 // half-close: the server sees EOF but can still answer
                assertTrue(s.isOutputShutdown());
                assertArrayEquals(msg, echoed.get(20, TimeUnit.SECONDS));

                Socket serverSide = accepted.get(5, TimeUnit.SECONDS);
                assertEquals("100.64.0.1", serverSide.getInetAddress().getHostAddress());
                assertEquals(s.getLocalPort(), serverSide.getPort());
                assertEquals(7000, serverSide.getLocalPort());
            }
        }
    }

    @Test @Timeout(30)
    void allFactoryEntryPointsConnect() throws Exception {
        TailnetSocketFactory f = new TailnetSocketFactory(net.dialerFromA());
        try (TailnetServerSocket server = net.listenOnB(7001)) {
            for (int i = 0; i < 4; i++) {
                Future<Socket> accepted = echoOnce(server);
                Socket s = switch (i) {
                    case 0 -> f.createSocket(NetstackPair.inet(NetstackPair.IP_B), 7001);
                    case 1 -> f.createSocket("b", 7001, null, 0);
                    case 2 -> f.createSocket(NetstackPair.inet(NetstackPair.IP_B), 7001, null, 0);
                    default -> {
                        Socket u = f.createSocket();
                        assertFalse(u.isConnected());
                        assertEquals("TailnetSocket[unconnected]", u.toString());
                        u.bind(new InetSocketAddress(0));               // accepted and ignored
                        u.connect(InetSocketAddress.createUnresolved("b", 7001), 5000);
                        yield u;
                    }
                };
                try (s) {
                    s.getOutputStream().write(("hi" + i).getBytes(StandardCharsets.US_ASCII));
                    s.shutdownOutput();
                    assertEquals("hi" + i, new String(s.getInputStream().readAllBytes(), StandardCharsets.US_ASCII));
                }
                accepted.get(5, TimeUnit.SECONDS);
            }
        }
    }

    @Test @Timeout(30)
    void unknownHostAndClosedPortFail() throws Exception {
        TailnetSocketFactory f = new TailnetSocketFactory(net.dialerFromA());
        assertThrows(UnknownHostException.class, () -> f.createSocket("nobody", 80));
        Socket s = f.createSocket();
        assertThrows(java.io.IOException.class, () -> s.connect(InetSocketAddress.createUnresolved("b", 9), 3000),
                "nothing listens on port 9");
        assertFalse(s.isConnected());
    }

    @Test
    void unconnectedAndClosedSocketsRefuseIo() throws Exception {
        TailnetSocket s = new TailnetSocket(net.dialerFromA());
        assertThrows(SocketException.class, s::getInputStream);
        assertThrows(SocketException.class, s::getOutputStream);
        assertNull(s.getInetAddress());
        assertEquals(0, s.getPort());
        assertEquals(-1, s.getLocalPort());
        assertThrows(IllegalArgumentException.class, () -> s.connect(new java.net.SocketAddress() { }));
        assertThrows(IllegalArgumentException.class, () -> s.setSoTimeout(-1));
        s.close();
        s.close();                                                    // idempotent
        assertTrue(s.isClosed());
        assertThrows(SocketException.class, () -> s.connect(InetSocketAddress.createUnresolved("b", 1)));
        assertThrows(SocketException.class, s::getOutputStream);
        assertThrows(SocketException.class, () -> new TailnetSocket(null, null, null).connect(InetSocketAddress.createUnresolved("b", 1)),
                "a socket created already connected cannot connect again");
    }

    @Test @Timeout(30)
    void connectedSocketCannotConnectAgainAndHonoursSoTimeout() throws Exception {
        try (TailnetServerSocket server = net.listenOnB(7002)) {
            Future<Socket> accepted = ex.submit(server::accept);
            try (Socket s = new TailnetSocketFactory(net.dialerFromA()).createSocket("b", 7002); Socket peer = accepted.get(5, TimeUnit.SECONDS)) {
                assertThrows(SocketException.class, () -> s.connect(InetSocketAddress.createUnresolved("b", 7002)));
                assertThrows(SocketException.class, () -> s.bind(null));
                s.setSoTimeout(200);
                assertEquals(200, s.getSoTimeout());
                InputStream in = s.getInputStream();
                long t0 = System.nanoTime();
                assertThrows(SocketTimeoutException.class, in::read, "nothing was sent");
                assertTrue(System.nanoTime() - t0 >= 150_000_000L, "read must wait for the timeout");
                peer.getOutputStream().write(42);
                assertEquals(42, in.read(), "the socket stays usable after a read timeout");
                assertEquals(0, in.read(new byte[4], 0, 0));
                assertThrows(IndexOutOfBoundsException.class, () -> in.read(new byte[4], 3, 2));
            }
        }
    }

    @Test @Timeout(30)
    void closingTheStreamClosesTheSocketAndInputShutdownIsReported() throws Exception {
        try (TailnetServerSocket server = net.listenOnB(7003)) {
            Future<Socket> accepted = ex.submit(server::accept);
            Socket s = new TailnetSocketFactory(net.dialerFromA()).createSocket("b", 7003);
            accepted.get(5, TimeUnit.SECONDS).close();
            s.shutdownInput();
            assertTrue(s.isInputShutdown());
            assertThrows(SocketException.class, s::getInputStream);
            s.getOutputStream().close();
            assertTrue(s.isClosed());
        }
    }

    @Test
    void socketOptionsAreAcceptedAndReported() throws Exception {
        TailnetSocket s = new TailnetSocket(net.dialerFromA());
        assertTrue(s.getTcpNoDelay(), "Nagle is off by default");
        s.setOption(StandardSocketOptions.TCP_NODELAY, false);
        assertEquals(Boolean.FALSE, s.getOption(StandardSocketOptions.TCP_NODELAY));
        s.setKeepAlive(true);
        assertEquals(Boolean.TRUE, s.getOption(StandardSocketOptions.SO_KEEPALIVE));
        assertNull(s.getOption(StandardSocketOptions.SO_RCVBUF));
        assertEquals(2, s.supportedOptions().size());
        assertNull(s.getChannel());
        assertThrows(SocketException.class, () -> s.sendUrgentData(1));
        s.setSoLinger(true, 5);          // no-ops that libraries call routinely must not throw
        s.setReceiveBufferSize(1);
        s.setSendBufferSize(1);
        s.setTrafficClass(4);
        s.setReuseAddress(true);
        s.setOOBInline(true);
        s.setPerformancePreferences(1, 2, 3);
        assertEquals(-1, s.getSoLinger());
    }

    @Test @Timeout(30)
    void serverSocketTimesOutRejectsBindAndStopsAcceptingWhenClosed() throws Exception {
        TailnetServerSocket server = net.listenOnB(7004);
        assertTrue(server.isBound());
        assertEquals(7004, server.getLocalPort());
        assertEquals("100.64.0.2", server.getInetAddress().getHostAddress());
        assertEquals(new InetSocketAddress(NetstackPair.inet(NetstackPair.IP_B), 7004), server.getLocalSocketAddress());
        assertNull(server.getChannel());
        assertThrows(SocketException.class, () -> server.bind(new InetSocketAddress(1)));
        assertThrows(SocketException.class, () -> server.bind(new InetSocketAddress(1), 5));
        server.setSoTimeout(150);
        assertEquals(150, server.getSoTimeout());
        assertThrows(SocketTimeoutException.class, server::accept);

        server.close();
        assertTrue(server.isClosed());
        assertThrows(SocketException.class, server::accept);
        assertThrows(java.io.IOException.class, () -> new TailnetSocketFactory(net.dialerFromA()).createSocket("b", 7004),
                "a closed listener frees its port");
        net.listenOnB(7004).close();       // and the port can be reused
    }
}
