package com.simtechdata.jtail.derp;

import static org.junit.jupiter.api.Assertions.*;

import com.simtechdata.jtail.crypto.NaClBox;
import com.simtechdata.jtail.crypto.X25519;
import com.simtechdata.jtail.tailcfg.Derp;
import com.simtechdata.jtail.testutil.SelfSignedTls;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

/** DerpClient and DerpManager against an in-process DERP server that speaks the real framing over real TLS. */
class FakeDerpTest {
    static final int SEND_PACKET = 4, RECV_PACKET = 5, NOTE_PREFERRED = 7, PEER_GONE = 8, PING = 0x12, PONG = 0x13, RESTARTING = 0x15;

    @TempDir static Path tmp;
    static SSLServerSocketFactory tlsFactory;
    static String priorOptIn;

    @BeforeAll static void setUp() throws Exception {
        tlsFactory = SelfSignedTls.serverFactory(tmp);
        priorOptIn = System.getProperty(DerpClient.ALLOW_INSECURE_PROPERTY);
        System.setProperty(DerpClient.ALLOW_INSECURE_PROPERTY, "true");   // our server's certificate is self-signed
    }

    @AfterAll static void tearDown() {
        if (priorOptIn == null) System.clearProperty(DerpClient.ALLOW_INSECURE_PROPERTY);
        else System.setProperty(DerpClient.ALLOW_INSECURE_PROPERTY, priorOptIn);
    }

    /** A DERP server that accepts any number of connections, one after another. */
    static final class FakeDerp implements AutoCloseable {
        final SSLServerSocket server;
        final byte[] priv = X25519.generatePrivate(), pub = X25519.publicKey(priv);
        final BlockingQueue<Object[]> frames = new LinkedBlockingQueue<>();   // {Integer type, byte[] payload}
        final AtomicInteger connections = new AtomicInteger();
        volatile OutputStream out;
        volatile Socket current;
        volatile byte[] clientKey;
        volatile boolean badMagic;
        volatile boolean closed;

        FakeDerp() throws Exception {
            server = (SSLServerSocket) tlsFactory.createServerSocket(0, 5, InetAddress.getLoopbackAddress());
            Thread t = new Thread(this::acceptLoop, "fake-derp");
            t.setDaemon(true);
            t.start();
        }

        int port() { return server.getLocalPort(); }

        Derp.Node node() {
            return new Derp.Node("t1", 1, "127.0.0.1", "", "127.0.0.1", "none", -1, false, port(), true, false);
        }

        private void acceptLoop() {
            while (!closed) {
                try (Socket s = server.accept()) {
                    current = s;
                    serve(s);
                } catch (Exception e) {
                    // client left or handshake failed: wait for the next one
                }
            }
        }

        private void serve(Socket s) throws IOException {
            InputStream raw = new BufferedInputStream(s.getInputStream());
            DataInputStream in = new DataInputStream(raw);
            out = s.getOutputStream();
            for (int state = 0, c; state < 4 && (c = in.read()) >= 0; ) {            // HTTP upgrade request
                state = (c == '\r' && (state == 0 || state == 2)) || (c == '\n' && (state == 1 || state == 3)) ? state + 1 : 0;
            }
            out.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            byte[] magic = "DERP🔑".getBytes(StandardCharsets.UTF_8);
            if (badMagic) magic[0] = 'X';
            byte[] greeting = Arrays.copyOf(magic, 8 + 32);
            System.arraycopy(pub, 0, greeting, 8, 32);
            send(1, greeting);

            in.readUnsignedByte();                                                     // FrameClientInfo
            byte[] info = new byte[in.readInt()];
            in.readFully(info);
            clientKey = Arrays.copyOf(info, 32);
            NaClBox box = new NaClBox(priv, clientKey);
            if (box.openWithNonce(Arrays.copyOfRange(info, 32, info.length)) == null) throw new IOException("bad client info");
            send(3, box.sealWithNonce("{}".getBytes(StandardCharsets.US_ASCII)));      // FrameServerInfo
            connections.incrementAndGet();

            while (true) {
                int type = in.readUnsignedByte();
                byte[] payload = new byte[in.readInt()];
                in.readFully(payload);
                frames.add(new Object[]{type, payload});
            }
        }

        synchronized void send(int type, byte[] payload) throws IOException {
            OutputStream o = out;
            o.write(new byte[]{(byte) type, (byte) (payload.length >>> 24), (byte) (payload.length >>> 16),
                    (byte) (payload.length >>> 8), (byte) payload.length});
            o.write(payload);
            o.flush();
        }

        /** Waits for a frame of {@code type}, ignoring others, and returns its payload. */
        byte[] await(int type) throws InterruptedException {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            while (System.nanoTime() < deadline) {
                Object[] f = frames.poll(200, TimeUnit.MILLISECONDS);
                if (f != null && (Integer) f[0] == type) return (byte[]) f[1];
            }
            fail("no frame of type " + type + " arrived");
            return null;
        }

        void dropConnection() throws IOException { current.close(); }

        @Override public void close() throws IOException {
            closed = true;
            server.close();
            Socket s = current;
            if (s != null) s.close();
        }
    }

    record Got(byte[] src, byte[] data) {}

    static final class Recorder implements DerpClient.Listener {
        final BlockingQueue<Got> packets = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> gone = new LinkedBlockingQueue<>();
        final BlockingQueue<Integer> goneReasons = new LinkedBlockingQueue<>();
        final BlockingQueue<Throwable> closedWith = new LinkedBlockingQueue<>();
        volatile boolean closedCalled;

        @Override public void onPacket(byte[] src, byte[] data) { packets.add(new Got(src, data)); }
        @Override public void onPeerGone(byte[] key, int reason) { gone.add(key); goneReasons.add(reason); }
        @Override public void onClosed(Throwable cause) { closedCalled = true; closedWith.add(cause == null ? new Error("clean") : cause); }
    }

    static byte[] key(int fill) {
        byte[] k = new byte[32];
        Arrays.fill(k, (byte) fill);
        return k;
    }

    @Test @Timeout(60)
    void relaysPacketsAndPreferenceInBothDirections() throws Exception {
        try (FakeDerp server = new FakeDerp()) {
            Recorder rec = new Recorder();
            byte[] myPriv = X25519.generatePrivate();
            try (DerpClient c = DerpClient.connect(server.node(), myPriv, rec)) {
                assertArrayEquals(server.pub, c.serverKey());
                assertArrayEquals(X25519.publicKey(myPriv), server.clientKey);

                byte[] dest = key(9), data = new byte[1500];
                new java.util.Random(1).nextBytes(data);
                c.send(dest, data);
                byte[] frame = server.await(SEND_PACKET);
                assertArrayEquals(dest, Arrays.copyOf(frame, 32));
                assertArrayEquals(data, Arrays.copyOfRange(frame, 32, frame.length));

                c.notePreferred(true);
                assertArrayEquals(new byte[]{1}, server.await(NOTE_PREFERRED));

                byte[] src = key(7), inbound = "from a peer".getBytes();
                byte[] payload = new byte[32 + inbound.length];
                System.arraycopy(src, 0, payload, 0, 32);
                System.arraycopy(inbound, 0, payload, 32, inbound.length);
                server.send(RECV_PACKET, payload);
                Got g = rec.packets.poll(10, TimeUnit.SECONDS);
                assertNotNull(g);
                assertArrayEquals(src, g.src());
                assertArrayEquals(inbound, g.data());

                assertThrows(IOException.class, () -> c.send(dest, new byte[DerpClient.MAX_PACKET + 1]), "oversized packets are refused locally");
            }
        }
    }

    @Test @Timeout(60)
    void answersServerPingsAndReportsPeerGone() throws Exception {
        try (FakeDerp server = new FakeDerp()) {
            Recorder rec = new Recorder();
            try (DerpClient c = DerpClient.connect(server.node(), X25519.generatePrivate(), rec)) {
                byte[] opaque = {1, 2, 3, 4, 5, 6, 7, 8};
                server.send(PING, opaque);
                assertArrayEquals(opaque, server.await(PONG));

                byte[] gone = new byte[33];
                System.arraycopy(key(5), 0, gone, 0, 32);
                gone[32] = 1;                                             // reason: peer not present
                server.send(PEER_GONE, gone);
                assertArrayEquals(key(5), rec.gone.poll(10, TimeUnit.SECONDS));
                assertEquals(1, rec.goneReasons.poll(1, TimeUnit.SECONDS));
                assertFalse(c.isClosed());
            }
        }
    }

    @Test @Timeout(60)
    void serverRestartAndOversizedFramesCloseTheClient() throws Exception {
        try (FakeDerp server = new FakeDerp()) {
            Recorder rec = new Recorder();
            DerpClient c = DerpClient.connect(server.node(), X25519.generatePrivate(), rec);
            server.send(RESTARTING, new byte[0]);
            Throwable cause = rec.closedWith.poll(10, TimeUnit.SECONDS);
            assertNotNull(cause, "the listener hears about the close");
            assertTrue(String.valueOf(cause).contains("restarting"), cause.toString());
            assertTrue(c.isClosed());

            Recorder rec2 = new Recorder();
            DerpClient c2 = DerpClient.connect(server.node(), X25519.generatePrivate(), rec2);
            try {
                server.send(RECV_PACKET, new byte[DerpClient.MAX_PACKET + 2048]);
            } catch (IOException clientAlreadyHungUp) {
                // the client closes as soon as it reads the oversized length, possibly mid-write
            }
            Throwable cause2 = rec2.closedWith.poll(10, TimeUnit.SECONDS);
            assertNotNull(cause2);
            assertTrue(String.valueOf(cause2).contains("too large"), cause2.toString());
            assertTrue(c2.isClosed());
        }
    }

    @Test @Timeout(60)
    void greetingWithTheWrongMagicIsRejected() throws Exception {
        try (FakeDerp server = new FakeDerp()) {
            server.badMagic = true;
            IOException e = assertThrows(IOException.class,
                    () -> DerpClient.connect(server.node(), X25519.generatePrivate(), new Recorder()));
            assertTrue(e.getMessage().contains("magic"), e.toString());
        }
    }

    @Test @Timeout(60)
    void anUntrustedCertificateIsRejectedUnlessTheJvmOptsIn() throws Exception {
        try (FakeDerp server = new FakeDerp()) {
            System.setProperty(DerpClient.ALLOW_INSECURE_PROPERTY, "false");
            try {
                assertThrows(javax.net.ssl.SSLException.class,
                        () -> DerpClient.connect(server.node(), X25519.generatePrivate(), new Recorder()),
                        "the DERP map's InsecureForTests alone must not make a self-signed certificate acceptable");
            } finally {
                System.setProperty(DerpClient.ALLOW_INSECURE_PROPERTY, "true");
            }
        }
    }

    // ---- DerpManager ----

    static Derp.Map_ mapOf(Derp.Node node) {
        Derp.Region r = new Derp.Region(1, "tst", "Test", false, false, List.of(node));
        return new Derp.Map_(new TreeMap<>(Map.of(1, r)), false);
    }

    static void await(java.util.function.BooleanSupplier cond, String what) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
        while (!cond.getAsBoolean()) {
            if (System.nanoTime() > deadline) fail("timed out waiting for " + what);
            Thread.sleep(50);
        }
    }

    @Test @Timeout(60)
    void managerConnectsToTheHomeRegionSendsAndReceives() throws Exception {
        try (FakeDerp server = new FakeDerp()) {
            BlockingQueue<Got> inbound = new LinkedBlockingQueue<>();
            AtomicInteger region = new AtomicInteger();
            try (DerpManager m = new DerpManager(X25519.generatePrivate(), (r, src, data) -> {
                region.set(r);
                inbound.add(new Got(src, data));
            })) {
                assertFalse(m.isConnected(1));
                m.setMap(mapOf(server.node()));
                m.setHome(1);
                assertEquals(1, m.home());
                await(() -> m.isConnected(1), "the home connection");
                assertArrayEquals(new byte[]{1}, server.await(NOTE_PREFERRED), "the home region is announced as preferred");

                m.send(1, key(3), "out".getBytes());
                byte[] frame = server.await(SEND_PACKET);
                assertArrayEquals(key(3), Arrays.copyOf(frame, 32));
                assertEquals("out", new String(frame, 32, frame.length - 32));

                byte[] payload = new byte[35];
                System.arraycopy(key(4), 0, payload, 0, 32);
                System.arraycopy("in!".getBytes(), 0, payload, 32, 3);
                server.send(RECV_PACKET, payload);
                Got g = inbound.poll(10, TimeUnit.SECONDS);
                assertNotNull(g);
                assertEquals(1, region.get());
                assertArrayEquals(key(4), g.src());
                assertEquals("in!", new String(g.data()));

                assertDoesNotThrow(() -> m.send(99, key(3), new byte[1]), "an unknown region drops the packet quietly");
            }
        }
    }

    @Test @Timeout(60)
    void managerReconnectsTheHomeRegionAfterTheServerDropsIt() throws Exception {
        try (FakeDerp server = new FakeDerp()) {
            try (DerpManager m = new DerpManager(X25519.generatePrivate(), (r, src, data) -> { })) {
                m.setMap(mapOf(server.node()));
                m.setHome(1);
                await(() -> server.connections.get() == 1 && m.isConnected(1), "the first connection");
                server.dropConnection();
                await(() -> server.connections.get() == 2 && m.isConnected(1), "the reconnection");
            }
        }
    }

    @Test @Timeout(60)
    void managerSurvivesAnUnreachableRelayAndCloseIsIdempotent() throws Exception {
        int deadPort;
        try (java.net.ServerSocket s = new java.net.ServerSocket(0)) { deadPort = s.getLocalPort(); }
        Derp.Node dead = new Derp.Node("t1", 1, "127.0.0.1", "", "127.0.0.1", "none", -1, false, deadPort, true, false);
        DerpManager m = new DerpManager(X25519.generatePrivate(), (r, src, data) -> fail("nothing can arrive"));
        m.setMap(mapOf(dead));
        m.setHome(1);
        m.send(1, key(1), new byte[]{1});                      // queued, then dropped when the connect fails
        Thread.sleep(1500);
        assertFalse(m.isConnected(1));
        m.close();
        assertDoesNotThrow(m::close);
        assertDoesNotThrow(() -> m.send(1, key(1), new byte[]{1}), "sending after close is a no-op");
    }
}
