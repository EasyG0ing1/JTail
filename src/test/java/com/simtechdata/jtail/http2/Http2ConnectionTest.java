package com.simtechdata.jtail.http2;

import static org.junit.jupiter.api.Assertions.*;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The HTTP/2 client against a server played by hand over loopback, so framing, flow control, GOAWAY and friends are
 * tested without a Go oracle.
 */
class Http2ConnectionTest {
    static final int DATA = 0, HEADERS = 1, RST_STREAM = 3, SETTINGS = 4, PING = 6, GOAWAY = 7, WINDOW_UPDATE = 8, CONTINUATION = 9;
    static final int END_STREAM = 1, END_HEADERS = 4, PADDED = 8, ACK = 1;

    record Frame(int type, int flags, int stream, byte[] payload) {}

    /** The test is the server; {@link #client} is the code under test. */
    static final class Peer implements AutoCloseable {
        final ServerSocket listener;
        final Socket clientSocket, server;
        final Http2Connection client;
        final DataInputStream in;
        final OutputStream out;

        Peer() throws Exception {
            listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
            clientSocket = new Socket(InetAddress.getLoopbackAddress(), listener.getLocalPort());
            server = listener.accept();
            server.setSoTimeout(10_000);
            in = new DataInputStream(new BufferedInputStream(server.getInputStream()));
            out = server.getOutputStream();
            client = new Http2Connection(clientSocket.getInputStream(), clientSocket.getOutputStream());
            byte[] preface = new byte[24];
            in.readFully(preface);
            assertEquals("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", new String(preface, StandardCharsets.US_ASCII));
            write(SETTINGS, 0, 0, new byte[0]);
        }

        Frame read() throws IOException {
            byte[] h = new byte[9];
            in.readFully(h);
            int len = ((h[0] & 0xFF) << 16) | ((h[1] & 0xFF) << 8) | (h[2] & 0xFF);
            int stream = ((h[5] & 0x7F) << 24) | ((h[6] & 0xFF) << 16) | ((h[7] & 0xFF) << 8) | (h[8] & 0xFF);
            byte[] p = new byte[len];
            in.readFully(p);
            return new Frame(h[3] & 0xFF, h[4] & 0xFF, stream, p);
        }

        /** Reads frames until one of {@code type} arrives, skipping the client's SETTINGS/WINDOW_UPDATE chatter. */
        Frame next(int type) throws IOException {
            while (true) {
                Frame f = read();
                if (f.type() == type) return f;
            }
        }

        void write(int type, int flags, int stream, byte[] payload) throws IOException {
            byte[] h = {(byte) (payload.length >> 16), (byte) (payload.length >> 8), (byte) payload.length,
                    (byte) type, (byte) flags, (byte) (stream >> 24), (byte) (stream >> 16), (byte) (stream >> 8), (byte) stream};
            out.write(h);
            out.write(payload);
            out.flush();
        }

        /** Sends a complete response header block for {@code stream}. */
        void respond(int stream, int status, boolean endStream, String... extra) throws IOException {
            List<String[]> hs = new java.util.ArrayList<>();
            hs.add(new String[]{":status", Integer.toString(status)});
            for (int i = 0; i + 1 < extra.length; i += 2) hs.add(new String[]{extra[i], extra[i + 1]});
            write(HEADERS, END_HEADERS | (endStream ? END_STREAM : 0), stream, Hpack.encode(hs));
        }

        @Override public void close() throws IOException {
            client.close();
            clientSocket.close();
            server.close();
            listener.close();
        }
    }

    final ExecutorService ex = Executors.newCachedThreadPool();

    @AfterEach void tearDown() { ex.shutdownNow(); }

    static byte[] int32(int v) { return new byte[]{(byte) (v >> 24), (byte) (v >> 16), (byte) (v >> 8), (byte) v}; }

    static Throwable failureOf(Future<?> f) {
        ExecutionException e = assertThrows(ExecutionException.class, () -> f.get(10, TimeUnit.SECONDS));
        return e.getCause();
    }

    @Test @Timeout(30)
    void requestAndResponseWithBodiesPaddingAndCustomHeaders() throws Exception {
        try (Peer p = new Peer()) {
            Future<Http2Connection.Http2Response> f = ex.submit(() ->
                    p.client.request("POST", "control.example", "/machine/map", List.<String[]>of(new String[]{"x-custom", "yes"}),
                            "hello".getBytes(StandardCharsets.US_ASCII)));

            Frame headers = p.next(HEADERS);
            assertEquals(1, headers.stream(), "client streams are odd, starting at 1");
            assertEquals(0, headers.flags() & END_STREAM, "a request with a body does not end with its headers");
            var seen = new Hpack.Decoder(4096).decode(headers.payload());
            assertEquals(":method", seen.get(0)[0]);
            assertEquals("POST", seen.get(0)[1]);
            assertEquals("control.example", seen.get(2)[1]);
            assertEquals("/machine/map", seen.get(3)[1]);
            assertTrue(seen.stream().anyMatch(h -> h[0].equals("x-custom") && h[1].equals("yes")));
            assertTrue(seen.stream().anyMatch(h -> h[0].equals("content-length") && h[1].equals("5")));

            Frame data = p.next(DATA);
            assertEquals("hello", new String(data.payload(), StandardCharsets.US_ASCII));
            assertEquals(END_STREAM, data.flags() & END_STREAM);

            p.respond(1, 200, false, "x-test", "present");
            p.write(DATA, PADDED, 1, new byte[]{3, 'w', 'o', 'r', 0, 0, 0});     // "wor" + 3 padding bytes
            p.write(DATA, PADDED | END_STREAM, 1, new byte[]{1, 'l', 'd', 0});   // "ld" + 1 padding byte

            Http2Connection.Http2Response r = f.get(10, TimeUnit.SECONDS);
            assertEquals(200, r.status());
            assertEquals("present", r.header("X-Test"), "header lookup is case-insensitive");
            assertEquals("world", new String(r.readAll(), StandardCharsets.US_ASCII));
            assertTrue(p.client.isUsable());
        }
    }

    @Test @Timeout(30)
    void requestWithoutBodyEndsTheStreamWithItsHeaders() throws Exception {
        try (Peer p = new Peer()) {
            Future<Http2Connection.Http2Response> f = ex.submit(() -> p.client.request("GET", "h", "/", null, null));
            Frame headers = p.next(HEADERS);
            assertEquals(END_STREAM, headers.flags() & END_STREAM);
            p.respond(1, 204, true);
            Http2Connection.Http2Response r = f.get(10, TimeUnit.SECONDS);
            assertEquals(204, r.status());
            assertEquals(0, r.readAll().length);
        }
    }

    @Test @Timeout(60)
    void largeRequestBodyWaitsForTheFlowControlWindow() throws Exception {
        try (Peer p = new Peer()) {
            byte[] body = new byte[200_000];
            Arrays.fill(body, (byte) 7);
            Future<Http2Connection.Http2Response> f = ex.submit(() -> p.client.request("POST", "h", "/up", null, body));
            p.next(HEADERS);

            int received = 0;
            while (received < 65_535) received += p.next(DATA).payload().length;
            assertEquals(65_535, received, "the client may send exactly the initial window and no more");

            p.server.setSoTimeout(500);
            try {
                while (true) assertNotEquals(DATA, p.read().type(), "no body bytes may arrive beyond the window");
            } catch (SocketTimeoutException expected) {
                // the client stalled, as required, until the window opens
            }
            p.server.setSoTimeout(10_000);

            p.write(WINDOW_UPDATE, 0, 0, int32(200_000));
            p.write(WINDOW_UPDATE, 0, 1, int32(200_000));
            boolean ended = false;
            while (!ended) {
                Frame d = p.next(DATA);
                received += d.payload().length;
                ended = (d.flags() & END_STREAM) != 0;
            }
            assertEquals(body.length, received);

            p.respond(1, 200, true);
            assertEquals(200, f.get(10, TimeUnit.SECONDS).status());
        }
    }

    @Test @Timeout(30)
    void responseHeaderBlockSplitAcrossContinuationFramesIsReassembled() throws Exception {
        try (Peer p = new Peer()) {
            Future<Http2Connection.Http2Response> f = ex.submit(() -> p.client.request("GET", "h", "/", null, null));
            p.next(HEADERS);
            byte[] block = Hpack.encode(List.of(new String[]{":status", "200"}, new String[]{"x-long", "v".repeat(300)}));
            p.write(HEADERS, END_STREAM, 1, Arrays.copyOfRange(block, 0, 20));                 // no END_HEADERS
            p.write(CONTINUATION, END_HEADERS, 1, Arrays.copyOfRange(block, 20, block.length));
            Http2Connection.Http2Response r = f.get(10, TimeUnit.SECONDS);
            assertEquals(200, r.status());
            assertEquals(300, r.header("x-long").length());
            assertEquals(0, r.readAll().length, "END_STREAM on the HEADERS frame ends the response");
        }
    }

    @Test @Timeout(30)
    void pingIsAnsweredWithTheSameOpaqueData() throws Exception {
        try (Peer p = new Peer()) {
            byte[] opaque = {1, 2, 3, 4, 5, 6, 7, 8};
            p.write(PING, 0, 0, opaque);
            Frame pong = p.next(PING);
            assertEquals(ACK, pong.flags() & ACK);
            assertArrayEquals(opaque, pong.payload());
        }
    }

    @Test @Timeout(30)
    void unknownFrameTypesAreIgnored() throws Exception {
        try (Peer p = new Peer()) {
            Future<Http2Connection.Http2Response> f = ex.submit(() -> p.client.request("GET", "h", "/", null, null));
            p.next(HEADERS);
            p.write(0xFE, 0, 0, new byte[]{1, 2, 3});
            p.respond(1, 200, true);
            assertEquals(200, f.get(10, TimeUnit.SECONDS).status());
        }
    }

    @Test @Timeout(30)
    void concurrentStreamsAreAnsweredIndependently() throws Exception {
        try (Peer p = new Peer()) {
            Future<Http2Connection.Http2Response> a = ex.submit(() -> p.client.request("GET", "h", "/a", null, null));
            int first = p.next(HEADERS).stream();
            Future<Http2Connection.Http2Response> b = ex.submit(() -> p.client.request("GET", "h", "/b", null, null));
            int second = p.next(HEADERS).stream();
            assertEquals(2, Math.abs(second - first), "stream ids advance by two");
            int lo = Math.min(first, second), hi = Math.max(first, second);
            p.respond(hi, 202, true);       // answer out of order
            p.respond(lo, 201, true);
            int sa = a.get(10, TimeUnit.SECONDS).status(), sb = b.get(10, TimeUnit.SECONDS).status();
            List<Integer> got = new java.util.ArrayList<>(List.of(sa, sb));
            java.util.Collections.sort(got);
            assertEquals(List.of(201, 202), got, "each request gets the response sent for its own stream");
        }
    }

    @Test @Timeout(30)
    void goAwayFailsPendingRequestsAndMarksTheConnectionUnusable() throws Exception {
        try (Peer p = new Peer()) {
            Future<Http2Connection.Http2Response> f = ex.submit(() -> p.client.request("GET", "h", "/", null, null));
            p.next(HEADERS);
            p.write(GOAWAY, 0, 0, new byte[]{0, 0, 0, 0, 0, 0, 0, 2});     // last stream 0, INTERNAL_ERROR
            Throwable cause = failureOf(f);
            assertTrue(cause instanceof IOException, String.valueOf(cause));
            assertTrue(cause.getMessage().contains("GOAWAY") || String.valueOf(cause.getCause()).contains("GOAWAY"), cause.toString());
            assertFalse(p.client.isUsable());
            assertThrows(IOException.class, () -> p.client.request("GET", "h", "/", null, null));
        }
    }

    @Test @Timeout(30)
    void resetStreamFailsOnlyThatRequest() throws Exception {
        try (Peer p = new Peer()) {
            Future<Http2Connection.Http2Response> f = ex.submit(() -> p.client.request("GET", "h", "/", null, null));
            p.next(HEADERS);
            p.write(RST_STREAM, 0, 1, int32(8));                              // CANCEL
            assertTrue(failureOf(f).getMessage().contains("reset"), "the error names the reset");
            assertTrue(p.client.isUsable(), "other streams are unaffected");

            Future<Http2Connection.Http2Response> g = ex.submit(() -> p.client.request("GET", "h", "/", null, null));
            int id = p.next(HEADERS).stream();
            p.respond(id, 200, true);
            assertEquals(200, g.get(10, TimeUnit.SECONDS).status());
        }
    }

    @Test @Timeout(30)
    void oversizedFrameBreaksTheConnectionInsteadOfAllocatingIt() throws Exception {
        try (Peer p = new Peer()) {
            Future<Http2Connection.Http2Response> f = ex.submit(() -> p.client.request("GET", "h", "/", null, null));
            p.next(HEADERS);
            // a frame header announcing 16385 bytes, one more than the client advertised it would accept
            p.out.write(new byte[]{0x00, 0x40, 0x01, DATA, 0, 0, 0, 0, 1});
            p.out.flush();
            Throwable cause = failureOf(f);
            assertTrue(String.valueOf(cause).contains("exceeds"), cause.toString());
            assertFalse(p.client.isUsable());
        }
    }

    @Test @Timeout(30)
    void serverClosingTheConnectionFailsPendingRequests() throws Exception {
        try (Peer p = new Peer()) {
            Future<Http2Connection.Http2Response> f = ex.submit(() -> p.client.request("GET", "h", "/", null, null));
            p.next(HEADERS);
            p.server.close();
            assertTrue(failureOf(f) instanceof IOException);
            assertFalse(p.client.isUsable());
        }
    }

    @Test @Timeout(30)
    void headerBlockOverTheCapIsRejected() throws Exception {
        try (Peer p = new Peer()) {
            Future<Http2Connection.Http2Response> f = ex.submit(() -> p.client.request("GET", "h", "/", null, null));
            p.next(HEADERS);
            p.write(HEADERS, 0, 1, new byte[16384]);                                  // no END_HEADERS: more to come
            for (int i = 0; i < 19; i++) p.write(CONTINUATION, 0, 1, new byte[16384]);   // 20 x 16 KB in total, over the 256 KB cap
            Throwable cause = failureOf(f);
            assertTrue(String.valueOf(cause).contains("too large"), cause.toString());
        }
    }
}
