package com.simtechdata.jtail.http2;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * A minimal HTTP/2 client over an arbitrary byte stream (RFC 9113). Tailscale's control protocol speaks
 * cleartext HTTP/2 inside the Noise transport, which {@code java.net.http} cannot do, so JTail carries its own.
 * Supports concurrent streams, request/response bodies, flow control, PING and GOAWAY. No server push, no priorities.
 */
public final class Http2Connection implements AutoCloseable {
    private static final byte[] PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
    private static final int DATA = 0, HEADERS = 1, RST_STREAM = 3, SETTINGS = 4, PUSH_PROMISE = 5, PING = 6,
            GOAWAY = 7, WINDOW_UPDATE = 8, CONTINUATION = 9;
    private static final int END_STREAM = 1, END_HEADERS = 4, PADDED = 8, PRIORITY = 0x20, ACK = 1;
    private static final int LOCAL_STREAM_WINDOW = 1 << 20;
    private static final int LOCAL_CONN_WINDOW_BUMP = (1 << 24) - 65535;

    private final InputStream in;
    private final OutputStream out;
    private final Object writeLock = new Object();
    private final Object flowLock = new Object();
    private final Hpack.Decoder decoder = new Hpack.Decoder(4096);
    private final Map<Integer, Http2Stream> streams = new HashMap<>();
    private int nextStreamId = 1;
    private int peerMaxFrame = 16384;
    private int peerInitialWindow = 65535;
    private long connSendWindow = 65535;
    private volatile Throwable failure;
    private volatile boolean closed;
    private final Thread reader;

    /** Performs the client preface and starts the frame reader. */
    public Http2Connection(InputStream in, OutputStream out) throws IOException {
        this.in = in;
        this.out = out;
        synchronized (writeLock) {
            out.write(PREFACE);
            ByteArrayOutputStream settings = new ByteArrayOutputStream();
            putSetting(settings, 2, 0);                       // ENABLE_PUSH = 0
            putSetting(settings, 4, LOCAL_STREAM_WINDOW);     // INITIAL_WINDOW_SIZE
            writeFrameLocked(SETTINGS, 0, 0, settings.toByteArray());
            writeFrameLocked(WINDOW_UPDATE, 0, 0, int32(LOCAL_CONN_WINDOW_BUMP));
            out.flush();
        }
        reader = new Thread(this::readLoop, "jtail-h2-reader");
        reader.setDaemon(true);
        reader.start();
    }

    private static void putSetting(ByteArrayOutputStream o, int id, int value) {
        o.write(id >> 8); o.write(id);
        o.writeBytes(int32(value));
    }

    private static byte[] int32(int v) {
        return new byte[]{(byte) (v >> 24), (byte) (v >> 16), (byte) (v >> 8), (byte) v};
    }

    /** Sends a request and returns once the response headers have arrived; the body streams via the response. */
    public Http2Response request(String method, String authority, String path, List<String[]> extraHeaders,
                                 byte[] body) throws IOException {
        Http2Stream s;
        synchronized (streams) {
            checkOpen();
            s = new Http2Stream(nextStreamId);
            nextStreamId += 2;
            s.sendWindow = peerInitialWindow;
            streams.put(s.id, s);
        }
        List<String[]> hs = new ArrayList<>();
        hs.add(new String[]{":method", method});
        hs.add(new String[]{":scheme", "http"});
        hs.add(new String[]{":authority", authority});
        hs.add(new String[]{":path", path});
        if (extraHeaders != null) hs.addAll(extraHeaders);
        if (body != null && body.length > 0) hs.add(new String[]{"content-length", Integer.toString(body.length)});
        byte[] block = Hpack.encode(hs);
        boolean hasBody = body != null && body.length > 0;
        synchronized (writeLock) { // header blocks must not interleave with other streams' HEADERS ids
            writeHeadersLocked(s.id, block, !hasBody);
            out.flush();
        }
        if (hasBody) sendData(s, body);
        return s.awaitResponse();
    }

    private void writeHeadersLocked(int id, byte[] block, boolean endStream) throws IOException {
        int off = 0, first = 1;
        do {
            int n = Math.min(block.length - off, peerMaxFrame);
            boolean last = off + n >= block.length;
            int type = first == 1 ? HEADERS : CONTINUATION;
            int flags = (last ? END_HEADERS : 0) | (first == 1 && endStream ? END_STREAM : 0);
            writeFrameLocked(type, flags, id, Arrays.copyOfRange(block, off, off + n));
            off += n;
            first = 0;
        } while (off < block.length);
    }

    private void sendData(Http2Stream s, byte[] body) throws IOException {
        int off = 0;
        while (off < body.length) {
            int n;
            synchronized (flowLock) {
                while (true) {
                    checkOpen();
                    if (s.reset) throw new IOException("stream reset by peer: error " + s.resetCode);
                    long avail = Math.min(connSendWindow, s.sendWindow);
                    if (avail > 0) { n = (int) Math.min(Math.min(avail, peerMaxFrame), body.length - off); break; }
                    try { flowLock.wait(500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IOException(e); }
                }
                connSendWindow -= n;
                s.sendWindow -= n;
            }
            boolean last = off + n >= body.length;
            synchronized (writeLock) {
                writeFrameLocked(DATA, last ? END_STREAM : 0, s.id, Arrays.copyOfRange(body, off, off + n));
                out.flush();
            }
            off += n;
        }
    }

    private void writeFrameLocked(int type, int flags, int streamId, byte[] payload) throws IOException {
        byte[] h = new byte[9];
        h[0] = (byte) (payload.length >> 16);
        h[1] = (byte) (payload.length >> 8);
        h[2] = (byte) payload.length;
        h[3] = (byte) type;
        h[4] = (byte) flags;
        h[5] = (byte) (streamId >> 24);
        h[6] = (byte) (streamId >> 16);
        h[7] = (byte) (streamId >> 8);
        h[8] = (byte) streamId;
        out.write(h);
        out.write(payload);
    }

    private void checkOpen() throws IOException {
        if (failure != null) throw new IOException("http2 connection failed: " + failure, failure);
        if (closed) throw new IOException("http2 connection closed");
    }

    // ---- reader ----

    private void readLoop() {
        try {
            byte[] hdr = new byte[9];
            List<byte[]> headerBlock = null;
            int headerStream = 0, headerFlags = 0;
            while (true) {
                readFully(hdr, 9);
                int len = ((hdr[0] & 0xFF) << 16) | ((hdr[1] & 0xFF) << 8) | (hdr[2] & 0xFF);
                int type = hdr[3] & 0xFF, flags = hdr[4] & 0xFF;
                int sid = ((hdr[5] & 0x7F) << 24) | ((hdr[6] & 0xFF) << 16) | ((hdr[7] & 0xFF) << 8) | (hdr[8] & 0xFF);
                byte[] p = new byte[len];
                readFully(p, len);
                if (headerBlock != null && type != CONTINUATION) throw new IOException("expected CONTINUATION");
                switch (type) {
                    case DATA -> onData(sid, flags, p);
                    case HEADERS -> {
                        int off = 0, end = p.length;
                        if ((flags & PADDED) != 0) { int pad = p[0] & 0xFF; off = 1; end -= pad; }
                        if ((flags & PRIORITY) != 0) off += 5;
                        byte[] frag = Arrays.copyOfRange(p, off, end);
                        if ((flags & END_HEADERS) != 0) onHeaders(sid, flags, frag);
                        else { headerBlock = new ArrayList<>(); headerBlock.add(frag); headerStream = sid; headerFlags = flags; }
                    }
                    case CONTINUATION -> {
                        if (headerBlock == null || sid != headerStream) throw new IOException("unexpected CONTINUATION");
                        headerBlock.add(p);
                        if ((flags & END_HEADERS) != 0) {
                            ByteArrayOutputStream all = new ByteArrayOutputStream();
                            for (byte[] b : headerBlock) all.writeBytes(b);
                            headerBlock = null;
                            onHeaders(sid, headerFlags, all.toByteArray());
                        }
                    }
                    case SETTINGS -> onSettings(flags, p);
                    case PING -> {
                        if ((flags & ACK) == 0) synchronized (writeLock) { writeFrameLocked(PING, ACK, 0, p); out.flush(); }
                    }
                    case WINDOW_UPDATE -> {
                        long inc = ((p[0] & 0x7FL) << 24) | ((p[1] & 0xFFL) << 16) | ((p[2] & 0xFFL) << 8) | (p[3] & 0xFFL);
                        synchronized (flowLock) {
                            if (sid == 0) connSendWindow += inc;
                            else { Http2Stream s = lookup(sid); if (s != null) s.sendWindow += inc; }
                            flowLock.notifyAll();
                        }
                    }
                    case RST_STREAM -> {
                        Http2Stream s = lookup(sid);
                        if (s != null) {
                            s.resetCode = ((p[0] & 0xFF) << 24) | ((p[1] & 0xFF) << 16) | ((p[2] & 0xFF) << 8) | (p[3] & 0xFF);
                            s.reset = true;
                            s.finish(new IOException("stream reset by peer: error " + s.resetCode));
                            synchronized (flowLock) { flowLock.notifyAll(); }
                        }
                    }
                    case GOAWAY -> throw new IOException("GOAWAY from server, error code "
                            + (((p[4] & 0xFF) << 24) | ((p[5] & 0xFF) << 16) | ((p[6] & 0xFF) << 8) | (p[7] & 0xFF)));
                    case PUSH_PROMISE -> throw new IOException("unexpected PUSH_PROMISE");
                    default -> { /* unknown frame types must be ignored */ }
                }
            }
        } catch (Throwable t) {
            if (!closed) failure = t;
            failAll(t);
        }
    }

    private Http2Stream lookup(int id) { synchronized (streams) { return streams.get(id); } }

    private void onSettings(int flags, byte[] p) throws IOException {
        if ((flags & ACK) != 0) return;
        for (int i = 0; i + 6 <= p.length; i += 6) {
            int id = ((p[i] & 0xFF) << 8) | (p[i + 1] & 0xFF);
            int v = ((p[i + 2] & 0xFF) << 24) | ((p[i + 3] & 0xFF) << 16) | ((p[i + 4] & 0xFF) << 8) | (p[i + 5] & 0xFF);
            switch (id) {
                case 4 -> {
                    synchronized (flowLock) {
                        int delta = v - peerInitialWindow;
                        peerInitialWindow = v;
                        synchronized (streams) { for (Http2Stream s : streams.values()) s.sendWindow += delta; }
                        flowLock.notifyAll();
                    }
                }
                case 5 -> peerMaxFrame = Math.max(16384, Math.min(v, (1 << 24) - 1));
                default -> { }
            }
        }
        synchronized (writeLock) { writeFrameLocked(SETTINGS, ACK, 0, new byte[0]); out.flush(); }
    }

    private void onHeaders(int sid, int flags, byte[] block) throws IOException {
        List<String[]> hs = decoder.decode(block);
        Http2Stream s = lookup(sid);
        if (s == null) return;
        s.onHeaders(hs, (flags & END_STREAM) != 0);
        if ((flags & END_STREAM) != 0) remove(s);
    }

    private void onData(int sid, int flags, byte[] p) throws IOException {
        int off = 0, end = p.length;
        if ((flags & PADDED) != 0) { int pad = p[0] & 0xFF; off = 1; end -= pad; }
        Http2Stream s = lookup(sid);
        if (end > off && s != null) s.queue.add(Arrays.copyOfRange(p, off, end));
        if (p.length > 0) { // replenish both windows by what was consumed on the wire
            synchronized (writeLock) {
                writeFrameLocked(WINDOW_UPDATE, 0, 0, int32(p.length));
                if (s != null && (flags & END_STREAM) == 0) writeFrameLocked(WINDOW_UPDATE, 0, sid, int32(p.length));
                out.flush();
            }
        }
        if ((flags & END_STREAM) != 0 && s != null) { s.finish(null); remove(s); }
    }

    private void remove(Http2Stream s) { synchronized (streams) { streams.remove(s.id); } }

    private void failAll(Throwable t) {
        List<Http2Stream> all;
        synchronized (streams) { all = new ArrayList<>(streams.values()); streams.clear(); }
        for (Http2Stream s : all) s.finish(t instanceof IOException ? (IOException) t : new IOException(t));
        synchronized (flowLock) { flowLock.notifyAll(); }
    }

    private void readFully(byte[] b, int n) throws IOException {
        int off = 0;
        while (off < n) {
            int r = in.read(b, off, n - off);
            if (r < 0) throw new EOFException("http2 connection closed by peer");
            off += r;
        }
    }

    public boolean isUsable() { return failure == null && !closed; }

    @Override public void close() {
        closed = true;
        try { out.close(); } catch (IOException ignored) { }
        try { in.close(); } catch (IOException ignored) { }
        failAll(new IOException("connection closed"));
    }

    // ---- per-stream state ----

    private static final class Http2Stream {
        final int id;
        long sendWindow;
        volatile boolean reset;
        volatile int resetCode;
        final LinkedBlockingQueue<byte[]> queue = new LinkedBlockingQueue<>();
        private final java.util.concurrent.CompletableFuture<Http2Response> response = new java.util.concurrent.CompletableFuture<>();
        private Http2Response resp;
        private volatile boolean finished;
        private static final byte[] EOF = new byte[0];

        Http2Stream(int id) { this.id = id; }

        void onHeaders(List<String[]> hs, boolean endStream) {
            if (resp == null) {
                int status = 0;
                Map<String, List<String>> map = new java.util.TreeMap<>(String.CASE_INSENSITIVE_ORDER);
                for (String[] h : hs) {
                    if (h[0].equals(":status")) status = Integer.parseInt(h[1]);
                    else map.computeIfAbsent(h[0], k -> new ArrayList<>()).add(h[1]);
                }
                if (status >= 100 && status < 200) return; // informational
                resp = new Http2Response(status, map, this);
                response.complete(resp);
            } // trailers ignored
            if (endStream) finish(null);
        }

        void finish(Throwable err) {
            if (finished) return;
            finished = true;
            if (err != null) {
                response.completeExceptionally(err);
                queue.add(errMarker(err));
            } else {
                queue.add(EOF);
            }
        }

        private byte[] errMarker(Throwable t) { error = t; return EOF; }
        volatile Throwable error;

        Http2Response awaitResponse() throws IOException {
            try {
                return response.get();
            } catch (java.util.concurrent.ExecutionException e) {
                throw e.getCause() instanceof IOException io ? io : new IOException(e.getCause());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException(e);
            }
        }

        InputStream bodyStream() {
            return new InputStream() {
                private byte[] cur = new byte[0];
                private int pos;
                private boolean eof;

                @Override public int read() throws IOException {
                    byte[] one = new byte[1];
                    return read(one, 0, 1) < 0 ? -1 : one[0] & 0xFF;
                }

                @Override public int read(byte[] b, int off, int len) throws IOException {
                    if (len == 0) return 0;
                    while (pos >= cur.length) {
                        if (eof) return -1;
                        try { cur = queue.take(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IOException(e); }
                        pos = 0;
                        if (cur == EOF) {
                            eof = true;
                            if (error != null) throw new IOException("response body failed: " + error, error);
                            return -1;
                        }
                    }
                    int n = Math.min(len, cur.length - pos);
                    System.arraycopy(cur, pos, b, off, n);
                    pos += n;
                    return n;
                }
            };
        }
    }

    /** A received response. The body may still be arriving (long-poll); read it from {@link #body()}. */
    public static final class Http2Response {
        private final int status;
        private final Map<String, List<String>> headers;
        private final Http2Stream stream;

        Http2Response(int status, Map<String, List<String>> headers, Http2Stream stream) {
            this.status = status; this.headers = headers; this.stream = stream;
        }

        public int status() { return status; }
        public Map<String, List<String>> headers() { return headers; }
        public String header(String name) { List<String> v = headers.get(name); return v == null ? null : v.get(0); }
        public InputStream body() { return stream.bodyStream(); }
        public byte[] readAll() throws IOException { return body().readAllBytes(); }
    }
}
