package com.simtechdata.jtail.derp;

import com.simtechdata.jtail.crypto.NaClBox;
import com.simtechdata.jtail.crypto.X25519;
import com.simtechdata.jtail.json.Json;
import com.simtechdata.jtail.tailcfg.Derp;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * A client for one DERP relay server (Tailscale's TCP/HTTPS relay protocol, used when peers cannot reach each other
 * directly). One instance owns one connection; {@link DerpConnection} adds reconnection on top.
 */
public final class DerpClient implements AutoCloseable {
    static final int FRAME_SERVER_KEY = 0x01, FRAME_CLIENT_INFO = 0x02, FRAME_SERVER_INFO = 0x03,
            FRAME_SEND_PACKET = 0x04, FRAME_RECV_PACKET = 0x05, FRAME_KEEP_ALIVE = 0x06, FRAME_NOTE_PREFERRED = 0x07,
            FRAME_PEER_GONE = 0x08, FRAME_PING = 0x12, FRAME_PONG = 0x13, FRAME_HEALTH = 0x14, FRAME_RESTARTING = 0x15;
    private static final byte[] MAGIC = "DERP🔑".getBytes(StandardCharsets.UTF_8); // "DERP🔑", 8 bytes
    public static final int MAX_PACKET = 64 << 10;

    /** Receives events from the server. Called on the client's reader thread. */
    public interface Listener {
        void onPacket(byte[] sourceNodeKey, byte[] data);
        default void onPeerGone(byte[] nodeKey, int reason) { }
        default void onClosed(Throwable cause) { }
    }

    private final Socket socket;
    private final DataInputStream in;
    private final OutputStream out;
    private final Object writeLock = new Object();
    private final byte[] myPriv, myPub;
    private byte[] serverKey;
    private final Listener listener;
    private volatile boolean closed;
    private Thread reader;

    private DerpClient(Socket s, byte[] myPriv, Listener l) throws IOException {
        this.socket = s;
        this.in = new DataInputStream(new BufferedInputStream(s.getInputStream(), 16384));
        this.out = s.getOutputStream();
        this.myPriv = myPriv;
        this.myPub = X25519.publicKey(myPriv);
        this.listener = l;
    }

    /** Connects to {@code node}, upgrades to DERP, and completes the key exchange. */
    public static DerpClient connect(Derp.Node node, byte[] myNodePriv, Listener listener) throws IOException {
        String host = !node.ipv4().isEmpty() && !node.ipv4().equals("none") ? node.ipv4() : node.hostName();
        Socket raw = new Socket();
        raw.connect(new InetSocketAddress(host, node.port()), 10_000);
        raw.setTcpNoDelay(true);
        Socket s = raw;
        try {
            String sni = node.certName().isEmpty() ? node.hostName() : node.certName();
            SSLSocket ssl = (SSLSocket) tlsFactory(node.insecureForTests()).createSocket(raw, sni, node.port(), true);
            SSLParameters sp = ssl.getSSLParameters();
            if (!sni.isEmpty() && !sni.matches("[0-9.:]+")) sp.setServerNames(java.util.List.of(new SNIHostName(sni)));
            if (!node.insecureForTests()) sp.setEndpointIdentificationAlgorithm("HTTPS");
            ssl.setSSLParameters(sp);
            ssl.startHandshake();
            s = ssl;
            DerpClient c = new DerpClient(s, myNodePriv, listener);
            c.upgrade(node.hostName());
            c.handshake();
            c.startReader();
            return c;
        } catch (IOException | RuntimeException e) {
            try { s.close(); } catch (IOException ignored) { }
            throw e;
        }
    }

    private static SSLSocketFactory tlsFactory(boolean insecure) throws IOException {
        if (!insecure) return (SSLSocketFactory) SSLSocketFactory.getDefault();
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{new X509TrustManager() {
                @Override public void checkClientTrusted(X509Certificate[] c, String a) { }
                @Override public void checkServerTrusted(X509Certificate[] c, String a) { }
                @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }}, null);
            return ctx.getSocketFactory();
        } catch (java.security.GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    private void upgrade(String host) throws IOException {
        out.write(("GET /derp HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n")
                .getBytes(StandardCharsets.US_ASCII));
        out.flush();
        String status = readLine();
        while (!readLine().isEmpty()) { /* skip headers */ }
        if (!status.contains(" 101")) throw new IOException("DERP upgrade failed: " + status);
    }

    private String readLine() throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) >= 0) {
            if (c == '\n') break;
            if (c != '\r') b.write(c);
            if (b.size() > 8192) throw new IOException("header too long");
        }
        if (c < 0 && b.size() == 0) throw new EOFException();
        return b.toString(StandardCharsets.ISO_8859_1);
    }

    private void handshake() throws IOException {
        // server -> FrameServerKey: 8B magic + 32B key
        int type = in.readUnsignedByte();
        int len = in.readInt();
        if (type != FRAME_SERVER_KEY || len < 40 || len > 1024) throw new IOException("invalid DERP server greeting");
        byte[] g = new byte[len];
        in.readFully(g);
        if (!Arrays.equals(Arrays.copyOf(g, 8), MAGIC)) throw new IOException("bad DERP magic");
        serverKey = Arrays.copyOfRange(g, 8, 40);

        Map<String, Object> info = new LinkedHashMap<>();
        info.put("version", 2);
        info.put("CanAckPings", true);
        byte[] sealed = new NaClBox(myPriv, serverKey).sealWithNonce(Json.write(info).getBytes(StandardCharsets.UTF_8));
        byte[] payload = new byte[32 + sealed.length];
        System.arraycopy(myPub, 0, payload, 0, 32);
        System.arraycopy(sealed, 0, payload, 32, sealed.length);
        writeFrame(FRAME_CLIENT_INFO, payload);

        // server -> FrameServerInfo (encrypted JSON); contents are advisory (rate limits), we only validate it opens
        type = in.readUnsignedByte();
        len = in.readInt();
        if (type != FRAME_SERVER_INFO || len < 24 || len > (1 << 20)) throw new IOException("expected DERP server info");
        byte[] si = new byte[len];
        in.readFully(si);
        if (new NaClBox(myPriv, serverKey).openWithNonce(si) == null) throw new IOException("cannot open DERP server info");
    }

    private void startReader() {
        reader = new Thread(this::readLoop, "jtail-derp-reader");
        reader.setDaemon(true);
        reader.start();
    }

    private void readLoop() {
        Throwable cause = null;
        try {
            while (!closed) {
                int type = in.readUnsignedByte();
                long len = in.readInt() & 0xFFFFFFFFL;
                if (len > MAX_PACKET + 1024) throw new IOException("DERP frame too large: " + len);
                byte[] b = new byte[(int) len];
                in.readFully(b);
                switch (type) {
                    case FRAME_RECV_PACKET -> {
                        if (b.length >= 32) listener.onPacket(Arrays.copyOf(b, 32), Arrays.copyOfRange(b, 32, b.length));
                    }
                    case FRAME_PING -> { if (b.length >= 8) writeFrame(FRAME_PONG, Arrays.copyOf(b, 8)); }
                    case FRAME_PEER_GONE -> {
                        if (b.length >= 32) listener.onPeerGone(Arrays.copyOf(b, 32), b.length > 32 ? b[32] & 0xFF : 0);
                    }
                    case FRAME_RESTARTING -> throw new IOException("DERP server is restarting");
                    default -> { /* keepalive, health, serverinfo, pong: nothing to do */ }
                }
            }
        } catch (Throwable t) {
            cause = t;
        } finally {
            boolean was = closed;
            closed = true;
            try { socket.close(); } catch (IOException ignored) { }
            if (!was) listener.onClosed(cause);
        }
    }

    /** Relays {@code packet} to the node identified by {@code destNodeKey} (which must be connected to this region). */
    public void send(byte[] destNodeKey, byte[] packet) throws IOException {
        if (packet.length > MAX_PACKET) throw new IOException("packet too large for DERP");
        byte[] p = new byte[32 + packet.length];
        System.arraycopy(destNodeKey, 0, p, 0, 32);
        System.arraycopy(packet, 0, p, 32, packet.length);
        writeFrame(FRAME_SEND_PACKET, p);
    }

    /** Tells the server whether this is our home region (it then keeps us registered for delivery). */
    public void notePreferred(boolean preferred) throws IOException {
        writeFrame(FRAME_NOTE_PREFERRED, new byte[]{(byte) (preferred ? 1 : 0)});
    }

    private void writeFrame(int type, byte[] payload) throws IOException {
        byte[] h = {(byte) type, (byte) (payload.length >>> 24), (byte) (payload.length >>> 16), (byte) (payload.length >>> 8), (byte) payload.length};
        synchronized (writeLock) {
            out.write(h);
            out.write(payload);
            out.flush();
        }
    }

    public byte[] serverKey() { return serverKey.clone(); }
    public boolean isClosed() { return closed; }

    @Override public void close() {
        closed = true;
        try { socket.close(); } catch (IOException ignored) { }
    }
}
