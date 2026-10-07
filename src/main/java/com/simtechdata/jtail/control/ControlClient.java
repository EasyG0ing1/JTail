package com.simtechdata.jtail.control;

import com.simtechdata.jtail.control.noise.ControlHandshake;
import com.simtechdata.jtail.control.noise.NoiseConn;
import com.simtechdata.jtail.http2.Http2Connection;
import com.simtechdata.jtail.json.J;
import com.simtechdata.jtail.json.Json;
import com.simtechdata.jtail.state.NodeIdentity;
import com.simtechdata.jtail.tailcfg.Keys;
import com.simtechdata.jtail.tailcfg.MapResponse;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import javax.net.ssl.SSLSocketFactory;

/**
 * Talks to a Tailscale (or Headscale) control server using the "ts2021" protocol: an HTTP upgrade to a Noise
 * channel carrying HTTP/2, over which JSON requests ({@code /machine/register}, {@code /machine/map}) are sent.
 */
public final class ControlClient implements AutoCloseable {
    /**
     * Capability version we advertise, both as the Noise protocol version and in requests. It tells the server which
     * features we understand; JTail implements the delta/patch map semantics but not zstd, hence an empty Compress.
     */
    public static final int CAPABILITY_VERSION = 125;

    private static final String UPGRADE = "tailscale-control-protocol";
    private static final byte[] EARLY_MAGIC = {(byte) 0xff, (byte) 0xff, (byte) 0xff, 'T', 'S'};

    private final URI baseUrl;
    private final NodeIdentity identity;
    private byte[] serverNoiseKey;
    private Http2Connection h2;

    public ControlClient(URI baseUrl, NodeIdentity identity) {
        this.baseUrl = baseUrl;
        this.identity = identity;
    }

    /** Result of /machine/register. */
    public record RegisterResult(String authUrl, boolean machineAuthorized, boolean nodeKeyExpired, String error,
                                 String loginName, String displayName) {}

    // ---- bootstrap ----

    /** Fetches the control server's Noise public key from {@code /key?v=<capver>} (over TLS when https). */
    public byte[] fetchServerKey() throws IOException {
        URI u = baseUrl.resolve("/key?v=" + CAPABILITY_VERSION);
        try {
            HttpClient hc = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15))
                    .proxy(ProxySelector.getDefault()).build();
            HttpResponse<String> r = hc.send(HttpRequest.newBuilder(u).timeout(Duration.ofSeconds(30)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) throw new ControlException("GET /key: HTTP " + r.statusCode(), r.statusCode());
            Map<String, Object> m = Json.parseObject(r.body());
            byte[] k = Keys.decode(Keys.MACHINE, J.str(m, "publicKey"));
            if (k == null) throw new ControlException("control server is too old: no noise public key", 0);
            return k;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException(e);
        }
    }

    /** Opens the Noise+HTTP/2 session if not already open. */
    public synchronized Http2Connection connect() throws IOException {
        if (h2 != null && h2.isUsable()) return h2;
        if (serverNoiseKey == null) serverNoiseKey = fetchServerKey();
        boolean tls = baseUrl.getScheme().equals("https");
        String host = baseUrl.getHost();
        int port = baseUrl.getPort() > 0 ? baseUrl.getPort() : (tls ? 443 : 80);

        Socket sock = openSocket(host, port, tls);
        try {
            sock.setTcpNoDelay(true);
            InputStream in = new BufferedInputStream(sock.getInputStream(), 8192);
            OutputStream out = sock.getOutputStream();

            ControlHandshake.ClientPending pending =
                    ControlHandshake.clientInit(identity.machinePrivate(), serverNoiseKey, CAPABILITY_VERSION);
            String req = "POST /ts2021 HTTP/1.1\r\n"
                    + "Host: " + host + (baseUrl.getPort() > 0 ? ":" + port : "") + "\r\n"
                    + "Upgrade: " + UPGRADE + "\r\n"
                    + "Connection: upgrade\r\n"
                    + "X-Tailscale-Handshake: " + Base64.getEncoder().encodeToString(pending.initiationMessage()) + "\r\n"
                    + "Content-Length: 0\r\n\r\n";
            out.write(req.getBytes(StandardCharsets.US_ASCII));
            out.flush();

            String status = readLine(in);
            Map<String, String> hdrs = new LinkedHashMap<>();
            for (String line; !(line = readLine(in)).isEmpty(); ) {
                int c = line.indexOf(':');
                if (c > 0) hdrs.put(line.substring(0, c).trim().toLowerCase(), line.substring(c + 1).trim());
            }
            if (!status.contains(" 101")) throw new ControlException("control upgrade failed: " + status, parseStatus(status));
            if (!UPGRADE.equals(hdrs.get("upgrade"))) throw new ControlException("server switched to unexpected protocol", 0);

            NoiseConn noise = pending.finish(in, out);
            PushbackInputStream nin = new PushbackInputStream(noise.inputStream(), 9);
            skipEarlyPayload(nin);
            h2 = new Http2Connection(nin, noise.outputStream());
            return h2;
        } catch (IOException | RuntimeException e) {
            try { sock.close(); } catch (IOException ignored) { }
            throw e;
        }
    }

    private Socket openSocket(String host, int port, boolean tls) throws IOException {
        Socket raw;
        Proxy proxy = Proxy.NO_PROXY;
        try {
            List<Proxy> ps = ProxySelector.getDefault().select(baseUrl);
            if (ps != null && !ps.isEmpty()) proxy = ps.get(0);
        } catch (RuntimeException ignored) { }
        if (proxy.type() == Proxy.Type.HTTP && proxy.address() instanceof InetSocketAddress pa) {
            raw = new Socket();
            raw.connect(new InetSocketAddress(pa.getHostString(), pa.getPort()), 15_000);
            OutputStream o = raw.getOutputStream();
            o.write(("CONNECT " + host + ":" + port + " HTTP/1.1\r\nHost: " + host + ":" + port + "\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            o.flush();
            InputStream i = raw.getInputStream();
            String st = readLine(i);
            while (!readLine(i).isEmpty()) { /* skip proxy headers */ }
            if (!st.contains(" 200")) { raw.close(); throw new ControlException("proxy CONNECT failed: " + st, parseStatus(st)); }
        } else {
            raw = new Socket();
            raw.connect(new InetSocketAddress(host, port), 15_000);
        }
        if (!tls) return raw;
        return ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(raw, host, port, true);
    }

    private static int parseStatus(String line) {
        try { return Integer.parseInt(line.split(" ")[1]); } catch (RuntimeException e) { return 0; }
    }

    /** Reads one CRLF-terminated line without over-reading the stream. */
    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) >= 0) {
            if (c == '\n') break;
            if (c != '\r') b.write(c);
            if (b.size() > 16384) throw new IOException("HTTP header line too long");
        }
        if (c < 0 && b.size() == 0) throw new EOFException("connection closed during HTTP upgrade");
        return b.toString(StandardCharsets.ISO_8859_1);
    }

    /** The server may send {@code ff ff ff 'T' 'S' <u32 len> <json>} before its first HTTP/2 frame; consume it. */
    private static void skipEarlyPayload(PushbackInputStream in) throws IOException {
        byte[] hdr = in.readNBytes(9);
        if (hdr.length < 9) throw new EOFException("control connection closed before HTTP/2 start");
        for (int i = 0; i < EARLY_MAGIC.length; i++) {
            if (hdr[i] != EARLY_MAGIC[i]) { in.unread(hdr); return; }
        }
        int len = ((hdr[5] & 0xFF) << 24) | ((hdr[6] & 0xFF) << 16) | ((hdr[7] & 0xFF) << 8) | (hdr[8] & 0xFF);
        if (len < 0 || len > (1 << 20)) throw new IOException("early payload too large");
        in.readNBytes(len); // tailcfg.EarlyNoise (nodeKeyChallenge); not needed by this client
    }

    // ---- API calls ----

    private Http2Connection.Http2Response post(String path, Map<String, Object> body) throws IOException {
        byte[] data = Json.write(body).getBytes(StandardCharsets.UTF_8);
        String authority = baseUrl.getHost() + (baseUrl.getPort() > 0 ? ":" + baseUrl.getPort() : "");
        return connect().request("POST", authority, path,
                java.util.Collections.singletonList(new String[]{"content-type", "application/json"}), data);
    }

    /**
     * Registers this node (or refreshes its registration). With a valid reusable auth key the response carries no
     * AuthURL and the node is immediately part of the tailnet.
     */
    public RegisterResult register(String authKey, Hostinfo hostinfo, boolean ephemeral, byte[] oldNodeKey)
            throws IOException {
        return registerWithExpiry(authKey, hostinfo, ephemeral, oldNodeKey, "0001-01-01T00:00:00Z");
    }

    /** Asks the control server to expire this node's key now, removing an ephemeral node from the tailnet. */
    public void logout(Hostinfo hostinfo) throws IOException {
        registerWithExpiry(null, hostinfo, false, null, "1970-01-01T00:02:03Z"); // same sentinel as the Go client
    }

    private RegisterResult registerWithExpiry(String authKey, Hostinfo hostinfo, boolean ephemeral, byte[] oldNodeKey,
                                              String expiry) throws IOException {
        Map<String, Object> req = new LinkedHashMap<>();
        req.put("Version", CAPABILITY_VERSION);
        req.put("NodeKey", Keys.encode(Keys.NODE, identity.nodePublic()));
        req.put("OldNodeKey", Keys.encode(Keys.NODE, oldNodeKey));
        req.put("NLKey", Keys.encode(Keys.NL, identity.nlPublic()));
        if (authKey != null && !authKey.isEmpty()) {
            Map<String, Object> auth = new LinkedHashMap<>();
            auth.put("AuthKey", authKey);
            req.put("Auth", auth);
        }
        req.put("Expiry", expiry);
        req.put("Followup", "");
        req.put("Hostinfo", hostinfo.toJson());
        if (ephemeral) req.put("Ephemeral", true);
        req.put("NodeKeySignature", null);
        req.put("Timestamp", Instant.now().toString());

        Http2Connection.Http2Response r = post("/machine/register", req);
        byte[] body = r.readAll();
        if (r.status() != 200) {
            throw new ControlException("register: HTTP " + r.status() + ": "
                    + new String(body, StandardCharsets.UTF_8).trim(), r.status());
        }
        Map<String, Object> m = Json.parseObject(new String(body, StandardCharsets.UTF_8));
        Map<String, Object> login = J.obj(m, "Login");
        return new RegisterResult(J.str(m, "AuthURL"), J.bool(m, "MachineAuthorized"), J.bool(m, "NodeKeyExpired"),
                J.str(m, "Error"), login == null ? "" : J.str(login, "LoginName"),
                login == null ? "" : J.str(login, "DisplayName"));
    }

    /**
     * Starts the streaming network-map long poll and delivers every response to {@code onMap} on the calling thread
     * until the stream ends or fails. Blocks; run it on its own thread.
     *
     * @param hostinfo   reported with the request
     * @param endpoints  our reachable UDP endpoints ("ip:port"), may be empty
     * @param stream     false = one-shot "lite" update: the call returns once the server has answered
     */
    public void pollMap(Hostinfo hostinfo, List<String> endpoints, boolean stream, Consumer<MapResponse> onMap)
            throws IOException {
        pollMap(hostinfo, endpoints, endpoints.stream().map(e -> 1).toList(), stream, onMap);
    }

    /** As above, with an explicit tailcfg.EndpointType per endpoint (1 = local, 2 = STUN). */
    public void pollMap(Hostinfo hostinfo, List<String> endpoints, List<Integer> endpointTypes, boolean stream,
                        Consumer<MapResponse> onMap) throws IOException {
        Map<String, Object> req = new LinkedHashMap<>();
        req.put("Version", CAPABILITY_VERSION);
        req.put("KeepAlive", true);
        req.put("NodeKey", Keys.encode(Keys.NODE, identity.nodePublic()));
        req.put("DiscoKey", Keys.encode(Keys.DISCO, identity.discoPublic()));
        if (!endpoints.isEmpty()) {
            req.put("Endpoints", endpoints);
            req.put("EndpointTypes", endpointTypes);
        }
        if (stream) req.put("Stream", true);
        req.put("Hostinfo", hostinfo.toJson());
        if (!stream) req.put("OmitPeers", true);

        Http2Connection.Http2Response r = post("/machine/map", req);
        if (r.status() != 200) {
            throw new ControlException("map: HTTP " + r.status() + ": "
                    + new String(r.readAll(), StandardCharsets.UTF_8).trim(), r.status());
        }
        InputStream body = r.body();
        while (true) {
            byte[] len = body.readNBytes(4);
            if (len.length == 0) return; // clean end of stream
            if (len.length < 4) throw new EOFException("truncated map frame header");
            int n = (len[0] & 0xFF) | ((len[1] & 0xFF) << 8) | ((len[2] & 0xFF) << 16) | ((len[3] & 0xFF) << 24);
            if (n < 0 || n > (64 << 20)) throw new IOException("map frame too large: " + n);
            byte[] json = body.readNBytes(n);
            if (json.length < n) throw new EOFException("truncated map frame");
            onMap.accept(MapResponse.fromJson(Json.parseObject(new String(json, StandardCharsets.UTF_8))));
        }
    }

    /**
     * Sends a one-shot "lite" map request that publishes our endpoints, disco key and hostinfo without streaming.
     * Servers (including Tailscale's) only record these from non-streaming requests, so call this before
     * {@link #pollMap} and again whenever the endpoints change.
     */
    public void sendUpdate(Hostinfo hostinfo, List<String> endpoints) throws IOException {
        pollMap(hostinfo, endpoints, false, r -> { });
    }

    public void sendUpdate(Hostinfo hostinfo, List<String> endpoints, List<Integer> endpointTypes) throws IOException {
        pollMap(hostinfo, endpoints, endpointTypes, false, r -> { });
    }

    @Override public synchronized void close() {
        if (h2 != null) { h2.close(); h2 = null; }
    }
}
