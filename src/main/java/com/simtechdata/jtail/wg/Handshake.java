package com.simtechdata.jtail.wg;

import static com.simtechdata.jtail.wg.WgConstants.*;

import com.simtechdata.jtail.crypto.Blake2s;
import com.simtechdata.jtail.crypto.ChaCha20Poly1305;
import com.simtechdata.jtail.crypto.Hmac;
import com.simtechdata.jtail.crypto.X25519;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;

/** The Noise_IKpsk2 handshake math of WireGuard, free of any I/O or peer bookkeeping. */
final class Handshake {
    private Handshake() {}

    static final byte[] INITIAL_CK = Blake2s.hash(CONSTRUCTION.getBytes(StandardCharsets.US_ASCII));
    static final byte[] INITIAL_HASH = Blake2s.hash(INITIAL_CK, IDENTIFIER.getBytes(StandardCharsets.US_ASCII));
    private static final byte[] ZERO_NONCE = new byte[12];

    static byte[] mac1Key(byte[] staticPublic) {
        return Blake2s.hash(LABEL_MAC1.getBytes(StandardCharsets.US_ASCII), staticPublic);
    }

    static byte[] cookieKey(byte[] staticPublic) {
        return Blake2s.hash(LABEL_COOKIE.getBytes(StandardCharsets.US_ASCII), staticPublic);
    }

    static byte[] mac(byte[] key, byte[] data, int len) {
        return Blake2s.hash(16, key, Arrays.copyOf(data, len));
    }

    private static byte[][] kdf(byte[] ck, byte[] input, int n) { return Hmac.hkdf(ck, input, n); }

    private static byte[] hash(byte[] a, byte[] b) { return Blake2s.hash(a, b); }

    static byte[] tai64n() {
        long now = System.currentTimeMillis();
        long secs = (1L << 62) + 10 + now / 1000;
        long nanos = (now % 1000) * 1_000_000L;
        byte[] out = new byte[12];
        for (int i = 0; i < 8; i++) out[i] = (byte) (secs >>> (56 - 8 * i));
        for (int i = 0; i < 4; i++) out[8 + i] = (byte) (nanos >>> (24 - 8 * i));
        return out;
    }

    /** Initiator state kept between sending the initiation and receiving the response. */
    static final class InitiatorState {
        byte[] ck, h, ephemeralPriv;
        int localIndex;
    }

    /** Builds a type-1 message (mac2 left zero for the caller to fill). */
    static byte[] createInitiation(byte[] ourPriv, byte[] ourPub, byte[] theirPub, byte[] staticStatic,
                                   int localIndex, InitiatorState st) {
        byte[] ck = INITIAL_CK.clone();
        byte[] h = hash(INITIAL_HASH, theirPub);
        byte[] ePriv = X25519.generatePrivate();
        byte[] ePub = X25519.publicKey(ePriv);
        ck = kdf(ck, ePub, 1)[0];
        h = hash(h, ePub);
        byte[][] k = kdf(ck, X25519.scalarMult(ePriv, theirPub), 2);
        ck = k[0];
        byte[] encStatic = new ChaCha20Poly1305(k[1]).seal(ZERO_NONCE, ourPub, h);
        h = hash(h, encStatic);
        k = kdf(ck, staticStatic, 2);
        ck = k[0];
        byte[] encTs = new ChaCha20Poly1305(k[1]).seal(ZERO_NONCE, tai64n(), h);
        h = hash(h, encTs);

        byte[] msg = new byte[INITIATION_LEN];
        msg[0] = MSG_INITIATION;
        putLe32(msg, 4, localIndex);
        System.arraycopy(ePub, 0, msg, 8, 32);
        System.arraycopy(encStatic, 0, msg, 40, 48);
        System.arraycopy(encTs, 0, msg, 88, 28);
        st.ck = ck; st.h = h; st.ephemeralPriv = ePriv; st.localIndex = localIndex;
        return msg;
    }

    /** Result of consuming an initiation as responder. */
    static final class Consumed {
        byte[] peerStatic, timestamp, ck, h, peerEphemeral;
        int peerIndex;
    }

    /** Verifies and decrypts an initiation. {@code staticLookup} resolves the peer's precomputed static-static secret. */
    static Consumed consumeInitiation(byte[] msg, byte[] ourPriv, byte[] ourPub,
                                      java.util.function.Function<byte[], byte[]> staticLookup)
            throws AEADBadTagException {
        byte[] ck = INITIAL_CK.clone();
        byte[] h = hash(INITIAL_HASH, ourPub);
        byte[] ePub = Arrays.copyOfRange(msg, 8, 40);
        ck = kdf(ck, ePub, 1)[0];
        h = hash(h, ePub);
        byte[][] k = kdf(ck, X25519.scalarMult(ourPriv, ePub), 2);
        ck = k[0];
        byte[] encStatic = Arrays.copyOfRange(msg, 40, 88);
        byte[] peerStatic = new ChaCha20Poly1305(k[1]).open(ZERO_NONCE, encStatic, h);
        h = hash(h, encStatic);
        byte[] ss = staticLookup.apply(peerStatic);
        if (ss == null) throw new AEADBadTagException("unknown peer");
        k = kdf(ck, ss, 2);
        ck = k[0];
        byte[] encTs = Arrays.copyOfRange(msg, 88, 116);
        byte[] ts = new ChaCha20Poly1305(k[1]).open(ZERO_NONCE, encTs, h);
        h = hash(h, encTs);
        Consumed c = new Consumed();
        c.peerStatic = peerStatic; c.timestamp = ts; c.ck = ck; c.h = h; c.peerEphemeral = ePub;
        c.peerIndex = le32(msg, 4);
        return c;
    }

    /** Result of building a response: wire message plus the derived transport keys {sendKey, recvKey}. */
    static final class Response {
        byte[] message, sendKey, recvKey;
    }

    static Response createResponse(Consumed c, byte[] theirStatic, int localIndex) {
        byte[] ck = c.ck, h = c.h;
        byte[] ePriv = X25519.generatePrivate();
        byte[] ePub = X25519.publicKey(ePriv);
        ck = kdf(ck, ePub, 1)[0];
        h = hash(h, ePub);
        ck = kdf(ck, X25519.scalarMult(ePriv, c.peerEphemeral), 1)[0];
        ck = kdf(ck, X25519.scalarMult(ePriv, theirStatic), 1)[0];
        byte[][] k = kdf(ck, new byte[32], 3); // psk = 0
        ck = k[0];
        h = hash(h, k[1]);
        byte[] empty = new ChaCha20Poly1305(k[2]).seal(ZERO_NONCE, new byte[0], h);
        byte[] msg = new byte[RESPONSE_LEN];
        msg[0] = MSG_RESPONSE;
        putLe32(msg, 4, localIndex);
        putLe32(msg, 8, c.peerIndex);
        System.arraycopy(ePub, 0, msg, 12, 32);
        System.arraycopy(empty, 0, msg, 44, 16);
        byte[][] t = kdf(ck, new byte[0], 2); // responder: recv = T1 (initiator's send), send = T2
        Response r = new Response();
        r.message = msg; r.recvKey = t[0]; r.sendKey = t[1];
        return r;
    }

    /** Consumes a response as initiator; returns {sendKey, recvKey} = (T1, T2). */
    static byte[][] consumeResponse(byte[] msg, InitiatorState st, byte[] ourPriv) throws AEADBadTagException {
        byte[] ePub = Arrays.copyOfRange(msg, 12, 44);
        byte[] ck = kdf(st.ck, ePub, 1)[0];
        byte[] h = hash(st.h, ePub);
        ck = kdf(ck, X25519.scalarMult(st.ephemeralPriv, ePub), 1)[0];
        ck = kdf(ck, X25519.scalarMult(ourPriv, ePub), 1)[0];
        byte[][] k = kdf(ck, new byte[32], 3);
        ck = k[0];
        h = hash(h, k[1]);
        new ChaCha20Poly1305(k[2]).open(ZERO_NONCE, Arrays.copyOfRange(msg, 44, 60), h);
        return kdf(ck, new byte[0], 2);
    }

    static void putLe32(byte[] b, int o, int v) {
        b[o] = (byte) v; b[o + 1] = (byte) (v >>> 8); b[o + 2] = (byte) (v >>> 16); b[o + 3] = (byte) (v >>> 24);
    }

    static int le32(byte[] b, int o) {
        return (b[o] & 0xFF) | (b[o + 1] & 0xFF) << 8 | (b[o + 2] & 0xFF) << 16 | (b[o + 3] & 0xFF) << 24;
    }

    static void putLe64(byte[] b, int o, long v) {
        for (int i = 0; i < 8; i++) b[o + i] = (byte) (v >>> (8 * i));
    }

    static long le64(byte[] b, int o) {
        long v = 0;
        for (int i = 7; i >= 0; i--) v = (v << 8) | (b[o + i] & 0xFF);
        return v;
    }
}
