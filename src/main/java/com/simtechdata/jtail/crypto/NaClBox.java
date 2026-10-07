package com.simtechdata.jtail.crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * NaCl {@code crypto_box_curve25519xsalsa20poly1305} (Salsa20, XSalsa20, HSalsa20 and Poly1305 implemented in pure
 * Java, since the JDK has none of them). Tailscale uses it for the DERP login handshake and for all disco
 * (NAT-traversal) messages.
 */
public final class NaClBox {
    public static final int NONCE = 24, OVERHEAD = 16;
    private static final SecureRandom RNG = new SecureRandom();

    private final byte[] sharedKey;

    /** Precomputes the shared key between {@code myPriv} and {@code theirPub} (crypto_box_beforenm). */
    public NaClBox(byte[] myPriv, byte[] theirPub) {
        this.sharedKey = hsalsa20(X25519.scalarMult(myPriv, theirPub), new byte[16]);
    }

    public static byte[] newNonce() {
        byte[] n = new byte[NONCE];
        RNG.nextBytes(n);
        return n;
    }

    /** Returns tag(16) || ciphertext. */
    public byte[] seal(byte[] nonce, byte[] msg) { return secretboxSeal(sharedKey, nonce, msg); }

    /** Returns the plaintext, or null if authentication fails. */
    public byte[] open(byte[] nonce, byte[] box) { return secretboxOpen(sharedKey, nonce, box); }

    /** Seals with a fresh random nonce and returns nonce(24) || box, the framing used by DERP and disco. */
    public byte[] sealWithNonce(byte[] msg) {
        byte[] n = newNonce();
        byte[] ct = seal(n, msg);
        byte[] out = new byte[NONCE + ct.length];
        System.arraycopy(n, 0, out, 0, NONCE);
        System.arraycopy(ct, 0, out, NONCE, ct.length);
        return out;
    }

    /** Opens nonce(24) || box as produced by {@link #sealWithNonce}; null on failure. */
    public byte[] openWithNonce(byte[] data) {
        if (data.length < NONCE + OVERHEAD) return null;
        return open(Arrays.copyOfRange(data, 0, NONCE), Arrays.copyOfRange(data, NONCE, data.length));
    }

    // ---- secretbox (XSalsa20-Poly1305) ----

    static byte[] secretboxSeal(byte[] key, byte[] nonce, byte[] msg) {
        byte[] subkey = hsalsa20(key, Arrays.copyOfRange(nonce, 0, 16));
        byte[] n8 = Arrays.copyOfRange(nonce, 16, 24);
        byte[] stream = salsaStream(subkey, n8, 32 + msg.length);
        byte[] ct = new byte[msg.length];
        for (int i = 0; i < msg.length; i++) ct[i] = (byte) (msg[i] ^ stream[32 + i]);
        byte[] tag = poly1305(Arrays.copyOfRange(stream, 0, 32), ct);
        byte[] out = new byte[16 + ct.length];
        System.arraycopy(tag, 0, out, 0, 16);
        System.arraycopy(ct, 0, out, 16, ct.length);
        return out;
    }

    static byte[] secretboxOpen(byte[] key, byte[] nonce, byte[] box) {
        if (box.length < 16) return null;
        byte[] subkey = hsalsa20(key, Arrays.copyOfRange(nonce, 0, 16));
        byte[] n8 = Arrays.copyOfRange(nonce, 16, 24);
        int len = box.length - 16;
        byte[] stream = salsaStream(subkey, n8, 32 + len);
        byte[] ct = Arrays.copyOfRange(box, 16, box.length);
        byte[] tag = poly1305(Arrays.copyOfRange(stream, 0, 32), ct);
        if (!MessageDigest.isEqual(tag, Arrays.copyOfRange(box, 0, 16))) return null;
        byte[] pt = new byte[len];
        for (int i = 0; i < len; i++) pt[i] = (byte) (ct[i] ^ stream[32 + i]);
        return pt;
    }

    // ---- Salsa20 ----

    private static int rotl(int v, int c) { return Integer.rotateLeft(v, c); }

    private static void salsaRounds(int[] x) {
        for (int i = 0; i < 10; i++) {
            x[4] ^= rotl(x[0] + x[12], 7);  x[8] ^= rotl(x[4] + x[0], 9);
            x[12] ^= rotl(x[8] + x[4], 13); x[0] ^= rotl(x[12] + x[8], 18);
            x[9] ^= rotl(x[5] + x[1], 7);   x[13] ^= rotl(x[9] + x[5], 9);
            x[1] ^= rotl(x[13] + x[9], 13); x[5] ^= rotl(x[1] + x[13], 18);
            x[14] ^= rotl(x[10] + x[6], 7); x[2] ^= rotl(x[14] + x[10], 9);
            x[6] ^= rotl(x[2] + x[14], 13); x[10] ^= rotl(x[6] + x[2], 18);
            x[3] ^= rotl(x[15] + x[11], 7); x[7] ^= rotl(x[3] + x[15], 9);
            x[11] ^= rotl(x[7] + x[3], 13); x[15] ^= rotl(x[11] + x[7], 18);
            x[1] ^= rotl(x[0] + x[3], 7);   x[2] ^= rotl(x[1] + x[0], 9);
            x[3] ^= rotl(x[2] + x[1], 13);  x[0] ^= rotl(x[3] + x[2], 18);
            x[6] ^= rotl(x[5] + x[4], 7);   x[7] ^= rotl(x[6] + x[5], 9);
            x[4] ^= rotl(x[7] + x[6], 13);  x[5] ^= rotl(x[4] + x[7], 18);
            x[11] ^= rotl(x[10] + x[9], 7); x[8] ^= rotl(x[11] + x[10], 9);
            x[9] ^= rotl(x[8] + x[11], 13); x[10] ^= rotl(x[9] + x[8], 18);
            x[12] ^= rotl(x[15] + x[14], 7); x[13] ^= rotl(x[12] + x[15], 9);
            x[14] ^= rotl(x[13] + x[12], 13); x[15] ^= rotl(x[14] + x[13], 18);
        }
    }

    private static int le32(byte[] b, int o) {
        return (b[o] & 0xFF) | (b[o + 1] & 0xFF) << 8 | (b[o + 2] & 0xFF) << 16 | (b[o + 3] & 0xFF) << 24;
    }

    private static void putLe32(byte[] b, int o, int v) {
        b[o] = (byte) v; b[o + 1] = (byte) (v >>> 8); b[o + 2] = (byte) (v >>> 16); b[o + 3] = (byte) (v >>> 24);
    }

    private static final int C0 = 0x61707865, C1 = 0x3320646e, C2 = 0x79622d32, C3 = 0x6b206574; // "expand 32-byte k"

    /** HSalsa20: 32-byte key + 16-byte input -> 32-byte subkey. */
    static byte[] hsalsa20(byte[] key, byte[] in16) {
        int[] x = {C0, le32(key, 0), le32(key, 4), le32(key, 8), le32(key, 12), C1, le32(in16, 0), le32(in16, 4),
                le32(in16, 8), le32(in16, 12), C2, le32(key, 16), le32(key, 20), le32(key, 24), le32(key, 28), C3};
        salsaRounds(x);
        byte[] out = new byte[32];
        int[] idx = {0, 5, 10, 15, 6, 7, 8, 9};
        for (int i = 0; i < 8; i++) putLe32(out, i * 4, x[idx[i]]);
        return out;
    }

    /** Salsa20 keystream of {@code len} bytes for a 32-byte key and 8-byte nonce, counter starting at 0. */
    static byte[] salsaStream(byte[] key, byte[] nonce8, int len) {
        byte[] out = new byte[len];
        long counter = 0;
        for (int off = 0; off < len; off += 64, counter++) {
            int[] in = {C0, le32(key, 0), le32(key, 4), le32(key, 8), le32(key, 12), C1, le32(nonce8, 0), le32(nonce8, 4),
                    (int) counter, (int) (counter >>> 32), C2, le32(key, 16), le32(key, 20), le32(key, 24), le32(key, 28), C3};
            int[] x = in.clone();
            salsaRounds(x);
            for (int i = 0; i < 16 && off + i * 4 < len; i++) {
                int v = x[i] + in[i];
                for (int b = 0; b < 4 && off + i * 4 + b < len; b++) out[off + i * 4 + b] = (byte) (v >>> (8 * b));
            }
        }
        return out;
    }

    // ---- Poly1305 ----

    private static final BigInteger P = BigInteger.ONE.shiftLeft(130).subtract(BigInteger.valueOf(5));
    private static final BigInteger MASK128 = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE);

    private static BigInteger leInt(byte[] b, int off, int len) {
        byte[] be = new byte[len];
        for (int i = 0; i < len; i++) be[i] = b[off + len - 1 - i];
        return new BigInteger(1, be);
    }

    static byte[] poly1305(byte[] key32, byte[] msg) {
        byte[] rb = Arrays.copyOfRange(key32, 0, 16);
        rb[3] &= 15; rb[7] &= 15; rb[11] &= 15; rb[15] &= 15;
        rb[4] &= (byte) 252; rb[8] &= (byte) 252; rb[12] &= (byte) 252;
        BigInteger r = leInt(rb, 0, 16);
        BigInteger s = leInt(key32, 16, 16);
        BigInteger acc = BigInteger.ZERO;
        for (int off = 0; off < msg.length; off += 16) {
            int n = Math.min(16, msg.length - off);
            BigInteger block = leInt(msg, off, n).add(BigInteger.ONE.shiftLeft(8 * n));
            acc = acc.add(block).multiply(r).mod(P);
        }
        BigInteger tag = acc.add(s).and(MASK128);
        byte[] out = new byte[16];
        byte[] be = tag.toByteArray();
        for (int i = 0; i < 16; i++) {
            int src = be.length - 1 - i;
            out[i] = src >= 0 ? be[src] : 0;
        }
        return out;
    }
}
