package com.simtechdata.jtail.crypto;

import java.util.Arrays;

/**
 * BLAKE2s (RFC 7693) with optional key (MAC mode) and configurable digest length (1..32).
 * Pure Java; the JDK does not ship BLAKE2s but WireGuard and Tailscale's Noise handshake require it.
 */
public final class Blake2s {
    public static final int BLOCK_SIZE = 64;
    public static final int MAX_DIGEST = 32;

    private static final int[] IV = {
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    };
    private static final byte[][] SIGMA = {
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
            {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
            {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
            {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
            {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
            {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
            {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
            {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
            {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    };

    private final int[] h = new int[8];
    private final byte[] buf = new byte[BLOCK_SIZE];
    private final int digestLen;
    private final byte[] key;
    private int bufLen;
    private long counter;

    public Blake2s() { this(MAX_DIGEST, null); }

    public Blake2s(int digestLen) { this(digestLen, null); }

    public Blake2s(int digestLen, byte[] key) {
        if (digestLen < 1 || digestLen > MAX_DIGEST) throw new IllegalArgumentException("digest length");
        if (key != null && key.length > 32) throw new IllegalArgumentException("key too long");
        this.digestLen = digestLen;
        this.key = key == null ? new byte[0] : key.clone();
        reset();
    }

    public void reset() {
        System.arraycopy(IV, 0, h, 0, 8);
        h[0] ^= 0x01010000 ^ (key.length << 8) ^ digestLen;
        bufLen = 0;
        counter = 0;
        if (key.length > 0) {
            Arrays.fill(buf, (byte) 0);
            System.arraycopy(key, 0, buf, 0, key.length);
            bufLen = BLOCK_SIZE;
        }
    }

    public void update(byte[] in) { update(in, 0, in.length); }

    public void update(byte[] in, int off, int len) {
        while (len > 0) {
            if (bufLen == BLOCK_SIZE) { // only compress a full buffer once more data follows
                counter += BLOCK_SIZE;
                compress(buf, 0, false);
                bufLen = 0;
            }
            int n = Math.min(len, BLOCK_SIZE - bufLen);
            System.arraycopy(in, off, buf, bufLen, n);
            bufLen += n;
            off += n;
            len -= n;
        }
    }

    /** Finishes the hash and returns the digest; the instance is reset afterwards. */
    public byte[] digest() {
        counter += bufLen;
        Arrays.fill(buf, bufLen, BLOCK_SIZE, (byte) 0);
        compress(buf, 0, true);
        byte[] out = new byte[digestLen];
        for (int i = 0; i < digestLen; i++) out[i] = (byte) (h[i >> 2] >>> (8 * (i & 3)));
        reset();
        return out;
    }

    public static byte[] hash(byte[]... parts) { return hash(MAX_DIGEST, null, parts); }

    public static byte[] hash(int digestLen, byte[] key, byte[]... parts) {
        Blake2s b = new Blake2s(digestLen, key);
        for (byte[] p : parts) b.update(p);
        return b.digest();
    }

    private void compress(byte[] block, int off, boolean last) {
        int[] m = new int[16];
        for (int i = 0; i < 16; i++) {
            int p = off + i * 4;
            m[i] = (block[p] & 0xFF) | (block[p + 1] & 0xFF) << 8 | (block[p + 2] & 0xFF) << 16 | (block[p + 3] & 0xFF) << 24;
        }
        int[] v = new int[16];
        System.arraycopy(h, 0, v, 0, 8);
        System.arraycopy(IV, 0, v, 8, 8);
        v[12] ^= (int) counter;
        v[13] ^= (int) (counter >>> 32);
        if (last) v[14] = ~v[14];
        for (int r = 0; r < 10; r++) {
            byte[] s = SIGMA[r];
            g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
    }

    private static void g(int[] v, int a, int b, int c, int d, int x, int y) {
        v[a] = v[a] + v[b] + x;
        v[d] = Integer.rotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = Integer.rotateRight(v[b] ^ v[c], 12);
        v[a] = v[a] + v[b] + y;
        v[d] = Integer.rotateRight(v[d] ^ v[a], 8);
        v[c] = v[c] + v[d];
        v[b] = Integer.rotateRight(v[b] ^ v[c], 7);
    }
}
