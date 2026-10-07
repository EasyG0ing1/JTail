package com.simtechdata.jtail.crypto;

import javax.crypto.AEADBadTagException;

/** XChaCha20-Poly1305 (24-byte nonce) built from HChaCha20 and the JDK's ChaCha20-Poly1305; used by WireGuard cookies. */
public final class XChaCha20Poly1305 {
    public static final int NONCE_SIZE = 24;
    private final byte[] key;

    public XChaCha20Poly1305(byte[] key) { this.key = key.clone(); }

    /** HChaCha20 core: 20 rounds over key + 16-byte nonce, outputs words 0..3 and 12..15 (draft-irtf-cfrg-xchacha). */
    static byte[] hchacha20(byte[] key, byte[] nonce16) {
        int[] s = new int[16];
        s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) s[4 + i] = le32(key, i * 4);
        for (int i = 0; i < 4; i++) s[12 + i] = le32(nonce16, i * 4);
        for (int r = 0; r < 10; r++) {
            qr(s, 0, 4, 8, 12); qr(s, 1, 5, 9, 13); qr(s, 2, 6, 10, 14); qr(s, 3, 7, 11, 15);
            qr(s, 0, 5, 10, 15); qr(s, 1, 6, 11, 12); qr(s, 2, 7, 8, 13); qr(s, 3, 4, 9, 14);
        }
        byte[] out = new byte[32];
        int[] idx = {0, 1, 2, 3, 12, 13, 14, 15};
        for (int i = 0; i < 8; i++) {
            int v = s[idx[i]];
            out[i * 4] = (byte) v; out[i * 4 + 1] = (byte) (v >>> 8); out[i * 4 + 2] = (byte) (v >>> 16); out[i * 4 + 3] = (byte) (v >>> 24);
        }
        return out;
    }

    private static int le32(byte[] b, int o) {
        return (b[o] & 0xFF) | (b[o + 1] & 0xFF) << 8 | (b[o + 2] & 0xFF) << 16 | (b[o + 3] & 0xFF) << 24;
    }

    private static void qr(int[] s, int a, int b, int c, int d) {
        s[a] += s[b]; s[d] = Integer.rotateLeft(s[d] ^ s[a], 16);
        s[c] += s[d]; s[b] = Integer.rotateLeft(s[b] ^ s[c], 12);
        s[a] += s[b]; s[d] = Integer.rotateLeft(s[d] ^ s[a], 8);
        s[c] += s[d]; s[b] = Integer.rotateLeft(s[b] ^ s[c], 7);
    }

    private ChaCha20Poly1305 inner(byte[] nonce24, byte[] nonce12out) {
        byte[] sub = hchacha20(key, java.util.Arrays.copyOfRange(nonce24, 0, 16));
        System.arraycopy(nonce24, 16, nonce12out, 4, 8); // first 4 bytes stay zero
        return new ChaCha20Poly1305(sub);
    }

    public byte[] seal(byte[] nonce24, byte[] plaintext, byte[] aad) {
        byte[] n = new byte[12];
        return inner(nonce24, n).seal(n, plaintext, aad);
    }

    public byte[] open(byte[] nonce24, byte[] ciphertext, byte[] aad) throws AEADBadTagException {
        byte[] n = new byte[12];
        return inner(nonce24, n).open(n, ciphertext, aad);
    }
}
