package com.simtechdata.jtail.crypto;

import java.util.Arrays;

/** HMAC and HKDF built on BLAKE2s-256, as used by Noise_*_BLAKE2s and WireGuard. */
public final class Hmac {
    private Hmac() {}

    public static byte[] hmacBlake2s(byte[] key, byte[]... parts) {
        byte[] k = new byte[Blake2s.BLOCK_SIZE];
        if (key.length > Blake2s.BLOCK_SIZE) key = Blake2s.hash(key);
        System.arraycopy(key, 0, k, 0, key.length);
        byte[] ipad = new byte[k.length], opad = new byte[k.length];
        for (int i = 0; i < k.length; i++) {
            ipad[i] = (byte) (k[i] ^ 0x36);
            opad[i] = (byte) (k[i] ^ 0x5c);
        }
        Blake2s in = new Blake2s();
        in.update(ipad);
        for (byte[] p : parts) in.update(p);
        byte[] inner = in.digest();
        Blake2s out = new Blake2s();
        out.update(opad);
        out.update(inner);
        byte[] r = out.digest();
        Arrays.fill(k, (byte) 0);
        return r;
    }

    /** HKDF (RFC 5869) with HMAC-BLAKE2s: extract then expand {@code n} 32-byte outputs (n in 1..3 typical). */
    public static byte[][] hkdf(byte[] salt, byte[] ikm, int n) {
        byte[] prk = hmacBlake2s(salt, ikm);
        byte[][] out = new byte[n][];
        byte[] prev = new byte[0];
        for (int i = 0; i < n; i++) {
            prev = hmacBlake2s(prk, prev, new byte[]{(byte) (i + 1)});
            out[i] = prev;
        }
        return out;
    }
}
