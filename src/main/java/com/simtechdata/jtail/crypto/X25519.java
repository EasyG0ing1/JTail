package com.simtechdata.jtail.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import javax.crypto.KeyAgreement;

/** X25519 (RFC 7748) over raw 32-byte keys, backed by the JDK provider. */
public final class X25519 {
    public static final int KEY_SIZE = 32;
    private static final SecureRandom RNG = new SecureRandom();
    private static final byte[] BASE = new byte[KEY_SIZE];
    static { BASE[0] = 9; }

    private X25519() {}

    /** Returns a new random private key, clamped as Curve25519 requires. */
    public static byte[] generatePrivate() {
        byte[] k = new byte[KEY_SIZE];
        RNG.nextBytes(k);
        return clamp(k);
    }

    public static byte[] clamp(byte[] k) {
        k[0] &= (byte) 248;
        k[31] &= 127;
        k[31] |= 64;
        return k;
    }

    public static byte[] publicKey(byte[] priv) { return scalarMult(priv, BASE); }

    /** Computes X25519(priv, pub). Throws if the result is the all-zero point (low-order input). */
    public static byte[] scalarMult(byte[] priv, byte[] pub) {
        try {
            KeyFactory kf = KeyFactory.getInstance("XDH");
            NamedParameterSpec spec = NamedParameterSpec.X25519;
            var privKey = kf.generatePrivate(new XECPrivateKeySpec(spec, priv.clone()));
            var pubKey = kf.generatePublic(new XECPublicKeySpec(spec, decodeU(pub)));
            KeyAgreement ka = KeyAgreement.getInstance("XDH");
            ka.init(privKey);
            ka.doPhase(pubKey, true);
            byte[] out = ka.generateSecret();
            int acc = 0;
            for (byte b : out) acc |= b;
            if (acc == 0) throw new IllegalArgumentException("X25519 produced all-zero output");
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** RFC 7748 decodeUCoordinate: little-endian, top bit of the last byte masked. */
    private static BigInteger decodeU(byte[] u) {
        byte[] be = new byte[KEY_SIZE];
        for (int i = 0; i < KEY_SIZE; i++) be[i] = u[KEY_SIZE - 1 - i];
        be[0] &= 0x7f;
        return new BigInteger(1, be);
    }
}
