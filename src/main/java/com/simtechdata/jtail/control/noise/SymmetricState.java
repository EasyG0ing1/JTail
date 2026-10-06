package com.simtechdata.jtail.control.noise;

import com.simtechdata.jtail.crypto.Blake2s;
import com.simtechdata.jtail.crypto.ChaCha20Poly1305;
import com.simtechdata.jtail.crypto.Hmac;
import com.simtechdata.jtail.crypto.X25519;
import java.nio.charset.StandardCharsets;
import javax.crypto.AEADBadTagException;

/** Noise symmetric state for Noise_IK_25519_ChaChaPoly_BLAKE2s, ported from tailscale control/controlbase. */
final class SymmetricState {
    static final String PROTOCOL_NAME = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
    private static final byte[] ZERO_NONCE = new byte[ChaCha20Poly1305.NONCE_SIZE];

    byte[] h;
    byte[] ck;
    private boolean finished;

    SymmetricState() {
        h = Blake2s.hash(PROTOCOL_NAME.getBytes(StandardCharsets.US_ASCII));
        ck = h.clone();
    }

    void mixHash(byte[] data) {
        check();
        h = Blake2s.hash(h, data);
    }

    /** MixKey(X25519(priv, pub)); returns the single-use AEAD for the next encrypted handshake field. */
    ChaCha20Poly1305 mixDH(byte[] priv, byte[] pub) {
        check();
        byte[][] out = Hmac.hkdf(ck, X25519.scalarMult(priv, pub), 2);
        ck = out[0];
        return new ChaCha20Poly1305(out[1]);
    }

    byte[] encryptAndHash(ChaCha20Poly1305 c, byte[] plaintext) {
        check();
        byte[] ct = c.seal(ZERO_NONCE, plaintext, h);
        mixHash(ct);
        return ct;
    }

    byte[] decryptAndHash(ChaCha20Poly1305 c, byte[] ciphertext) throws AEADBadTagException {
        check();
        byte[] pt = c.open(ZERO_NONCE, ciphertext, h);
        mixHash(ciphertext);
        return pt;
    }

    /** Returns {c1, c2}; the state cannot be used afterwards. */
    ChaCha20Poly1305[] split() {
        check();
        finished = true;
        byte[][] k = Hmac.hkdf(ck, new byte[0], 2);
        return new ChaCha20Poly1305[]{new ChaCha20Poly1305(k[0]), new ChaCha20Poly1305(k[1])};
    }

    private void check() {
        if (finished) throw new IllegalStateException("symmetric state used after split");
    }
}
