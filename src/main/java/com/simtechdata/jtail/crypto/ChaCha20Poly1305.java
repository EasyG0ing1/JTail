package com.simtechdata.jtail.crypto;

import java.security.GeneralSecurityException;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * ChaCha20-Poly1305 AEAD (RFC 8439) with explicit 12-byte nonces, backed by the JDK provider.
 * Cipher instances are cached per object and guarded by a lock, because creating one per packet dominates the cost of
 * WireGuard data-path processing. The JDK only forbids re-initialising an encryptor with an identical key+nonce pair,
 * which a correct caller never does.
 */
public final class ChaCha20Poly1305 {
    public static final int KEY_SIZE = 32;
    public static final int NONCE_SIZE = 12;
    public static final int TAG_SIZE = 16;

    private final SecretKeySpec key;
    private Cipher enc, dec;

    public ChaCha20Poly1305(byte[] key) {
        if (key.length != KEY_SIZE) throw new IllegalArgumentException("key must be 32 bytes");
        this.key = new SecretKeySpec(key, "ChaCha20");
    }

    public synchronized byte[] seal(byte[] nonce, byte[] plaintext, byte[] aad) {
        try {
            if (enc == null) enc = Cipher.getInstance("ChaCha20-Poly1305");
            enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
            if (aad != null && aad.length > 0) enc.updateAAD(aad);
            return enc.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            enc = null; // never reuse a cipher that failed mid-operation
            throw new IllegalStateException(e);
        }
    }

    /** @throws AEADBadTagException if authentication fails */
    public synchronized byte[] open(byte[] nonce, byte[] ciphertext, byte[] aad) throws AEADBadTagException {
        try {
            if (dec == null) dec = Cipher.getInstance("ChaCha20-Poly1305");
            dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(nonce));
            if (aad != null && aad.length > 0) dec.updateAAD(aad);
            return dec.doFinal(ciphertext);
        } catch (AEADBadTagException e) {
            dec = null;
            throw e;
        } catch (GeneralSecurityException e) {
            dec = null;
            throw new AEADBadTagException(e.getMessage());
        }
    }
}
