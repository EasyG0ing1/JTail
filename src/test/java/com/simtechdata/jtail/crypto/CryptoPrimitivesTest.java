package com.simtechdata.jtail.crypto;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import javax.crypto.AEADBadTagException;
import org.junit.jupiter.api.Test;

class CryptoPrimitivesTest {
    @Test
    void blake2sRfc7693Abc() {
        assertEquals("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
                Hex.of(Blake2s.hash("abc".getBytes(StandardCharsets.US_ASCII))));
    }

    @Test
    void blake2sEmpty() {
        assertEquals("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9", Hex.of(Blake2s.hash()));
    }

    @Test
    void blake2sIncrementalMatchesOneShot() {
        byte[] data = new byte[1000];
        for (int i = 0; i < data.length; i++) data[i] = (byte) i;
        Blake2s b = new Blake2s();
        b.update(data, 0, 64);   // exact block boundary
        b.update(data, 64, 1);
        b.update(data, 65, 935);
        assertArrayEquals(Blake2s.hash(data), b.digest());
    }

    @Test
    void blake2sKeyedOfficialVector() {
        // Official blake2s-kat keyed vector: key = 00..1f, input = empty
        byte[] key = new byte[32];
        for (int i = 0; i < 32; i++) key[i] = (byte) i;
        assertEquals("48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49",
                Hex.of(Blake2s.hash(32, key)));
    }

    @Test
    void hmacBlake2sIsStable() {
        // Self-consistency: HMAC differs by key and by data.
        byte[] a = Hmac.hmacBlake2s(new byte[]{1}, new byte[]{2});
        assertFalse(java.util.Arrays.equals(a, Hmac.hmacBlake2s(new byte[]{2}, new byte[]{2})));
        assertFalse(java.util.Arrays.equals(a, Hmac.hmacBlake2s(new byte[]{1}, new byte[]{3})));
    }

    @Test
    void x25519Rfc7748() {
        byte[] alicePriv = Hex.parse("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] bobPriv = Hex.parse("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        byte[] alicePub = X25519.publicKey(alicePriv);
        byte[] bobPub = X25519.publicKey(bobPriv);
        assertEquals("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", Hex.of(alicePub));
        assertEquals("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", Hex.of(bobPub));
        String shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
        assertEquals(shared, Hex.of(X25519.scalarMult(alicePriv, bobPub)));
        assertEquals(shared, Hex.of(X25519.scalarMult(bobPriv, alicePub)));
    }

    @Test
    void chachaPolyRfc8439() throws Exception {
        byte[] key = Hex.parse("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        byte[] nonce = Hex.parse("070000004041424344454647");
        byte[] aad = Hex.parse("50515253c0c1c2c3c4c5c6c7");
        byte[] pt = ("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
                + "sunscreen would be it.").getBytes(StandardCharsets.US_ASCII);
        byte[] ct = new ChaCha20Poly1305(key).seal(nonce, pt, aad);
        assertEquals("1ae10b594f09e26a7e902ecbd0600691", Hex.of(java.util.Arrays.copyOfRange(ct, pt.length, ct.length)));
        assertArrayEquals(pt, new ChaCha20Poly1305(key).open(nonce, ct, aad));
        ct[0] ^= 1;
        byte[] bad = ct;
        assertThrows(AEADBadTagException.class, () -> new ChaCha20Poly1305(key).open(nonce, bad, aad));
    }

    @Test
    void hchacha20Vector() {
        byte[] key = Hex.parse("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] nonce = Hex.parse("000000090000004a0000000031415927");
        assertEquals("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc",
                Hex.of(XChaCha20Poly1305.hchacha20(key, nonce)));
    }

    @Test
    void xchachaRoundTrip() throws Exception {
        XChaCha20Poly1305 x = new XChaCha20Poly1305(new byte[32]);
        byte[] nonce = new byte[24];
        nonce[23] = 9;
        byte[] ct = x.seal(nonce, "cookie".getBytes(), "aad".getBytes());
        assertArrayEquals("cookie".getBytes(), x.open(nonce, ct, "aad".getBytes()));
        assertThrows(AEADBadTagException.class, () -> x.open(nonce, ct, "other".getBytes()));
    }

    @Test
    void cachedCipherHandlesManyNonces() throws Exception {
        ChaCha20Poly1305 c = new ChaCha20Poly1305(new byte[32]);
        for (int i = 0; i < 100; i++) {
            byte[] n = new byte[12];
            n[11] = (byte) i;
            byte[] ct = c.seal(n, new byte[]{(byte) i}, null);
            assertArrayEquals(new byte[]{(byte) i}, c.open(n, ct, null));
        }
    }
}
