package com.simtechdata.jtail.crypto;

import static org.junit.jupiter.api.Assertions.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/** Test vectors were generated with golang.org/x/crypto/nacl/box (what Tailscale itself uses). */
class NaClBoxTest {
    @Test
    void matchesGoNaClBoxVectors() throws Exception {
        byte[] sk1 = null, pk2 = null, nonce = null, sk2 = null, pk1 = null;
        int checked = 0;
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                getClass().getResourceAsStream("/nacl-vectors.txt")))) {
            String line;
            while ((line = r.readLine()) != null) {
                String[] f = line.split(" ", -1);
                switch (f[0]) {
                    case "SK1" -> sk1 = Hex.parse(f[1]);
                    case "PK1" -> pk1 = Hex.parse(f[1]);
                    case "SK2" -> sk2 = Hex.parse(f[1]);
                    case "PK2" -> pk2 = Hex.parse(f[1]);
                    case "NONCE" -> nonce = Hex.parse(f[1]);
                    case "V" -> {
                        byte[] msg = Hex.parse(f[1]), ct = Hex.parse(f[2]);
                        // sender: sk1 -> pk2; receiver: sk2 <- pk1 (box is symmetric in its shared key)
                        assertArrayEquals(ct, new NaClBox(sk1, pk2).seal(nonce, msg), "seal len=" + msg.length);
                        assertArrayEquals(msg, new NaClBox(sk2, pk1).open(nonce, ct), "open len=" + msg.length);
                        checked++;
                    }
                    default -> { }
                }
            }
        }
        assertTrue(checked >= 10, "vectors checked: " + checked);
    }

    @Test
    void rejectsTamperedAndWrongKey() {
        byte[] a = X25519.generatePrivate(), b = X25519.generatePrivate();
        NaClBox ab = new NaClBox(a, X25519.publicKey(b));
        byte[] sealed = ab.sealWithNonce("disco payload".getBytes());
        assertArrayEquals("disco payload".getBytes(), new NaClBox(b, X25519.publicKey(a)).openWithNonce(sealed));
        byte[] bad = sealed.clone();
        bad[bad.length - 1] ^= 1;
        assertNull(new NaClBox(b, X25519.publicKey(a)).openWithNonce(bad));
        assertNull(new NaClBox(X25519.generatePrivate(), X25519.publicKey(a)).openWithNonce(sealed));
        assertNull(ab.openWithNonce(Arrays.copyOf(sealed, 20)));
    }
}
