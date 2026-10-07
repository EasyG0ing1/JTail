package com.simtechdata.jtail.state;

import com.simtechdata.jtail.crypto.Hex;

/** Tailscale's text encoding for keys: a type prefix and 64 hex characters (e.g. {@code nodekey:ab12...}). */
public final class KeyText {
    public static final String MACHINE_PUBLIC = "mkey:";
    public static final String MACHINE_PRIVATE = "privkey:";
    public static final String NODE_PUBLIC = "nodekey:";
    public static final String DISCO_PUBLIC = "discokey:";

    private KeyText() {}

    public static String encode(String prefix, byte[] key32) {
        if (key32.length != 32) throw new IllegalArgumentException("key must be 32 bytes");
        return prefix + Hex.of(key32);
    }

    public static byte[] decode(String prefix, String text) {
        if (text == null || !text.startsWith(prefix) || text.length() != prefix.length() + 64) {
            throw new IllegalArgumentException("malformed key, expected " + prefix + "<64 hex>");
        }
        return Hex.parse(text.substring(prefix.length()));
    }
}
