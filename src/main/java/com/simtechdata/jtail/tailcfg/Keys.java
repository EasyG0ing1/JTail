package com.simtechdata.jtail.tailcfg;

import com.simtechdata.jtail.crypto.Hex;
import java.util.Arrays;

/** Text forms of Tailscale public keys as they appear in JSON ({@code nodekey:<64 hex>}, etc.). */
public final class Keys {
    public static final String NODE = "nodekey:", MACHINE = "mkey:", DISCO = "discokey:", NL = "nlpub:";
    private Keys() {}

    public static String encode(String prefix, byte[] key) {
        if (key == null) key = new byte[32];
        return prefix + Hex.of(key);
    }

    /** Decodes a typed key; returns null for empty or all-zero (Go's zero value) keys. */
    public static byte[] decode(String prefix, String s) {
        if (s == null || s.isEmpty()) return null;
        if (!s.startsWith(prefix) || s.length() != prefix.length() + 64) {
            throw new IllegalArgumentException("malformed key " + s + ", want " + prefix + "<64 hex>");
        }
        byte[] k = Hex.parse(s.substring(prefix.length()));
        return Arrays.equals(k, new byte[32]) ? null : k;
    }
}
