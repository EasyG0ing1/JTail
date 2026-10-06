package com.simtechdata.jtail.crypto;

import java.util.HexFormat;

/** Tiny helpers shared by tests and key text encodings. */
public final class Hex {
    private Hex() {}
    public static String of(byte[] b) { return HexFormat.of().formatHex(b); }
    public static byte[] parse(String s) { return HexFormat.of().parseHex(s); }
}
