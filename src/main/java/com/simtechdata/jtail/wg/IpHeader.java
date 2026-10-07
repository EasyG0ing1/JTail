package com.simtechdata.jtail.wg;

import java.util.Arrays;

/** Minimal IPv4/IPv6 header peeking used for cryptokey routing. */
public final class IpHeader {
    private IpHeader() {}

    public static int version(byte[] p) { return p.length == 0 ? 0 : (p[0] >> 4) & 0xF; }

    public static byte[] src(byte[] p) {
        return switch (version(p)) {
            case 4 -> p.length >= 20 ? Arrays.copyOfRange(p, 12, 16) : null;
            case 6 -> p.length >= 40 ? Arrays.copyOfRange(p, 8, 24) : null;
            default -> null;
        };
    }

    public static byte[] dst(byte[] p) {
        return switch (version(p)) {
            case 4 -> p.length >= 20 ? Arrays.copyOfRange(p, 16, 20) : null;
            case 6 -> p.length >= 40 ? Arrays.copyOfRange(p, 24, 40) : null;
            default -> null;
        };
    }

    /** Removes WireGuard's zero padding using the IP length field; returns null if the packet is malformed. */
    public static byte[] trim(byte[] p) {
        int total;
        switch (version(p)) {
            case 4 -> {
                if (p.length < 20) return null;
                total = ((p[2] & 0xFF) << 8) | (p[3] & 0xFF);
            }
            case 6 -> {
                if (p.length < 40) return null;
                total = 40 + (((p[4] & 0xFF) << 8) | (p[5] & 0xFF));
            }
            default -> { return null; }
        }
        if (total < 20 || total > p.length) return null;
        return total == p.length ? p : Arrays.copyOf(p, total);
    }
}
