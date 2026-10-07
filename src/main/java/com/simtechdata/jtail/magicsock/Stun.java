package com.simtechdata.jtail.magicsock;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.util.Arrays;

/** Minimal STUN (RFC 5389) binding client pieces: build a request, parse the mapped address from a response. */
public final class Stun {
    private Stun() {}

    private static final int MAGIC_COOKIE = 0x2112A442;
    private static final SecureRandom RNG = new SecureRandom();

    public static byte[] newTxId() {
        byte[] t = new byte[12];
        RNG.nextBytes(t);
        return t;
    }

    public static byte[] bindingRequest(byte[] txId) {
        byte[] b = new byte[20];
        b[1] = 0x01; // Binding Request
        b[4] = (byte) (MAGIC_COOKIE >>> 24); b[5] = (byte) (MAGIC_COOKIE >>> 16);
        b[6] = (byte) (MAGIC_COOKIE >>> 8); b[7] = (byte) MAGIC_COOKIE;
        System.arraycopy(txId, 0, b, 8, 12);
        return b;
    }

    /** True if the datagram has the shape of a STUN message (so it is not WireGuard or disco). */
    public static boolean looksLikeStun(byte[] p) {
        return p.length >= 20 && (p[0] & 0xC0) == 0 && ((p[4] & 0xFF) << 24 | (p[5] & 0xFF) << 16 | (p[6] & 0xFF) << 8 | (p[7] & 0xFF)) == MAGIC_COOKIE;
    }

    public static byte[] txId(byte[] p) { return Arrays.copyOfRange(p, 8, 20); }

    /** Extracts the (XOR-)MAPPED-ADDRESS of a Binding Success response, or null. */
    public static InetSocketAddress parseBindingResponse(byte[] p) {
        if (!looksLikeStun(p) || p[0] != 0x01 || p[1] != 0x01) return null;
        int msgLen = ((p[2] & 0xFF) << 8) | (p[3] & 0xFF);
        if (20 + msgLen > p.length) return null;
        int off = 20;
        InetSocketAddress mapped = null;
        while (off + 4 <= 20 + msgLen) {
            int type = ((p[off] & 0xFF) << 8) | (p[off + 1] & 0xFF);
            int len = ((p[off + 2] & 0xFF) << 8) | (p[off + 3] & 0xFF);
            int v = off + 4;
            if (v + len > p.length) return null;
            if ((type == 0x0020 || type == 0x0001) && len >= 8) {
                boolean xor = type == 0x0020;
                int family = p[v + 1] & 0xFF;
                int port = ((p[v + 2] & 0xFF) << 8) | (p[v + 3] & 0xFF);
                if (xor) port ^= MAGIC_COOKIE >>> 16;
                byte[] ip = Arrays.copyOfRange(p, v + 4, v + 4 + (family == 1 ? 4 : 16));
                if (family != 1 && family != 2 || ip.length != (family == 1 ? 4 : 16) || v + 4 + ip.length > p.length) return null;
                if (xor) {
                    byte[] mask = new byte[16];
                    mask[0] = (byte) (MAGIC_COOKIE >>> 24); mask[1] = (byte) (MAGIC_COOKIE >>> 16);
                    mask[2] = (byte) (MAGIC_COOKIE >>> 8); mask[3] = (byte) MAGIC_COOKIE;
                    System.arraycopy(p, 8, mask, 4, 12);
                    for (int i = 0; i < ip.length; i++) ip[i] ^= mask[i];
                }
                try {
                    InetSocketAddress a = new InetSocketAddress(InetAddress.getByAddress(ip), port);
                    if (xor) return a; // XOR-MAPPED-ADDRESS wins over the legacy attribute
                    mapped = a;
                } catch (UnknownHostException e) {
                    return null;
                }
            }
            off = v + ((len + 3) & ~3);
        }
        return mapped;
    }
}
