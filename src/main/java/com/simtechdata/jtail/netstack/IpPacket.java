package com.simtechdata.jtail.netstack;

import java.util.Arrays;

/** IPv4/IPv6 packet parsing and construction, plus the Internet checksum used by IP, ICMP, TCP and UDP. */
public final class IpPacket {
    public static final int PROTO_ICMP = 1, PROTO_TCP = 6, PROTO_UDP = 17, PROTO_ICMPV6 = 58;

    public final int version;
    public final byte[] src, dst;
    public final int protocol;
    public final byte[] payload;   // transport payload (extension headers are not supported and rejected)
    public final int ttl;

    private IpPacket(int version, byte[] src, byte[] dst, int protocol, byte[] payload, int ttl) {
        this.version = version; this.src = src; this.dst = dst; this.protocol = protocol; this.payload = payload; this.ttl = ttl;
    }

    /** Parses and validates a packet; returns null for malformed, fragmented or unsupported packets. */
    public static IpPacket parse(byte[] p) {
        if (p.length < 1) return null;
        int v = (p[0] >> 4) & 0xF;
        if (v == 4) {
            if (p.length < 20) return null;
            int ihl = (p[0] & 0xF) * 4;
            int total = ((p[2] & 0xFF) << 8) | (p[3] & 0xFF);
            if (ihl < 20 || total < ihl || total > p.length) return null;
            int fragField = ((p[6] & 0xFF) << 8) | (p[7] & 0xFF);
            if ((fragField & 0x3FFF) != 0) return null; // MF set or fragment offset != 0: fragments unsupported
            if (checksum(p, 0, ihl, 0) != 0) return null;
            return new IpPacket(4, Arrays.copyOfRange(p, 12, 16), Arrays.copyOfRange(p, 16, 20), p[9] & 0xFF,
                    Arrays.copyOfRange(p, ihl, total), p[8] & 0xFF);
        } else if (v == 6) {
            if (p.length < 40) return null;
            int plen = ((p[4] & 0xFF) << 8) | (p[5] & 0xFF);
            if (40 + plen > p.length) return null;
            return new IpPacket(6, Arrays.copyOfRange(p, 8, 24), Arrays.copyOfRange(p, 24, 40), p[6] & 0xFF,
                    Arrays.copyOfRange(p, 40, 40 + plen), p[7] & 0xFF);
        }
        return null;
    }

    /** Builds a complete IP packet around {@code transport} (which must already carry a valid checksum). */
    public static byte[] build(byte[] src, byte[] dst, int protocol, byte[] transport) {
        if (src.length == 4) {
            byte[] p = new byte[20 + transport.length];
            p[0] = 0x45;
            p[2] = (byte) (p.length >> 8);
            p[3] = (byte) p.length;
            p[6] = 0x40; // DF
            p[8] = 64;
            p[9] = (byte) protocol;
            System.arraycopy(src, 0, p, 12, 4);
            System.arraycopy(dst, 0, p, 16, 4);
            int c = checksum(p, 0, 20, 0);
            p[10] = (byte) (c >> 8);
            p[11] = (byte) c;
            System.arraycopy(transport, 0, p, 20, transport.length);
            return p;
        }
        byte[] p = new byte[40 + transport.length];
        p[0] = 0x60;
        p[4] = (byte) (transport.length >> 8);
        p[5] = (byte) transport.length;
        p[6] = (byte) protocol;
        p[7] = 64;
        System.arraycopy(src, 0, p, 8, 16);
        System.arraycopy(dst, 0, p, 24, 16);
        System.arraycopy(transport, 0, p, 40, transport.length);
        return p;
    }

    /** One's-complement sum of {@code len} bytes folded to 16 bits and inverted, seeded with {@code initial}. */
    public static int checksum(byte[] b, int off, int len, long initial) {
        long s = initial;
        int i = off, end = off + len;
        for (; i + 1 < end; i += 2) s += ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);
        if (i < end) s += (b[i] & 0xFF) << 8;
        while ((s >>> 16) != 0) s = (s & 0xFFFF) + (s >>> 16);
        return (int) (~s & 0xFFFF);
    }

    /** Unfolded pseudo-header sum for TCP/UDP/ICMPv6 checksums. */
    public static long pseudoHeader(byte[] src, byte[] dst, int proto, int length) {
        long s = 0;
        for (int i = 0; i < src.length; i += 2) s += ((src[i] & 0xFF) << 8) | (src[i + 1] & 0xFF);
        for (int i = 0; i < dst.length; i += 2) s += ((dst[i] & 0xFF) << 8) | (dst[i + 1] & 0xFF);
        s += proto;
        s += length;
        return s;
    }

    /** Computes the transport checksum over {@code seg} (whose checksum field must be zero). */
    public static int transportChecksum(byte[] src, byte[] dst, int proto, byte[] seg) {
        return checksum(seg, 0, seg.length, pseudoHeader(src, dst, proto, seg.length));
    }

    /** True if {@code seg}'s embedded checksum verifies against the pseudo-header. */
    public static boolean verifyTransport(byte[] src, byte[] dst, int proto, byte[] seg) {
        return checksum(seg, 0, seg.length, pseudoHeader(src, dst, proto, seg.length)) == 0;
    }
}
