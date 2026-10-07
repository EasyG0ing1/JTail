package com.simtechdata.jtail.netstack;

import java.util.Arrays;

/** A parsed/constructible TCP segment. */
final class TcpSegment {
    static final int FIN = 0x01, SYN = 0x02, RST = 0x04, PSH = 0x08, ACK = 0x10;

    int srcPort, dstPort, seq, ack, flags, window;
    byte[] data = new byte[0];
    int mss = -1;        // MSS option, -1 if absent
    int wscale = -1;     // window-scale option, -1 if absent

    boolean has(int f) { return (flags & f) != 0; }

    /** Sequence space consumed: data bytes plus one each for SYN and FIN. */
    int seqLen() { return data.length + (has(SYN) ? 1 : 0) + (has(FIN) ? 1 : 0); }

    /** Parses and checksum-verifies a segment; returns null if malformed. */
    static TcpSegment parse(byte[] src, byte[] dst, byte[] b) {
        if (b.length < 20) return null;
        if (!IpPacket.verifyTransport(src, dst, IpPacket.PROTO_TCP, b)) return null;
        int off = ((b[12] >> 4) & 0xF) * 4;
        if (off < 20 || off > b.length) return null;
        TcpSegment s = new TcpSegment();
        s.srcPort = ((b[0] & 0xFF) << 8) | (b[1] & 0xFF);
        s.dstPort = ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
        s.seq = i32(b, 4);
        s.ack = i32(b, 8);
        s.flags = b[13] & 0x3F;
        s.window = ((b[14] & 0xFF) << 8) | (b[15] & 0xFF);
        for (int i = 20; i < off; ) {
            int kind = b[i] & 0xFF;
            if (kind == 0) break;
            if (kind == 1) { i++; continue; }
            if (i + 1 >= off) return null;
            int len = b[i + 1] & 0xFF;
            if (len < 2 || i + len > off) return null;
            if (kind == 2 && len == 4) s.mss = ((b[i + 2] & 0xFF) << 8) | (b[i + 3] & 0xFF);
            else if (kind == 3 && len == 3) s.wscale = Math.min(b[i + 2] & 0xFF, 14);
            i += len;
        }
        s.data = off == b.length ? new byte[0] : Arrays.copyOfRange(b, off, b.length);
        return s;
    }

    private static int i32(byte[] b, int o) {
        return ((b[o] & 0xFF) << 24) | ((b[o + 1] & 0xFF) << 16) | ((b[o + 2] & 0xFF) << 8) | (b[o + 3] & 0xFF);
    }

    /** Serialises with options (MSS/wscale when set >= 0) and a valid checksum. */
    byte[] build(byte[] srcIp, byte[] dstIp) {
        int optLen = (mss >= 0 ? 4 : 0) + (wscale >= 0 ? 4 : 0); // wscale padded with a NOP
        int hdr = 20 + optLen;
        byte[] b = new byte[hdr + data.length];
        b[0] = (byte) (srcPort >> 8); b[1] = (byte) srcPort;
        b[2] = (byte) (dstPort >> 8); b[3] = (byte) dstPort;
        putI32(b, 4, seq);
        putI32(b, 8, ack);
        b[12] = (byte) ((hdr / 4) << 4);
        b[13] = (byte) flags;
        b[14] = (byte) (window >> 8); b[15] = (byte) window;
        int o = 20;
        if (mss >= 0) { b[o++] = 2; b[o++] = 4; b[o++] = (byte) (mss >> 8); b[o++] = (byte) mss; }
        if (wscale >= 0) { b[o++] = 1; b[o++] = 3; b[o++] = 3; b[o++] = (byte) wscale; }
        System.arraycopy(data, 0, b, hdr, data.length);
        int c = IpPacket.transportChecksum(srcIp, dstIp, IpPacket.PROTO_TCP, b);
        b[16] = (byte) (c >> 8); b[17] = (byte) c;
        return b;
    }

    private static void putI32(byte[] b, int o, int v) {
        b[o] = (byte) (v >>> 24); b[o + 1] = (byte) (v >>> 16); b[o + 2] = (byte) (v >>> 8); b[o + 3] = (byte) v;
    }
}
