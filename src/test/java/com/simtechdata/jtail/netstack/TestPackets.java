package com.simtechdata.jtail.netstack;

/** Builds raw packets for tests; lives in the netstack package to reach package-private segment helpers. */
public final class TestPackets {
    private TestPackets() {}

    public static byte[] tcpSyn(byte[] src, byte[] dst, int sport, int dport) {
        TcpSegment s = new TcpSegment();
        s.srcPort = sport; s.dstPort = dport; s.seq = 1000; s.flags = TcpSegment.SYN; s.window = 65535; s.mss = 1240; s.wscale = 3;
        return IpPacket.build(src, dst, IpPacket.PROTO_TCP, s.build(src, dst));
    }
}
