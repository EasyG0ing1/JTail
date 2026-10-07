package com.simtechdata.jtail.tailcfg;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

/** An IP prefix such as {@code 100.64.0.5/32} or {@code fd7a:115c:a1e0::1/128} (Go's netip.Prefix). */
public record IpPrefix(byte[] addr, int bits) {
    public static IpPrefix parse(String s) {
        int slash = s.indexOf('/');
        String ip = slash < 0 ? s : s.substring(0, slash);
        byte[] a = parseIp(ip);
        int bits = slash < 0 ? a.length * 8 : Integer.parseInt(s.substring(slash + 1));
        if (bits < 0 || bits > a.length * 8) throw new IllegalArgumentException("bad prefix length: " + s);
        return new IpPrefix(a, bits);
    }

    /** Parses an IPv4/IPv6 literal without DNS lookups. */
    public static byte[] parseIp(String ip) {
        if (ip.isEmpty() || !(Character.digit(ip.charAt(0), 16) >= 0 || ip.charAt(0) == ':')) {
            throw new IllegalArgumentException("not an IP literal: " + ip);
        }
        try {
            if (ip.indexOf('%') > 0) ip = ip.substring(0, ip.indexOf('%'));
            return InetAddress.getByName(ip).getAddress();
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("not an IP literal: " + ip, e);
        }
    }

    public boolean isIPv4() { return addr.length == 4; }

    /** True if {@code ip} (4 or 16 bytes; 4-in-6 mapped addresses are unmapped) falls inside this prefix. */
    public boolean contains(byte[] ip) {
        if (ip.length == 16 && addr.length == 4 && isMapped(ip)) ip = Arrays.copyOfRange(ip, 12, 16);
        if (ip.length != addr.length) return false;
        int full = bits / 8;
        for (int i = 0; i < full; i++) if (ip[i] != addr[i]) return false;
        int rem = bits % 8;
        if (rem == 0) return true;
        int mask = (0xFF << (8 - rem)) & 0xFF;
        return (ip[full] & mask) == (addr[full] & mask);
    }

    private static boolean isMapped(byte[] ip) {
        for (int i = 0; i < 10; i++) if (ip[i] != 0) return false;
        return ip[10] == (byte) 0xff && ip[11] == (byte) 0xff;
    }

    public InetAddress address() {
        try { return InetAddress.getByAddress(addr); } catch (UnknownHostException e) { throw new IllegalStateException(e); }
    }

    @Override public String toString() { return address().getHostAddress() + "/" + bits; }
    @Override public boolean equals(Object o) { return o instanceof IpPrefix p && p.bits == bits && Arrays.equals(p.addr, addr); }
    @Override public int hashCode() { return Arrays.hashCode(addr) * 31 + bits; }
}
