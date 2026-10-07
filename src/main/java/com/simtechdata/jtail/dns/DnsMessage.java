package com.simtechdata.jtail.dns;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/** Just enough DNS (RFC 1035) to ask a resolver for A/AAAA records and read the answers. */
public final class DnsMessage {
    private DnsMessage() {}

    public static final int TYPE_A = 1, TYPE_AAAA = 28;
    private static final SecureRandom RNG = new SecureRandom();

    /** A parsed answer set. {@code rcode} 0 = success, 3 = NXDOMAIN. */
    public record Response(int id, int rcode, List<InetAddress> addresses) {}

    public static int newId() { return RNG.nextInt(0x10000); }

    public static byte[] query(int id, String name, int qtype) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(id >> 8); o.write(id);
        o.write(0x01); o.write(0x00);       // RD
        o.write(0); o.write(1);             // QDCOUNT
        o.write(0); o.write(0); o.write(0); o.write(0); o.write(0); o.write(0);
        String n = name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
        for (String label : n.split("\\.")) {
            byte[] b = label.getBytes(StandardCharsets.US_ASCII);
            if (b.length == 0 || b.length > 63) throw new IllegalArgumentException("bad DNS label in " + name);
            o.write(b.length);
            o.writeBytes(b);
        }
        o.write(0);
        o.write(qtype >> 8); o.write(qtype);
        o.write(0); o.write(1);             // IN
        return o.toByteArray();
    }

    /** Parses a response; returns null if it is malformed or not a response. */
    public static Response parse(byte[] m) {
        try {
            if (m.length < 12) return null;
            int id = u16(m, 0);
            int flags = u16(m, 2);
            if ((flags & 0x8000) == 0) return null;
            int rcode = flags & 0xF;
            int qd = u16(m, 4), an = u16(m, 6);
            int pos = 12;
            for (int i = 0; i < qd; i++) { pos = skipName(m, pos); pos += 4; }
            List<InetAddress> out = new ArrayList<>();
            for (int i = 0; i < an; i++) {
                pos = skipName(m, pos);
                if (pos + 10 > m.length) return null;
                int type = u16(m, pos);
                int rdlen = u16(m, pos + 8);
                pos += 10;
                if (pos + rdlen > m.length) return null;
                if ((type == TYPE_A && rdlen == 4) || (type == TYPE_AAAA && rdlen == 16)) {
                    out.add(InetAddress.getByAddress(java.util.Arrays.copyOfRange(m, pos, pos + rdlen)));
                }
                pos += rdlen;
            }
            return new Response(id, rcode, out);
        } catch (RuntimeException | UnknownHostException e) {
            return null;
        }
    }

    private static int u16(byte[] m, int o) { return ((m[o] & 0xFF) << 8) | (m[o + 1] & 0xFF); }

    /** Skips a possibly-compressed name, returning the offset just past it. */
    private static int skipName(byte[] m, int pos) throws IllegalArgumentException {
        int steps = 0;
        while (true) {
            if (pos >= m.length || ++steps > 128) throw new IllegalArgumentException("bad name");
            int len = m[pos] & 0xFF;
            if (len == 0) return pos + 1;
            if ((len & 0xC0) == 0xC0) return pos + 2;       // compression pointer ends the name in place
            pos += 1 + len;
        }
    }
}
