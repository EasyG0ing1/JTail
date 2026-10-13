package com.simtechdata.jtail.dns;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class DnsMessageTest {
    /** A response to the question "a.b" with one answer that uses a compression pointer to the question name. */
    static byte[] response(int id, int flags, int type, byte[] rdata) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(id >> 8); o.write(id);
        o.write(flags >> 8); o.write(flags);
        o.write(0); o.write(1);                 // QDCOUNT
        o.write(0); o.write(rdata == null ? 0 : 1); // ANCOUNT
        o.write(0); o.write(0); o.write(0); o.write(0);
        o.write(1); o.writeBytes("a".getBytes()); o.write(1); o.writeBytes("b".getBytes()); o.write(0);
        o.write(0); o.write(1); o.write(0); o.write(1);    // QTYPE A, QCLASS IN
        if (rdata != null) {
            o.write(0xC0); o.write(12);                    // pointer back to the question name
            o.write(type >> 8); o.write(type);
            o.write(0); o.write(1);
            o.write(0); o.write(0); o.write(0); o.write(60);
            o.write(0); o.write(rdata.length);
            o.writeBytes(rdata);
        }
        return o.toByteArray();
    }

    @Test
    void queryEncodesHeaderAndLabels() {
        byte[] q = DnsMessage.query(0xBEEF, "example.com.", DnsMessage.TYPE_AAAA);
        assertEquals(0xBE, q[0] & 0xFF);
        assertEquals(0xEF, q[1] & 0xFF);
        assertEquals(0x01, q[2], "recursion desired");
        assertEquals(1, q[5], "one question");
        assertEquals(7, q[12], "first label length");
        assertEquals("example", new String(q, 13, 7, StandardCharsets.US_ASCII));
        assertEquals(0, q[q.length - 5], "root label terminates the name");
        assertEquals(0, q[q.length - 4]);
        assertEquals(28, q[q.length - 3], "QTYPE AAAA");
    }

    @Test
    void queryRejectsEmptyAndOversizedLabels() {
        assertThrows(IllegalArgumentException.class, () -> DnsMessage.query(1, "a..b", DnsMessage.TYPE_A));
        assertThrows(IllegalArgumentException.class, () -> DnsMessage.query(1, "x".repeat(64) + ".com", DnsMessage.TYPE_A));
    }

    @Test
    void parsesAddressAnswersThroughCompressionPointers() throws Exception {
        DnsMessage.Response r = DnsMessage.parse(response(7, 0x8180, DnsMessage.TYPE_A, new byte[]{100, 64, 0, 9}));
        assertNotNull(r);
        assertEquals(7, r.id());
        assertEquals(0, r.rcode());
        assertEquals(1, r.addresses().size());
        assertEquals("100.64.0.9", r.addresses().get(0).getHostAddress());

        byte[] v6 = new byte[16];
        v6[0] = (byte) 0xfd; v6[15] = 1;
        DnsMessage.Response r6 = DnsMessage.parse(response(8, 0x8180, DnsMessage.TYPE_AAAA, v6));
        assertEquals(1, r6.addresses().size());
        assertTrue(r6.addresses().get(0) instanceof java.net.Inet6Address);
    }

    @Test
    void nxdomainAndEmptyAnswersParse() {
        DnsMessage.Response nx = DnsMessage.parse(response(9, 0x8183, 0, null));
        assertEquals(3, nx.rcode());
        assertTrue(nx.addresses().isEmpty());
    }

    @Test
    void ignoresRecordsOfOtherTypesAndWrongLengths() {
        DnsMessage.Response r = DnsMessage.parse(response(10, 0x8180, 16 /* TXT */, new byte[]{3, 'a', 'b', 'c'}));
        assertTrue(r.addresses().isEmpty());
        DnsMessage.Response bad = DnsMessage.parse(response(11, 0x8180, DnsMessage.TYPE_A, new byte[]{1, 2, 3}));
        assertTrue(bad.addresses().isEmpty(), "an A record must carry exactly four bytes");
    }

    @Test
    void rejectsQueriesTruncatedAndTruncatedAnswers() {
        assertNull(DnsMessage.parse(new byte[11]), "shorter than a header");
        assertNull(DnsMessage.parse(DnsMessage.query(1, "a.b", DnsMessage.TYPE_A)), "a query is not a response");
        byte[] full = response(12, 0x8180, DnsMessage.TYPE_A, new byte[]{1, 2, 3, 4});
        for (int cut = 12; cut < full.length; cut++) {
            DnsMessage.Response r = DnsMessage.parse(java.util.Arrays.copyOf(full, cut));
            if (r != null) assertTrue(r.addresses().isEmpty(), "a cut at " + cut + " must not invent addresses");
        }
    }

    @Test
    void selfReferencingCompressionPointersDoNotHangOrThrow() {
        // Pointers are skipped, never followed, so a self-referencing pointer cannot loop. The result is just
        // whatever the remaining bytes decode to, or null.
        byte[] loop = response(13, 0x8180, DnsMessage.TYPE_A, new byte[]{1, 2, 3, 4});
        loop[12] = (byte) 0xC0; loop[13] = 12;
        assertDoesNotThrow(() -> DnsMessage.parse(loop));
    }

    @Test
    void parseResolverAcceptsTheSupportedForms() {
        assertEquals(new InetSocketAddress("100.64.0.2", 53), DnsResolver.parseResolver("100.64.0.2"));
        assertEquals(new InetSocketAddress("100.64.0.2", 5353), DnsResolver.parseResolver("100.64.0.2:5353"));
        InetSocketAddress v6 = DnsResolver.parseResolver("[::1]:53");
        assertEquals(53, v6.getPort());
        assertEquals("0:0:0:0:0:0:0:1", v6.getAddress().getHostAddress());
        assertNull(DnsResolver.parseResolver("https://dns.example/dns-query"), "DNS over HTTPS is not supported");
        assertNull(DnsResolver.parseResolver("not an address"));
    }
}
