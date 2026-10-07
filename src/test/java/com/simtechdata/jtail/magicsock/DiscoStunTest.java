package com.simtechdata.jtail.magicsock;

import static org.junit.jupiter.api.Assertions.*;

import com.simtechdata.jtail.crypto.Hex;
import com.simtechdata.jtail.crypto.NaClBox;
import com.simtechdata.jtail.crypto.X25519;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class DiscoStunTest {
    private static Map<String, byte[]> vectors() throws Exception {
        Map<String, byte[]> m = new HashMap<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(DiscoStunTest.class.getResourceAsStream("/disco-vectors.txt")))) {
            String l;
            while ((l = r.readLine()) != null) { String[] f = l.split(" "); m.put(f[0], Hex.parse(f[1])); }
        }
        return m;
    }

    @Test
    void marshalMatchesGoDiscoPackage() throws Exception {
        Map<String, byte[]> v = vectors();
        byte[] tx = Hex.parse("0102030405060708090a0b0c");
        assertArrayEquals(v.get("PING"), Disco.marshal(new Disco.Ping(tx, null, 0)));
        assertArrayEquals(v.get("PINGKEY"), Disco.marshal(new Disco.Ping(tx, v.get("NK"), 0)));
        assertArrayEquals(v.get("PINGPAD"), Disco.marshal(new Disco.Ping(tx, null, 5)));
        assertArrayEquals(v.get("PONG4"), Disco.marshal(new Disco.Pong(tx, new InetSocketAddress("1.2.3.4", 5678))));
        assertArrayEquals(v.get("PONG6"), Disco.marshal(new Disco.Pong(tx, new InetSocketAddress("2001:db8::1", 41641))));
        assertArrayEquals(v.get("CMM"), Disco.marshal(new Disco.CallMeMaybe(List.of(
                new InetSocketAddress("10.0.0.1", 41641), new InetSocketAddress("fd7a::5", 1234)))));
    }

    @Test
    void parsesGoGeneratedMessages() throws Exception {
        Map<String, byte[]> v = vectors();
        var ping = (Disco.Ping) Disco.parse(v.get("PINGKEY"));
        assertArrayEquals(v.get("NK"), ping.nodeKey());
        assertEquals(0, ping.padding());
        assertEquals(5, ((Disco.Ping) Disco.parse(v.get("PINGPAD"))).padding());
        var pong = (Disco.Pong) Disco.parse(v.get("PONG4"));
        assertEquals("/1.2.3.4", pong.src().getAddress().toString());
        assertEquals(5678, pong.src().getPort());
        var cmm = (Disco.CallMeMaybe) Disco.parse(v.get("CMM"));
        assertEquals(2, cmm.endpoints().size());
        assertEquals(1234, cmm.endpoints().get(1).getPort());
        assertNull(Disco.parse(new byte[1]));
    }

    @Test
    void envelopeRoundTrip() {
        byte[] privA = X25519.generatePrivate(), privB = X25519.generatePrivate();
        byte[] pubA = X25519.publicKey(privA), pubB = X25519.publicKey(privB);
        byte[] pkt = Disco.seal(pubA, new NaClBox(privA, pubB), new Disco.Ping(new byte[12], null, 0));
        assertTrue(Disco.looksLikeDisco(pkt));
        assertArrayEquals(pubA, Disco.source(pkt));
        assertInstanceOf(Disco.Ping.class, Disco.open(pkt, new NaClBox(privB, pubA)));
        assertNull(Disco.open(pkt, new NaClBox(privB, pubB)), "wrong key must fail");
        assertFalse(Disco.looksLikeDisco(new byte[100]));
    }

    @Test
    void stunRfc5769MappedAddress() {
        // RFC 5769 section 2.2 sample IPv4 response (XOR-MAPPED-ADDRESS = 192.0.2.1:32853), integrity/fingerprint omitted
        byte[] p = Hex.parse("0101000c2112a442b7e7a701bc34d686fa87dfae" + "0020000800 01a147e112a643".replace(" ", ""));
        InetSocketAddress a = Stun.parseBindingResponse(p);
        assertNotNull(a);
        assertEquals("192.0.2.1", a.getAddress().getHostAddress());
        assertEquals(32853, a.getPort());
        byte[] req = Stun.bindingRequest(new byte[12]);
        assertTrue(Stun.looksLikeStun(req));
        assertNull(Stun.parseBindingResponse(req));
    }
}
