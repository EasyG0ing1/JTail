package com.simtechdata.jtail;

import static org.junit.jupiter.api.Assertions.*;

import com.simtechdata.jtail.crypto.NaClBox;
import com.simtechdata.jtail.crypto.X25519;
import com.simtechdata.jtail.filter.PacketFilter;
import com.simtechdata.jtail.http2.Hpack;
import com.simtechdata.jtail.json.Json;
import com.simtechdata.jtail.magicsock.Disco;
import com.simtechdata.jtail.magicsock.Stun;
import com.simtechdata.jtail.netstack.IpPacket;
import com.simtechdata.jtail.netstack.Netstack;
import com.simtechdata.jtail.tailcfg.FilterRule;
import com.simtechdata.jtail.tailcfg.IpPrefix;
import com.simtechdata.jtail.wg.WgDevice;
import java.io.IOException;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** Every wire parser must survive arbitrary garbage without throwing unexpected exceptions or hanging. */
class RobustnessTest {
    static final Random R = new Random(1234);

    static byte[] garbage(int max) {
        byte[] b = new byte[R.nextInt(max + 1)];
        R.nextBytes(b);
        return b;
    }

    static byte[] mutate(byte[] src) {
        byte[] b = src.clone();
        int flips = 1 + R.nextInt(4);
        for (int i = 0; i < flips && b.length > 0; i++) b[R.nextInt(b.length)] ^= (byte) (1 << R.nextInt(8));
        if (R.nextInt(5) == 0 && b.length > 1) return java.util.Arrays.copyOf(b, R.nextInt(b.length));
        return b;
    }

    @Test @Timeout(60)
    void ipAndTransportParsersNeverThrow() {
        for (int i = 0; i < 20000; i++) {
            byte[] g = garbage(200);
            if (g.length > 0 && R.nextBoolean()) g[0] = (byte) (R.nextBoolean() ? 0x45 : 0x60);
            IpPacket.parse(g);
            Stun.looksLikeStun(g);
            Stun.parseBindingResponse(g);
            Disco.looksLikeDisco(g);
            Disco.parse(g);
        }
    }

    @Test @Timeout(60)
    void hpackAndJsonRejectGarbageCleanly() {
        for (int i = 0; i < 5000; i++) {
            byte[] g = garbage(100);
            try { new Hpack.Decoder(4096).decode(g); } catch (IOException expected) { /* malformed block */ }
            try { Json.parse(new String(g, java.nio.charset.StandardCharsets.ISO_8859_1)); } catch (IOException expected) { }
        }
    }

    @Test @Timeout(120)
    void netstackSurvivesRandomAndMutatedPackets() throws Exception {
        byte[] ip = {100, 64, 0, 1};
        try (Netstack ns = new Netstack(List.of(ip), p -> { }, 1280)) {
            ns.listenTcp(80);
            ns.bindUdp(53);
            // a valid-looking SYN, then mutations of it, plus pure noise addressed to us
            byte[] syn = com.simtechdata.jtail.netstack.TestPackets.tcpSyn(new byte[]{100, 64, 0, 2}, ip, 40000, 80);
            for (int i = 0; i < 30000; i++) {
                byte[] p = (i % 3 == 0) ? garbage(120) : mutate(syn);
                if (p.length > 20 && i % 3 == 0) { p[0] = 0x45; System.arraycopy(ip, 0, p, 16, 4); }
                ns.deliver(p);
            }
        }
    }

    @Test @Timeout(120)
    void wireguardDeviceSurvivesGarbageAndMutatedHandshakes() throws Exception {
        byte[] privA = X25519.generatePrivate(), privB = X25519.generatePrivate();
        java.util.concurrent.CopyOnWriteArrayList<byte[]> sent = new java.util.concurrent.CopyOnWriteArrayList<>();
        try (WgDevice a = new WgDevice(privA, (p, d) -> sent.add(d), (p, pk) -> { });
             WgDevice b = new WgDevice(privB, (p, d) -> { }, (p, pk) -> fail("garbage must never reach the IP layer"))) {
            var peer = a.addPeer(X25519.publicKey(privB), List.of(IpPrefix.parse("100.64.0.2/32")));
            b.addPeer(X25519.publicKey(privA), List.of(IpPrefix.parse("100.64.0.1/32")));
            byte[] ipkt = new byte[40];
            ipkt[0] = 0x45; ipkt[3] = 40; System.arraycopy(new byte[]{100, 64, 0, 2}, 0, ipkt, 16, 4);
            a.sendTo(peer, ipkt);
            Thread.sleep(200);
            byte[] initiation = sent.get(0);
            for (int i = 0; i < 20000; i++) {
                b.receive(i % 2 == 0 ? garbage(200) : mutate(initiation), "x");
            }
        }
    }

    @Test @Timeout(60)
    void discoOpenRejectsForgeries() {
        byte[] privA = X25519.generatePrivate(), privB = X25519.generatePrivate();
        byte[] pubA = X25519.publicKey(privA);
        NaClBox ab = new NaClBox(privA, X25519.publicKey(privB)), ba = new NaClBox(privB, pubA);
        byte[] good = Disco.seal(pubA, ab, new Disco.Ping(new byte[12], null, 0));
        assertNotNull(Disco.open(good, ba));
        int hdr = Disco.MAGIC.length + 32; // the cleartext sender key is only a lookup hint; everything after is authenticated
        for (int i = 0; i < 5000; i++) {
            byte[] m = good.clone();
            int flips = 1 + R.nextInt(3);
            for (int f = 0; f < flips; f++) m[hdr + R.nextInt(m.length - hdr)] ^= (byte) (1 << R.nextInt(8));
            if (!java.util.Arrays.equals(m, good)) assertNull(Disco.open(m, ba), "tampered ciphertext must be rejected");
        }
    }

    @Test
    void filterHandlesMalformedRules() {
        PacketFilter f = PacketFilter.compile(List.of(new FilterRule(List.of("not-an-ip", "1.2.3.4-zzz", "*"),
                List.of(new FilterRule.DstPorts("garbage", 0, 1), new FilterRule.DstPorts("*", 80, 80)), List.of())));
        IpPacket syn = IpPacket.parse(com.simtechdata.jtail.netstack.TestPackets.tcpSyn(new byte[]{100, 64, 0, 2}, new byte[]{100, 64, 0, 1}, 5, 80));
        assertNotNull(syn);
        assertTrue(f.allowInbound(syn));
        IpPacket other = IpPacket.parse(com.simtechdata.jtail.netstack.TestPackets.tcpSyn(new byte[]{100, 64, 0, 2}, new byte[]{100, 64, 0, 1}, 5, 81));
        assertFalse(f.allowInbound(other));
    }
}
