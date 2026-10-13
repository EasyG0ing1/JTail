package com.simtechdata.jtail.tailcfg;

import static org.junit.jupiter.api.Assertions.*;

import com.simtechdata.jtail.json.Json;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.List;
import org.junit.jupiter.api.Test;

class NetMapTest {
    static final String KEY_A = "nodekey:" + "11".repeat(32);
    static final String KEY_B = "nodekey:" + "22".repeat(32);
    static final String DISCO_B = "discokey:" + "33".repeat(32);

    static MapResponse map(String json) throws IOException {
        return MapResponse.fromJson(Json.parseObject(json));
    }

    @Test
    void fullPeerListThenDeltasThenRemoval() throws IOException {
        NetMap nm = new NetMap();
        NetMap.Snapshot s = nm.apply(map("{\"Node\":{\"ID\":1,\"Name\":\"me.tail.example.\",\"Key\":\"" + KEY_A
                + "\",\"Addresses\":[\"100.64.0.1/32\"]},\"Peers\":[{\"ID\":2,\"Name\":\"b.tail.example.\",\"Key\":\""
                + KEY_B + "\",\"DiscoKey\":\"" + DISCO_B + "\",\"Addresses\":[\"100.64.0.2/32\"],"
                + "\"Endpoints\":[\"1.2.3.4:41641\"],\"Online\":true,\"Hostinfo\":{\"Hostname\":\"b\"}}],"
                + "\"Domain\":\"tail.example\"}"));
        assertEquals("me.tail.example.", s.self().name);
        assertEquals("tail.example", s.domain());
        assertEquals(1, s.peers().size());
        Node b = s.peers().get(0);
        assertEquals("b", b.hostname);
        assertEquals("b", b.shortName());
        assertEquals("100.64.0.2", java.net.InetAddress.getByAddress(b.ipv4()).getHostAddress());
        assertEquals(Boolean.TRUE, b.online);
        assertEquals(new InetSocketAddress("1.2.3.4", 41641), b.endpoints.get(0));
        assertSame(b, s.peerByKey(b.key));
        assertNull(s.peerByKey(new byte[32]));

        s = nm.apply(map("{\"PeersChangedPatch\":[{\"NodeID\":2,\"Online\":false,\"Endpoints\":[\"5.6.7.8:1\"],"
                + "\"DERPRegion\":9}]}"));
        assertEquals(Boolean.FALSE, s.peers().get(0).online);
        assertEquals(9, s.peers().get(0).homeDerp);
        assertEquals(new InetSocketAddress("5.6.7.8", 1), s.peers().get(0).endpoints.get(0));

        s = nm.apply(map("{\"PeersRemoved\":[2]}"));
        assertTrue(s.peers().isEmpty());
    }

    @Test
    void keepAliveChangesNothingAndOnlineChangesApply() throws IOException {
        NetMap nm = new NetMap();
        nm.apply(map("{\"Peers\":[{\"ID\":5,\"Key\":\"" + KEY_B + "\"}]}"));
        NetMap.Snapshot before = nm.snapshot();
        assertSame(before, nm.apply(map("{\"KeepAlive\":true}")));
        NetMap.Snapshot after = nm.apply(map("{\"OnlineChange\":{\"5\":true}}"));
        assertEquals(Boolean.TRUE, after.peers().get(0).online);
    }

    @Test
    void dnsConfigAndDerpMapAreRead() throws IOException {
        MapResponse r = map("{\"DNSConfig\":{\"Resolvers\":[{\"Addr\":\"100.64.0.53\"}],"
                + "\"Routes\":{\"corp.example\":[{\"Addr\":\"10.0.0.53\"}]},\"Domains\":[\"tail.example\"],"
                + "\"ExtraRecords\":[{\"Name\":\"svc.tail.example\",\"Type\":\"A\",\"Value\":\"100.64.0.7\"}]},"
                + "\"DERPMap\":{\"Regions\":{\"2\":{\"RegionID\":2,\"RegionCode\":\"ny\",\"Nodes\":[{\"Name\":\"2a\","
                + "\"RegionID\":2,\"HostName\":\"derp.example\",\"DERPPort\":8443,\"InsecureForTests\":true}]}}}}");
        DnsConfig dns = r.dnsConfig;
        assertEquals(List.of("100.64.0.53"), dns.resolvers());
        assertEquals(List.of("10.0.0.53"), dns.routes().get("corp.example"));
        assertEquals("100.64.0.7", dns.extraRecords().get(0).value());
        Derp.Node n = r.derpMap.region(2).nodes().get(0);
        assertEquals("derp.example", n.hostName());
        assertEquals(8443, n.port());
        assertTrue(n.insecureForTests(), "the flag is parsed; whether it is honoured is DerpClient's decision");
        assertEquals(443, new Derp.Node("x", 1, "h", "", "", "", 0, false, 0, false, false).port());
    }

    @Test
    void legacyDerpStringProvidesTheHomeRegion() throws IOException {
        Node n = Node.fromJson(Json.parseObject("{\"ID\":3,\"Key\":\"" + KEY_B + "\",\"DERP\":\"127.3.3.40:7\"}"));
        assertEquals(7, n.homeDerp);
        Node fromNetInfo = Node.fromJson(Json.parseObject("{\"ID\":4,\"Hostinfo\":{\"NetInfo\":{\"PreferredDERP\":11}}}"));
        assertEquals(11, fromNetInfo.homeDerp);
    }

    @Test
    void endpointParsingHandlesIpv4AndBracketedIpv6() {
        assertEquals(new InetSocketAddress("1.2.3.4", 5), Node.parseEndpoint("1.2.3.4:5"));
        assertEquals(41641, Node.parseEndpoint("[fd7a:115c:a1e0::1]:41641").getPort());
        assertThrows(IllegalArgumentException.class, () -> Node.parseEndpoint("no-port-here"));
        assertThrows(RuntimeException.class, () -> Node.parseEndpoint("1.2.3.4:notaport"));
    }

    @Test
    void keyDecodingRejectsMalformedAndTreatsZeroAsAbsent() {
        assertNull(Keys.decode(Keys.NODE, null));
        assertNull(Keys.decode(Keys.NODE, ""));
        assertNull(Keys.decode(Keys.NODE, Keys.NODE + "00".repeat(32)), "the all-zero key is Go's zero value");
        assertEquals(32, Keys.decode(Keys.NODE, KEY_A).length);
        assertEquals(0x11, Keys.decode(Keys.NODE, KEY_A)[0]);
        assertThrows(IllegalArgumentException.class, () -> Keys.decode(Keys.NODE, "mkey:" + "11".repeat(32)));
        assertThrows(IllegalArgumentException.class, () -> Keys.decode(Keys.NODE, KEY_A + "00"));
        assertEquals(Keys.NODE + "00".repeat(32), Keys.encode(Keys.NODE, null));
    }

    @Test
    void unknownPeerPatchesAreIgnored() throws IOException {
        NetMap nm = new NetMap();
        NetMap.Snapshot s = nm.apply(map("{\"PeersChangedPatch\":[{\"NodeID\":99,\"Online\":true}]}"));
        assertTrue(s.peers().isEmpty());
    }
}
