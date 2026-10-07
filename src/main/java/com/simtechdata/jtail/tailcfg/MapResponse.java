package com.simtechdata.jtail.tailcfg;

import com.simtechdata.jtail.json.J;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** One message of the /machine/map stream (tailcfg.MapResponse), holding only the fields JTail consumes. */
public final class MapResponse {
    public boolean keepAlive;
    public Node node;                       // self; null = unchanged
    public Derp.Map_ derpMap;               // null = unchanged
    public List<Node> peers;                // non-empty = full replace
    public List<Node> peersChanged = new ArrayList<>();
    public List<Long> peersRemoved = new ArrayList<>();
    public List<Map<String, Object>> peersChangedPatch = new ArrayList<>();
    public Map<Long, Boolean> onlineChange = new LinkedHashMap<>();
    public DnsConfig dnsConfig;             // null = unchanged
    public String domain = "";
    public boolean hasPacketFilter;          // key present = replace "base"
    public List<FilterRule> packetFilter = new ArrayList<>();
    public Map<String, List<FilterRule>> packetFilters; // null entries (value=null) delete; "*" clears
    public Map<String, Object> pingRequest;
    public String seqHandle = "";
    public List<String> health = new ArrayList<>();
    public Map<String, Object> raw;

    public static MapResponse fromJson(Map<String, Object> m) {
        MapResponse r = new MapResponse();
        r.raw = m;
        r.keepAlive = J.bool(m, "KeepAlive");
        Map<String, Object> self = J.obj(m, "Node");
        if (self != null) r.node = Node.fromJson(self);
        Map<String, Object> dm = J.obj(m, "DERPMap");
        if (dm != null) r.derpMap = Derp.Map_.fromJson(dm);
        List<Map<String, Object>> ps = J.objects(m, "Peers");
        if (!ps.isEmpty()) { r.peers = new ArrayList<>(); for (Map<String, Object> p : ps) r.peers.add(Node.fromJson(p)); }
        for (Map<String, Object> p : J.objects(m, "PeersChanged")) r.peersChanged.add(Node.fromJson(p));
        r.peersRemoved = J.longs(m, "PeersRemoved");
        r.peersChangedPatch = J.objects(m, "PeersChangedPatch");
        Map<String, Object> oc = J.obj(m, "OnlineChange");
        if (oc != null) for (Map.Entry<String, Object> e : oc.entrySet()) r.onlineChange.put(Long.parseLong(e.getKey()), Boolean.TRUE.equals(e.getValue()));
        Map<String, Object> dns = J.obj(m, "DNSConfig");
        if (dns != null) r.dnsConfig = DnsConfig.fromJson(dns);
        r.domain = J.str(m, "Domain");
        if (m.containsKey("PacketFilter") && m.get("PacketFilter") != null) {
            r.hasPacketFilter = true;
            for (Map<String, Object> f : J.objects(m, "PacketFilter")) r.packetFilter.add(FilterRule.fromJson(f));
        }
        Map<String, Object> pfs = J.obj(m, "PacketFilters");
        if (pfs != null) {
            r.packetFilters = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : pfs.entrySet()) {
                if (e.getValue() == null) { r.packetFilters.put(e.getKey(), null); continue; }
                List<FilterRule> rules = new ArrayList<>();
                if (e.getValue() instanceof List<?> l) for (Object o : l) { Map<String, Object> x = J.obj(o); if (x != null) rules.add(FilterRule.fromJson(x)); }
                r.packetFilters.put(e.getKey(), rules);
            }
        }
        r.pingRequest = J.obj(m, "PingRequest");
        r.health = J.strings(m, "Health");
        return r;
    }
}
