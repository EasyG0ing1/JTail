package com.simtechdata.jtail.tailcfg;

import com.simtechdata.jtail.json.J;
import java.net.InetSocketAddress;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * The accumulated tailnet view, built by applying the control server's streamed {@link MapResponse} deltas
 * (the logic of Tailscale's controlclient mapSession). Every {@link #apply} yields a new immutable {@link Snapshot}.
 */
public final class NetMap {
    /** Immutable view handed to the rest of the library. */
    public record Snapshot(Node self, List<Node> peers, Derp.Map_ derpMap, DnsConfig dns, String domain,
                           List<FilterRule> packetFilter, List<String> health) {
        public Node peerByKey(byte[] key) {
            for (Node n : peers) if (n.key != null && java.util.Arrays.equals(n.key, key)) return n;
            return null;
        }
    }

    private Node self;
    private final Map<Long, Node> peers = new TreeMap<>();
    private Derp.Map_ derpMap;
    private DnsConfig dns = DnsConfig.EMPTY;
    private String domain = "";
    private final Map<String, List<FilterRule>> filters = new TreeMap<>();
    private List<String> health = List.of();
    private Snapshot snapshot = new Snapshot(null, List.of(), null, DnsConfig.EMPTY, "", List.of(), List.of());

    public synchronized Snapshot snapshot() { return snapshot; }

    /** Applies one streamed response and returns the updated snapshot. */
    public synchronized Snapshot apply(MapResponse r) {
        if (r.keepAlive) return snapshot;
        if (r.node != null) self = r.node;
        if (r.derpMap != null) derpMap = r.derpMap;
        if (r.dnsConfig != null) dns = r.dnsConfig;
        if (!r.domain.isEmpty()) domain = r.domain;
        if (!r.health.isEmpty()) health = List.copyOf(r.health);

        if (r.peers != null && !r.peers.isEmpty()) {
            peers.clear();
            for (Node n : r.peers) peers.put(n.id, n);
        } else {
            for (long id : r.peersRemoved) peers.remove(id);
            for (Node n : r.peersChanged) peers.put(n.id, n);
            for (Map.Entry<Long, Boolean> e : r.onlineChange.entrySet()) {
                Node n = peers.get(e.getKey());
                if (n != null) { n = n.copy(); n.online = e.getValue(); peers.put(n.id, n); }
            }
            for (Map<String, Object> p : r.peersChangedPatch) patch(p);
        }

        if (r.hasPacketFilter) filters.put("base", r.packetFilter);
        if (r.packetFilters != null) {
            if (r.packetFilters.containsKey("*") && r.packetFilters.get("*") == null) filters.clear();
            for (Map.Entry<String, List<FilterRule>> e : r.packetFilters.entrySet()) {
                if (e.getKey().equals("*")) continue;
                if (e.getValue() == null) filters.remove(e.getKey()); else filters.put(e.getKey(), e.getValue());
            }
        }
        snapshot = build();
        return snapshot;
    }

    private void patch(Map<String, Object> pc) {
        Node old = peers.get(J.lng(pc, "NodeID"));
        if (old == null) return;
        Node n = old.copy();
        if (J.lng(pc, "DERPRegion") != 0) n.homeDerp = J.integer(pc, "DERPRegion");
        if (pc.get("Endpoints") instanceof List<?> eps) {
            List<InetSocketAddress> out = new ArrayList<>();
            for (Object o : eps) if (o instanceof String s) out.add(Node.parseEndpoint(s));
            n.endpoints = out;
        }
        if (pc.get("Key") instanceof String s) n.key = Keys.decode(Keys.NODE, s);
        if (pc.get("DiscoKey") instanceof String s) n.discoKey = Keys.decode(Keys.DISCO, s);
        Boolean online = J.optBool(pc, "Online");
        if (online != null) n.online = online;
        if (pc.get("KeyExpiry") instanceof String s) n.keyExpiry = Node.parseTime(s);
        if (pc.get("CapMap") != null) n.capMap = J.obj(pc, "CapMap");
        peers.put(n.id, n);
    }

    private Snapshot build() {
        List<FilterRule> merged = new ArrayList<>();
        for (List<FilterRule> l : filters.values()) merged.addAll(l);
        return new Snapshot(self, Collections.unmodifiableList(new ArrayList<>(peers.values())), derpMap, dns, domain,
                Collections.unmodifiableList(merged), health);
    }
}
