package com.simtechdata.jtail.tailcfg;

import com.simtechdata.jtail.json.J;
import java.net.InetSocketAddress;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** A node in the netmap (tailcfg.Node). Mutable only through {@link NetMap} delta application. */
public final class Node {
    public long id;
    public String stableId = "";
    public String name = "";          // FQDN with trailing dot, e.g. "host.tail1234.ts.net."
    public long user;
    public byte[] key;                // node (WireGuard) public key
    public Instant keyExpiry;         // null = never
    public byte[] machine;
    public byte[] discoKey;
    public List<IpPrefix> addresses = new ArrayList<>();
    public List<IpPrefix> allowedIPs = new ArrayList<>();
    public List<InetSocketAddress> endpoints = new ArrayList<>();
    public int homeDerp;
    public String hostname = "";
    public List<String> tags = new ArrayList<>();
    public Boolean online;
    public boolean expired;
    public boolean machineAuthorized;
    public Map<String, Object> capMap;

    /** Shallow-ish copy used for copy-on-write patching (lists are copied; keys are immutable by convention). */
    public Node copy() {
        Node n = new Node();
        n.id = id; n.stableId = stableId; n.name = name; n.user = user; n.key = key; n.keyExpiry = keyExpiry;
        n.machine = machine; n.discoKey = discoKey; n.addresses = new ArrayList<>(addresses);
        n.allowedIPs = new ArrayList<>(allowedIPs); n.endpoints = new ArrayList<>(endpoints); n.homeDerp = homeDerp;
        n.hostname = hostname; n.tags = new ArrayList<>(tags); n.online = online; n.expired = expired;
        n.machineAuthorized = machineAuthorized; n.capMap = capMap;
        return n;
    }

    public static Node fromJson(Map<String, Object> m) {
        Node n = new Node();
        n.id = J.lng(m, "ID");
        n.stableId = J.str(m, "StableID");
        n.name = J.str(m, "Name");
        n.user = J.lng(m, "User");
        n.key = Keys.decode(Keys.NODE, J.str(m, "Key"));
        n.keyExpiry = parseTime(J.str(m, "KeyExpiry"));
        n.machine = Keys.decode(Keys.MACHINE, J.str(m, "Machine"));
        n.discoKey = Keys.decode(Keys.DISCO, J.str(m, "DiscoKey"));
        for (String s : J.strings(m, "Addresses")) n.addresses.add(IpPrefix.parse(s));
        for (String s : J.strings(m, "AllowedIPs")) n.allowedIPs.add(IpPrefix.parse(s));
        if (n.allowedIPs.isEmpty()) n.allowedIPs.addAll(n.addresses);
        for (String s : J.strings(m, "Endpoints")) n.endpoints.add(parseEndpoint(s));
        n.homeDerp = J.integer(m, "HomeDERP");
        Map<String, Object> hi = J.obj(m, "Hostinfo");
        if (hi != null) n.hostname = J.str(hi, "Hostname");
        // Current control servers often leave HomeDERP unset. The peer's relay region is then carried either in the
        // legacy "DERP" string ("127.3.3.40:<region>") or in the peer's own reported NetInfo.PreferredDERP.
        if (n.homeDerp == 0) {
            String legacy = J.str(m, "DERP");
            if (legacy != null && legacy.startsWith("127.3.3.40:")) {
                try { n.homeDerp = Integer.parseInt(legacy.substring("127.3.3.40:".length())); } catch (NumberFormatException ignored) { }
            }
        }
        if (n.homeDerp == 0 && hi != null) {
            Map<String, Object> ni = J.obj(hi, "NetInfo");
            if (ni != null) n.homeDerp = J.integer(ni, "PreferredDERP");
        }
        n.tags = J.strings(m, "Tags");
        n.online = J.optBool(m, "Online");
        n.expired = J.bool(m, "Expired");
        n.machineAuthorized = J.bool(m, "MachineAuthorized");
        n.capMap = J.obj(m, "CapMap");
        return n;
    }

    /** Parses "1.2.3.4:567" or "[::1]:567" without DNS. */
    public static InetSocketAddress parseEndpoint(String s) {
        int colon = s.lastIndexOf(':');
        if (colon < 0) throw new IllegalArgumentException("bad endpoint " + s);
        String host = s.substring(0, colon);
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
        byte[] ip = IpPrefix.parseIp(host);
        try {
            return new InetSocketAddress(java.net.InetAddress.getByAddress(ip), Integer.parseInt(s.substring(colon + 1)));
        } catch (java.net.UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }
    }

    static Instant parseTime(String s) {
        if (s == null || s.isEmpty() || s.startsWith("0001-01-01")) return null;
        return OffsetDateTime.parse(s).toInstant();
    }

    /** The node's first IPv4 Tailscale address, or null. */
    public byte[] ipv4() {
        for (IpPrefix p : addresses) if (p.isIPv4()) return p.addr();
        return null;
    }

    /** MagicDNS short name: first label of {@link #name}. */
    public String shortName() {
        String n = name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
        int dot = n.indexOf('.');
        return dot < 0 ? n : n.substring(0, dot);
    }
}
