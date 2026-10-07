package com.simtechdata.jtail.tailcfg;

import com.simtechdata.jtail.json.J;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** tailcfg.DERPMap and friends. */
public final class Derp {
    private Derp() {}

    public record Node(String name, int regionId, String hostName, String certName, String ipv4, String ipv6,
                       int stunPort, boolean stunOnly, int derpPort, boolean insecureForTests, boolean canPort80) {
        static Node fromJson(Map<String, Object> m) {
            return new Node(J.str(m, "Name"), J.integer(m, "RegionID"), J.str(m, "HostName"), J.str(m, "CertName"),
                    J.str(m, "IPv4"), J.str(m, "IPv6"), J.integer(m, "STUNPort"), J.bool(m, "STUNOnly"),
                    J.integer(m, "DERPPort"), J.bool(m, "InsecureForTests"), J.bool(m, "CanPort80"));
        }
        public int port() { return derpPort == 0 ? 443 : derpPort; }
    }

    public record Region(int regionId, String regionCode, String regionName, boolean avoid, boolean noMeasureNoHome,
                         List<Node> nodes) {
        static Region fromJson(Map<String, Object> m) {
            List<Node> ns = new ArrayList<>();
            for (Map<String, Object> n : J.objects(m, "Nodes")) ns.add(Node.fromJson(n));
            return new Region(J.integer(m, "RegionID"), J.str(m, "RegionCode"), J.str(m, "RegionName"),
                    J.bool(m, "Avoid"), J.bool(m, "NoMeasureNoHome"), ns);
        }
    }

    public record Map_(TreeMap<Integer, Region> regions, boolean omitDefaultRegions) {
        public static Map_ fromJson(Map<String, Object> m) {
            TreeMap<Integer, Region> out = new TreeMap<>();
            Map<String, Object> regs = J.obj(m, "Regions");
            if (regs != null) {
                for (Map.Entry<String, Object> e : regs.entrySet()) {
                    Map<String, Object> r = J.obj(e.getValue());
                    if (r != null) out.put(Integer.parseInt(e.getKey()), Region.fromJson(r));
                }
            }
            return new Map_(out, J.bool(m, "omitDefaultRegions"));
        }
        public Region region(int id) { return regions.get(id); }
    }
}
