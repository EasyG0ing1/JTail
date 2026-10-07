package com.simtechdata.jtail.tailcfg;

import com.simtechdata.jtail.json.J;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** tailcfg.DNSConfig, reduced to the fields JTail's MagicDNS resolver uses. */
public record DnsConfig(List<String> resolvers, Map<String, List<String>> routes, List<String> domains,
                        boolean proxied, List<Record_> extraRecords) {
    public record Record_(String name, String type, String value) {}

    public static final DnsConfig EMPTY = new DnsConfig(List.of(), Map.of(), List.of(), false, List.of());

    public static DnsConfig fromJson(Map<String, Object> m) {
        List<String> res = new ArrayList<>();
        for (Map<String, Object> r : J.objects(m, "Resolvers")) res.add(J.str(r, "Addr"));
        Map<String, List<String>> routes = new LinkedHashMap<>();
        Map<String, Object> rm = J.obj(m, "Routes");
        if (rm != null) {
            for (Map.Entry<String, Object> e : rm.entrySet()) {
                List<String> addrs = new ArrayList<>();
                if (e.getValue() instanceof List<?> l) for (Object o : l) { Map<String, Object> x = J.obj(o); if (x != null) addrs.add(J.str(x, "Addr")); }
                routes.put(e.getKey(), addrs);
            }
        }
        List<Record_> extras = new ArrayList<>();
        for (Map<String, Object> r : J.objects(m, "ExtraRecords")) extras.add(new Record_(J.str(r, "Name"), J.str(r, "Type"), J.str(r, "Value")));
        return new DnsConfig(res, routes, J.strings(m, "Domains"), J.bool(m, "Proxied"), extras);
    }
}
