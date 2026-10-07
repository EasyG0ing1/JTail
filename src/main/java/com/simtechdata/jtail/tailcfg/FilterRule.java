package com.simtechdata.jtail.tailcfg;

import com.simtechdata.jtail.json.J;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** tailcfg.FilterRule: a source set, destination IP/port ranges and optional IP protocols (empty = TCP/UDP/ICMP). */
public record FilterRule(List<String> srcIPs, List<DstPorts> dstPorts, List<Integer> ipProto) {
    public record DstPorts(String ip, int first, int last) {}

    public static FilterRule fromJson(Map<String, Object> m) {
        List<DstPorts> dsts = new ArrayList<>();
        for (Map<String, Object> d : J.objects(m, "DstPorts")) {
            Map<String, Object> pr = J.obj(d, "Ports");
            dsts.add(new DstPorts(J.str(d, "IP"), pr == null ? 0 : J.integer(pr, "First"), pr == null ? 65535 : J.integer(pr, "Last")));
        }
        List<Integer> protos = new ArrayList<>();
        for (Long l : J.longs(m, "IPProto")) protos.add(l.intValue());
        return new FilterRule(J.strings(m, "SrcIPs"), dsts, protos);
    }
}
