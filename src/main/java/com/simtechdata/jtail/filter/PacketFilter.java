package com.simtechdata.jtail.filter;

import com.simtechdata.jtail.netstack.IpPacket;
import com.simtechdata.jtail.tailcfg.FilterRule;
import com.simtechdata.jtail.tailcfg.IpPrefix;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The tailnet ACL packet filter delivered in the netmap. Mirrors Tailscale's semantics: inbound TCP is judged on its
 * SYN, UDP is accepted if rules allow it or it answers a flow we started, and ICMP echo needs an allowing rule.
 */
public final class PacketFilter {
    private interface IpMatcher { boolean matches(byte[] ip); }

    private record CompiledRule(List<IpMatcher> src, List<DstMatcher> dst, boolean tcp, boolean udp, boolean icmp) {}
    private record DstMatcher(IpMatcher ip, int first, int last) {}

    private final List<CompiledRule> rules;
    private final Map<String, Long> udpFlows = new ConcurrentHashMap<>(); // reverse-key -> expiry nanos
    private static final long UDP_FLOW_NANOS = 30L * 1_000_000_000L;

    private PacketFilter(List<CompiledRule> rules) { this.rules = rules; }

    /** A filter that accepts everything (used before the first netmap and when no filter is configured). */
    public static PacketFilter allowAll() {
        return new PacketFilter(List.of(new CompiledRule(List.of(ip -> true), List.of(new DstMatcher(ip -> true, 0, 65535)), true, true, true)));
    }

    public static PacketFilter compile(List<FilterRule> rs) {
        List<CompiledRule> out = new ArrayList<>();
        for (FilterRule r : rs) {
            List<IpMatcher> src = new ArrayList<>();
            for (String s : r.srcIPs()) { IpMatcher m = parseMatcher(s); if (m != null) src.add(m); }
            List<DstMatcher> dst = new ArrayList<>();
            for (FilterRule.DstPorts d : r.dstPorts()) { IpMatcher m = parseMatcher(d.ip()); if (m != null) dst.add(new DstMatcher(m, d.first(), d.last())); }
            boolean tcp = r.ipProto().isEmpty(), udp = tcp, icmp = tcp;
            for (int proto : r.ipProto()) {
                if (proto == IpPacket.PROTO_TCP) tcp = true;
                else if (proto == IpPacket.PROTO_UDP) udp = true;
                else if (proto == IpPacket.PROTO_ICMP || proto == IpPacket.PROTO_ICMPV6) icmp = true;
            }
            if (!src.isEmpty() && !dst.isEmpty()) out.add(new CompiledRule(src, dst, tcp, udp, icmp));
        }
        return new PacketFilter(out);
    }

    /** "*", an IP, a CIDR, or "lo-hi" range. Capability grants ("cap:...") and unknown forms never match. */
    static IpMatcher parseMatcher(String s) {
        try {
            if (s.equals("*")) return ip -> true;
            if (s.contains("-")) {
                String[] r = s.split("-", 2);
                byte[] lo = IpPrefix.parseIp(r[0]), hi = IpPrefix.parseIp(r[1]);
                return ip -> ip.length == lo.length && Arrays.compareUnsigned(ip, lo) >= 0 && Arrays.compareUnsigned(ip, hi) <= 0;
            }
            IpPrefix p = IpPrefix.parse(s);
            return p::contains;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Records an outbound UDP datagram so its replies are admitted. */
    public void noteOutbound(IpPacket p) {
        if (p.protocol != IpPacket.PROTO_UDP || p.payload.length < 4) return;
        int sport = ((p.payload[0] & 0xFF) << 8) | (p.payload[1] & 0xFF);
        int dport = ((p.payload[2] & 0xFF) << 8) | (p.payload[3] & 0xFF);
        if (udpFlows.size() > 4096) udpFlows.values().removeIf(t -> t < System.nanoTime());
        udpFlows.put(key(p.dst, dport, p.src, sport), System.nanoTime() + UDP_FLOW_NANOS);
    }

    private static String key(byte[] a, int ap, byte[] b, int bp) {
        return ByteBuffer.wrap(a).hashCode() + ":" + Arrays.toString(a) + ap + ">" + Arrays.toString(b) + bp;
    }

    /** True if the inbound packet may enter the stack. */
    public boolean allowInbound(IpPacket p) {
        byte[] t = p.payload;
        switch (p.protocol) {
            case IpPacket.PROTO_TCP -> {
                if (t.length < 14) return false;
                boolean syn = (t[13] & 0x02) != 0, ack = (t[13] & 0x10) != 0;
                if (!(syn && !ack)) return true; // only connection attempts are filtered; segments of existing flows pass
                int dport = ((t[2] & 0xFF) << 8) | (t[3] & 0xFF);
                return matches(p, IpPacket.PROTO_TCP, dport);
            }
            case IpPacket.PROTO_UDP -> {
                if (t.length < 4) return false;
                int sport = ((t[0] & 0xFF) << 8) | (t[1] & 0xFF), dport = ((t[2] & 0xFF) << 8) | (t[3] & 0xFF);
                Long exp = udpFlows.get(key(p.src, sport, p.dst, dport));
                if (exp != null && exp > System.nanoTime()) return true;
                return matches(p, IpPacket.PROTO_UDP, dport);
            }
            case IpPacket.PROTO_ICMP, IpPacket.PROTO_ICMPV6 -> {
                if (t.length < 1) return false;
                int type = t[0] & 0xFF;
                boolean echoReply = (p.protocol == IpPacket.PROTO_ICMP && type == 0) || (p.protocol == IpPacket.PROTO_ICMPV6 && type == 129);
                if (echoReply || type == 3 || type == 1) return true; // replies and errors for our own traffic
                return matches(p, p.protocol, 0);
            }
            default -> { return false; }
        }
    }

    private boolean matches(IpPacket p, int proto, int dport) {
        for (CompiledRule r : rules) {
            boolean protoOk = proto == IpPacket.PROTO_TCP ? r.tcp : proto == IpPacket.PROTO_UDP ? r.udp : r.icmp;
            if (!protoOk) continue;
            boolean srcOk = false;
            for (IpMatcher m : r.src) if (m.matches(p.src)) { srcOk = true; break; }
            if (!srcOk) continue;
            for (DstMatcher d : r.dst) {
                if (!d.ip.matches(p.dst)) continue;
                if (proto == IpPacket.PROTO_TCP || proto == IpPacket.PROTO_UDP) { if (dport >= d.first && dport <= d.last) return true; }
                else return true;
            }
        }
        return false;
    }
}
