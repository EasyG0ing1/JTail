package com.simtechdata.jtail.dns;

import com.simtechdata.jtail.netstack.UdpSocket;
import com.simtechdata.jtail.tailcfg.DnsConfig;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * Resolves names that are not tailnet peers using the tailnet's DNS configuration: MagicDNS extra records first, then
 * split-DNS routes (longest matching suffix) and global resolvers, queried over the tailnet itself.
 */
public final class DnsResolver {
    private record Cached(List<InetAddress> addrs, long expiresNanos) {}

    private final Function<Integer, UdpSocket> openUdp;
    private final Predicate<byte[]> reachable;
    private final Map<String, Cached> cache = new ConcurrentHashMap<>();
    private static final long TTL_NANOS = 60_000_000_000L;

    /**
     * @param openUdp   opens a UDP socket on the tailnet address (argument is the port, 0 = ephemeral)
     * @param reachable tells whether a resolver address can be reached through the tailnet
     */
    public DnsResolver(Function<Integer, UdpSocket> openUdp, Predicate<byte[]> reachable) {
        this.openUdp = openUdp;
        this.reachable = reachable;
    }

    /** Returns all addresses for {@code name} or throws UnknownHostException. */
    public List<InetAddress> resolve(String name, DnsConfig cfg) throws UnknownHostException {
        String n = name.toLowerCase(Locale.ROOT);
        if (n.endsWith(".")) n = n.substring(0, n.length() - 1);

        List<InetAddress> out = new ArrayList<>();
        for (DnsConfig.Record_ r : cfg.extraRecords()) {
            String rn = r.name().toLowerCase(Locale.ROOT);
            if (rn.endsWith(".")) rn = rn.substring(0, rn.length() - 1);
            if (rn.equals(n) && (r.type().isEmpty() || r.type().equals("A") || r.type().equals("AAAA"))) {
                try { out.add(InetAddress.getByAddress(com.simtechdata.jtail.tailcfg.IpPrefix.parseIp(r.value()))); }
                catch (RuntimeException ignored) { }
            }
        }
        if (!out.isEmpty()) return out;

        Cached c = cache.get(n);
        if (c != null && c.expiresNanos > System.nanoTime()) return c.addrs;

        List<String> candidates = new ArrayList<>();
        candidates.add(n);
        if (!n.contains(".")) for (String d : cfg.domains()) candidates.add(n + "." + d.replaceAll("\\.$", ""));

        for (String cand : candidates) {
            for (String resolver : resolversFor(cand, cfg)) {
                List<InetAddress> got = query(resolver, cand);
                if (!got.isEmpty()) {
                    cache.put(n, new Cached(got, System.nanoTime() + TTL_NANOS));
                    return got;
                }
            }
        }
        throw new UnknownHostException(name + ": not found in tailnet DNS");
    }

    private List<String> resolversFor(String name, DnsConfig cfg) {
        String bestSuffix = null;
        for (String suffix : cfg.routes().keySet()) {
            String s = suffix.toLowerCase(Locale.ROOT).replaceAll("^\\.|\\.$", "");
            boolean match = s.isEmpty() || name.equals(s) || name.endsWith("." + s);
            if (match && (bestSuffix == null || s.length() > bestSuffix.length())) bestSuffix = s;
        }
        List<String> out = new ArrayList<>();
        if (bestSuffix != null) {
            for (Map.Entry<String, List<String>> e : cfg.routes().entrySet()) {
                if (e.getKey().toLowerCase(Locale.ROOT).replaceAll("^\\.|\\.$", "").equals(bestSuffix)) out.addAll(e.getValue());
            }
        }
        if (out.isEmpty()) out.addAll(cfg.resolvers());
        return out;
    }

    private List<InetAddress> query(String resolver, String name) {
        InetSocketAddress server = parseResolver(resolver);
        if (server == null || !reachable.test(server.getAddress().getAddress())) return List.of();
        List<InetAddress> all = new ArrayList<>();
        for (int qtype : new int[]{DnsMessage.TYPE_A, DnsMessage.TYPE_AAAA}) {
            try (UdpSocket sock = openUdp.apply(0)) {
                int id = DnsMessage.newId();
                sock.send(server.getAddress().getAddress(), server.getPort(), DnsMessage.query(id, name, qtype));
                long deadline = System.nanoTime() + 3_000_000_000L;
                while (true) {
                    long left = (deadline - System.nanoTime()) / 1_000_000L;
                    if (left <= 0) break;
                    UdpSocket.Datagram d = sock.receive(left);
                    DnsMessage.Response r = DnsMessage.parse(d.data());
                    if (r != null && r.id() == id) { all.addAll(r.addresses()); break; }
                }
            } catch (SocketTimeoutException e) {
                // resolver did not answer for this record type
            } catch (IOException | RuntimeException e) {
                return all;
            }
        }
        return all;
    }

    /** Accepts "1.2.3.4", "1.2.3.4:5353" or "[::1]:53"; DNS-over-HTTPS URLs are not supported. */
    static InetSocketAddress parseResolver(String s) {
        try {
            if (s.startsWith("http")) return null;
            int port = 53;
            String host = s;
            if (s.startsWith("[")) {
                int end = s.indexOf(']');
                host = s.substring(1, end);
                if (s.length() > end + 1 && s.charAt(end + 1) == ':') port = Integer.parseInt(s.substring(end + 2));
            } else if (s.indexOf(':') == s.lastIndexOf(':') && s.indexOf(':') > 0) {
                host = s.substring(0, s.indexOf(':'));
                port = Integer.parseInt(s.substring(s.indexOf(':') + 1));
            }
            return new InetSocketAddress(InetAddress.getByAddress(com.simtechdata.jtail.tailcfg.IpPrefix.parseIp(host)), port);
        } catch (RuntimeException | UnknownHostException e) {
            return null;
        }
    }
}
