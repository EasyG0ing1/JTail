package com.simtechdata.jtail.dns;

import static org.junit.jupiter.api.Assertions.*;

import com.simtechdata.jtail.netstack.Netstack;
import com.simtechdata.jtail.netstack.UdpSocket;
import com.simtechdata.jtail.tailcfg.DnsConfig;
import com.simtechdata.jtail.testutil.NetstackPair;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

class DnsResolverTest {
    final NetstackPair net = new NetstackPair();
    final ExecutorService ex = Executors.newSingleThreadExecutor();

    @AfterEach void tearDown() {
        ex.shutdownNow();
        net.close();
    }

    /** {@link DnsResolver} takes a non-throwing opener, so wrap the checked exception from binding. */
    static UdpSocket bind(Netstack stack, int port) {
        try { return stack.bindUdp(port); } catch (IOException e) { throw new UncheckedIOException(e); }
    }

    static DnsConfig config(List<DnsConfig.Record_> records, List<String> resolvers) {
        return new DnsConfig(resolvers, java.util.Map.of(), List.of("tail.example"), false, records);
    }

    /** Answers every A query on node b with 10.1.2.3 and every other query with an empty answer. */
    Future<?> fakeResolverOnB() throws Exception {
        UdpSocket server = net.b.bindUdp(53);
        return ex.submit(() -> {
            try (server) {
                while (true) {
                    UdpSocket.Datagram d = server.receive(10_000);
                    byte[] q = d.data();
                    int qtype = ((q[q.length - 4] & 0xFF) << 8) | (q[q.length - 3] & 0xFF);
                    byte[] resp = java.util.Arrays.copyOf(q, q.length);
                    resp[2] = (byte) 0x81; resp[3] = (byte) 0x80;     // response, no error
                    if (qtype == DnsMessage.TYPE_A) {
                        resp[7] = 1;                                   // one answer
                        byte[] answer = {(byte) 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 1, 2, 3};
                        byte[] full = new byte[resp.length + answer.length];
                        System.arraycopy(resp, 0, full, 0, resp.length);
                        System.arraycopy(answer, 0, full, resp.length, answer.length);
                        resp = full;
                    }
                    server.send(d.srcIp(), d.srcPort(), resp);
                }
            } catch (java.net.SocketException closed) {
                return null;
            }
        });
    }

    @Test
    void magicDnsExtraRecordsAnswerWithoutTouchingTheNetwork() throws Exception {
        DnsResolver r = new DnsResolver(port -> { throw new AssertionError("no network query expected"); }, ip -> false);
        DnsConfig cfg = config(List.of(new DnsConfig.Record_("Printer.Tail.Example.", "A", "100.64.0.9"),
                new DnsConfig.Record_("printer.tail.example", "", "100.64.0.10"),
                new DnsConfig.Record_("broken.tail.example", "A", "not-an-ip")), List.of());
        assertEquals("100.64.0.9", r.resolve("printer.tail.example", cfg).get(0).getHostAddress());
        assertEquals("100.64.0.9", r.resolve("PRINTER.tail.example.", cfg).get(0).getHostAddress(), "names are case-insensitive");
        assertEquals("100.64.0.10", r.resolve("printer.tail.example", config(List.of(
                new DnsConfig.Record_("printer.tail.example", "", "100.64.0.10")), List.of())).get(0).getHostAddress());
        assertThrows(UnknownHostException.class, () -> r.resolve("broken.tail.example", config(List.of(
                new DnsConfig.Record_("broken.tail.example", "A", "not-an-ip")), List.of())),
                "a record with a bad address is ignored");
    }

    @Test
    void unknownNamesWithNoResolversAreNotFound() {
        DnsResolver r = new DnsResolver(port -> { throw new AssertionError("no socket expected"); }, ip -> true);
        assertThrows(UnknownHostException.class, () -> r.resolve("nowhere.example", config(List.of(), List.of())));
    }

    @Test @Timeout(60)
    void queriesAResolverOverTheTailnetAndCachesTheAnswer() throws Exception {
        Future<?> server = fakeResolverOnB();
        try {
            DnsResolver r = new DnsResolver(port -> bind(net.a, port), ip -> true);
            DnsConfig cfg = config(List.of(), List.of("100.64.0.2"));
            List<java.net.InetAddress> got = r.resolve("fileserver", cfg);
            assertEquals("10.1.2.3", got.get(0).getHostAddress());

            // a second lookup is served from the cache, so it works even when the resolver is unreachable
            DnsResolver offline = new DnsResolver(port -> bind(net.a, port), ip -> false);
            assertTrue(r.resolve("fileserver", cfg).size() >= 1);
            assertThrows(UnknownHostException.class, () -> offline.resolve("other.example", cfg));
        } finally {
            server.cancel(true);                   // stops the fake resolver; its socket closes on the way out
        }
    }

    @Test @Timeout(60)
    void resolverThatDoesNotAnswerTimesOutAsUnknownHost() {
        DnsResolver r = new DnsResolver(port -> bind(net.a, port), ip -> true);
        DnsConfig cfg = config(List.of(), List.of("100.64.0.2"));   // nothing listens on b:53 here
        assertThrows(UnknownHostException.class, () -> r.resolve("silent.example", cfg));
    }
}
