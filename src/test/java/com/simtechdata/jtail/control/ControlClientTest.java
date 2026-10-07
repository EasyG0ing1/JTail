package com.simtechdata.jtail.control;

import static org.junit.jupiter.api.Assertions.*;

import com.simtechdata.jtail.state.NodeIdentity;
import com.simtechdata.jtail.tailcfg.NetMap;
import com.simtechdata.jtail.testutil.Oracles;
import java.net.URI;
import java.util.List;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

class ControlClientTest {
    private static ControlClient client(String url) {
        return new ControlClient(URI.create(url), NodeIdentity.generate());
    }

    @Test
    @Timeout(90)
    void registersAndStreamsNetmapAgainstGoTestControl() throws Exception {
        try (Oracles.Running o = Oracles.start("go-control", "-authkey", "tskey-auth-secret")) {
            String url = o.line().substring("BASEURL ".length());

            // wrong key is refused
            try (ControlClient bad = client(url)) {
                RuntimeException ex = null;
                try {
                    var r = bad.register("tskey-auth-WRONG", new Hostinfo("bad"), false, null);
                    assertFalse(r.error().isEmpty() && r.authUrl().isEmpty() && r.machineAuthorized(), "wrong key must not register");
                } catch (java.io.IOException expected) { /* server rejects with an HTTP error */ }
            }

            // node A registers and streams its map
            NodeIdentity idA = NodeIdentity.generate();
            ControlClient a = new ControlClient(URI.create(url), idA);
            var ra = a.register("tskey-auth-secret", new Hostinfo("node-a"), false, null);
            assertEquals("", ra.error());
            assertEquals("", ra.authUrl());
            assertTrue(ra.machineAuthorized());

            a.sendUpdate(new Hostinfo("node-a"), List.of("127.0.0.1:41641"));
            NetMap netmapA = new NetMap();
            BlockingQueue<NetMap.Snapshot> updatesA = new LinkedBlockingQueue<>();
            ExecutorService ex = Executors.newCachedThreadPool(r -> { Thread t = new Thread(r); t.setDaemon(true); return t; });
            ex.submit(() -> {
                a.pollMap(new Hostinfo("node-a"), List.of("127.0.0.1:41641"), true, mr -> updatesA.add(netmapA.apply(mr)));
                return null;
            });
            NetMap.Snapshot s = awaitSnapshot(updatesA, x -> x.self() != null && x.derpMap() != null);
            assertEquals(1, s.derpMap().regions().size());
            assertFalse(s.self().addresses.isEmpty(), "self must get a tailnet address");
            assertArrayEquals(idA.nodePublic(), s.self().key);
            assertEquals("node-a", s.self().hostname);
            assertNotNull(s.self().ipv4());

            // node B joins the same tailnet; A must see B as a peer
            NodeIdentity idB = NodeIdentity.generate();
            ControlClient b = new ControlClient(URI.create(url), idB);
            assertTrue(b.register("tskey-auth-secret", new Hostinfo("node-b"), false, null).machineAuthorized());
            b.sendUpdate(new Hostinfo("node-b"), List.of("127.0.0.1:41642"));
            NetMap netmapB = new NetMap();
            BlockingQueue<NetMap.Snapshot> updatesB = new LinkedBlockingQueue<>();
            ex.submit(() -> {
                b.pollMap(new Hostinfo("node-b"), List.of("127.0.0.1:41642"), true, mr -> updatesB.add(netmapB.apply(mr)));
                return null;
            });
            NetMap.Snapshot sa = awaitSnapshot(updatesA, x -> x.peerByKey(idB.nodePublic()) != null);
            assertEquals("node-b", sa.peerByKey(idB.nodePublic()).hostname);
            assertArrayEquals(idB.discoPublic(), sa.peerByKey(idB.nodePublic()).discoKey);
            assertEquals("127.0.0.1", sa.peerByKey(idB.nodePublic()).endpoints.get(0).getAddress().getHostAddress());
            NetMap.Snapshot sb = awaitSnapshot(updatesB, x -> x.peerByKey(idA.nodePublic()) != null);
            assertNotNull(sb.peerByKey(idA.nodePublic()).ipv4());
            a.close(); b.close(); ex.shutdownNow();
        }
    }

    private static NetMap.Snapshot awaitSnapshot(BlockingQueue<NetMap.Snapshot> q, java.util.function.Predicate<NetMap.Snapshot> p)
            throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
        while (System.nanoTime() < deadline) {
            NetMap.Snapshot s = q.poll(500, TimeUnit.MILLISECONDS);
            if (s != null && p.test(s)) return s;
        }
        fail("timed out waiting for netmap condition");
        return null;
    }
}
