package com.simtechdata.jtail.derp;

import com.simtechdata.jtail.tailcfg.Derp;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Keeps DERP connections to the regions we need: a permanent, auto-reconnecting "home" connection that receives
 * traffic, plus connections opened on demand to other regions where peers' home relays live.
 */
public final class DerpManager implements AutoCloseable {
    /** Receives packets from any region. */
    public interface Receiver { void onDerpPacket(int region, byte[] sourceNodeKey, byte[] data); }

    private final byte[] nodePriv;
    private final Receiver receiver;
    private volatile Derp.Map_ map;
    private volatile int home;
    private final Map<Integer, Conn> conns = new ConcurrentHashMap<>();
    private final ExecutorService connector = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "jtail-derp-connect");
        t.setDaemon(true);
        return t;
    });
    private final ScheduledExecutorService timers = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "jtail-derp-timers");
        t.setDaemon(true);
        return t;
    });
    private volatile boolean closed;

    public DerpManager(byte[] nodePriv, Receiver receiver) {
        this.nodePriv = nodePriv.clone();
        this.receiver = receiver;
    }

    public void setMap(Derp.Map_ m) { this.map = m; }
    public Derp.Map_ map() { return map; }
    public int home() { return home; }

    /** Marks {@code region} as our home relay and keeps a connection to it. */
    public void setHome(int region) {
        int old = home;
        home = region;
        if (old != 0 && old != region) {
            Conn c = conns.get(old);
            if (c != null) c.notePreferred(false);
        }
        Conn c = conn(region);
        if (c != null) c.ensure();
    }

    public boolean isConnected(int region) {
        Conn c = conns.get(region);
        return c != null && c.client != null && !c.client.isClosed();
    }

    /** Sends via {@code region}; the packet may be queued briefly while a connection is established. */
    public void send(int region, byte[] dest, byte[] packet) {
        Conn c = conn(region);
        if (c == null) { com.simtechdata.jtail.Trace.log("derp", "send dropped: region " + region + " not in DERP map"); return; }
        com.simtechdata.jtail.Trace.log("derp", "tx " + packet.length + "B to " + com.simtechdata.jtail.Trace.key(dest) + " via region " + region);
        c.send(dest, packet);
    }

    private Conn conn(int region) {
        if (closed) return null;
        Derp.Map_ m = map;
        if (m == null || m.region(region) == null || m.region(region).nodes().isEmpty()) return null;
        return conns.computeIfAbsent(region, Conn::new);
    }

    private final class Conn {
        final int region;
        volatile DerpClient client;
        private boolean connecting;
        private int failures;
        private final ArrayDeque<byte[][]> queue = new ArrayDeque<>();

        Conn(int region) { this.region = region; }

        void ensure() {
            synchronized (this) {
                if (closed || connecting || (client != null && !client.isClosed())) return;
                connecting = true;
            }
            connector.execute(this::connectNow);
        }

        void notePreferred(boolean v) {
            DerpClient c = client;
            if (c != null) try { c.notePreferred(v); } catch (IOException ignored) { }
        }

        private void connectNow() {
            DerpClient c = null;
            try {
                Derp.Region r = map.region(region);
                IOException last = null;
                for (Derp.Node n : r.nodes()) {
                    if (n.stunOnly()) continue;
                    try {
                        com.simtechdata.jtail.Trace.log("derp", "connecting to region " + region + " node " + n.hostName());
                        c = DerpClient.connect(n, nodePriv, new DerpClient.Listener() {
                            @Override public void onPacket(byte[] src, byte[] data) {
                                com.simtechdata.jtail.Trace.log("derp", "rx " + data.length + "B from " + com.simtechdata.jtail.Trace.key(src) + " via region " + region);
                                receiver.onDerpPacket(region, src, data);
                            }
                            @Override public void onClosed(Throwable cause) { handleClosed(); }
                        });
                        break;
                    } catch (IOException e) { last = e; com.simtechdata.jtail.Trace.log("derp", "connect to " + n.hostName() + " FAILED: " + e); }
                }
                if (c == null) throw last != null ? last : new IOException("no usable DERP node in region " + region);
                com.simtechdata.jtail.Trace.log("derp", "connected to region " + region);
                if (home == region) c.notePreferred(true);
                synchronized (this) {
                    client = c;
                    connecting = false;
                    failures = 0;
                }
                flush(c);
            } catch (IOException | RuntimeException e) {
                com.simtechdata.jtail.Trace.log("derp", "region " + region + " unavailable: " + e);
                synchronized (this) { connecting = false; failures++; queue.clear(); }
                scheduleReconnect();
            }
        }

        private void flush(DerpClient c) {
            byte[][] item;
            while (true) {
                synchronized (this) { item = queue.pollFirst(); }
                if (item == null) return;
                try { c.send(item[0], item[1]); } catch (IOException e) { return; }
            }
        }

        void handleClosed() {
            synchronized (this) { client = null; }
            if (!closed && (home == region)) scheduleReconnect();
        }

        void scheduleReconnect() {
            if (closed) return;
            long delay = Math.min(30_000L, 500L << Math.min(failures, 6));
            if (home == region) timers.schedule(this::ensure, delay, TimeUnit.MILLISECONDS);
        }

        void send(byte[] dest, byte[] pkt) {
            DerpClient c = client;
            if (c != null && !c.isClosed()) {
                try { c.send(dest, pkt); return; } catch (IOException ignored) { c.close(); }
            }
            synchronized (this) {
                if (queue.size() >= 32) queue.pollFirst();
                queue.addLast(new byte[][]{dest, pkt});
            }
            ensure();
        }
    }

    @Override public void close() {
        closed = true;
        for (Conn c : conns.values()) { DerpClient d = c.client; if (d != null) d.close(); }
        conns.clear();
        connector.shutdownNow();
        timers.shutdownNow();
    }
}
