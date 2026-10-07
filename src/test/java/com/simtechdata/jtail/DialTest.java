package com.simtechdata.jtail;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.Socket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Behaviour of the fluent {@link Dial} request that needs no network: validation, immutability, encoding. */
class DialTest {
    /** Records what a Tailnet was asked to dial and captures the bytes written to the fake socket. */
    static final class Recorder {
        final List<String> dialed = new ArrayList<>();
        final ByteArrayOutputStream written = new ByteArrayOutputStream();
        boolean closed;
        int soTimeout;

        Tailnet tailnet() {
            return (Tailnet) Proxy.newProxyInstance(Tailnet.class.getClassLoader(), new Class<?>[]{Tailnet.class}, (proxy, m, args) -> {
                if (m.getName().equals("dial") && args != null && args.length == 3) {
                    dialed.add(args[0] + ":" + args[1] + "@" + args[2] + "ms");
                    return new Socket() {
                        @Override public OutputStream getOutputStream() { return written; }
                        @Override public void setSoTimeout(int t) { soTimeout = t; }
                        @Override public synchronized void close() { closed = true; }
                    };
                }
                throw new UnsupportedOperationException(m.getName());
            });
        }
    }

    @Test
    void sendConnectsWritesPayloadAndClosesTheSocket() throws Exception {
        Recorder r = new Recorder();
        new Dial(r.tailnet()).to("db").port(7000).timeout(Duration.ofSeconds(5)).payload("héllo").send();
        assertEquals(List.of("db:7000@5000ms"), r.dialed);
        assertArrayEquals("héllo".getBytes(java.nio.charset.StandardCharsets.UTF_8), r.written.toByteArray());
        assertTrue(r.closed, "the socket must be closed after sending");
        assertEquals(5000, r.soTimeout);
    }

    @Test
    void byteArrayPayloadIsCopiedAndSentVerbatim() throws Exception {
        Recorder r = new Recorder();
        byte[] data = {0, 1, 2, (byte) 255};
        Dial d = new Dial(r.tailnet()).to("db").port(1).payload(data);
        data[0] = 99;                                   // later mutation must not leak into the request
        d.send();
        assertArrayEquals(new byte[]{0, 1, 2, (byte) 255}, r.written.toByteArray());
    }

    @Test
    void requestsAreImmutableAndReusable() throws Exception {
        Recorder r = new Recorder();
        Dial base = new Dial(r.tailnet()).to("db").port(7000);
        Dial first = base.payload("one");
        Dial second = base.payload("two");
        assertNotSame(base, first);
        assertThrows(IllegalStateException.class, base::send, "the base request never got a payload");
        first.send();
        second.send();
        first.send();                                   // the same request can be sent again
        assertEquals("onetwoone", r.written.toString());
        assertEquals(3, r.dialed.size());
    }

    @Test
    void sendingWithMissingSettingsFailsFastWithAClearMessage() {
        Dial empty = new Dial(new Recorder().tailnet());
        assertTrue(assertThrows(IllegalStateException.class, empty::send).getMessage().contains("destination"));
        assertTrue(assertThrows(IllegalStateException.class, empty.to("x")::send).getMessage().contains("port"));
        assertTrue(assertThrows(IllegalStateException.class, empty.to("x").port(1)::send).getMessage().contains("payload"));
    }

    @Test
    void argumentsAreValidated() {
        Dial d = new Dial(new Recorder().tailnet());
        assertThrows(IllegalArgumentException.class, () -> d.port(0));
        assertThrows(IllegalArgumentException.class, () -> d.port(65536));
        assertThrows(IllegalArgumentException.class, () -> d.to("  "));
        assertThrows(IllegalArgumentException.class, () -> d.timeout(Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> d.timeout(Duration.ofSeconds(-1)));
        assertThrows(IllegalArgumentException.class, () -> d.timeout(Duration.ofDays(60)));
        assertThrows(NullPointerException.class, () -> d.to((String) null));
        assertThrows(NullPointerException.class, () -> d.to((Peer) null));
        assertThrows(NullPointerException.class, () -> d.payload((String) null));
        assertThrows(NullPointerException.class, () -> d.payload((byte[]) null));
        assertThrows(NullPointerException.class, () -> d.timeout(null));
    }

    @Test
    void toPeerPrefersTheIpv4Address() throws Exception {
        Recorder r = new Recorder();
        Peer p = new Peer("n.tailnet.ts.net", "n",
                List.of(InetAddress.getByName("fd7a:115c:a1e0::1"), InetAddress.getByName("100.64.0.9")), true, List.of());
        new Dial(r.tailnet()).to(p).port(5).payload("x").send();
        assertEquals("100.64.0.9:5@30000ms", r.dialed.get(0));
        assertThrows(IllegalArgumentException.class,
                () -> new Dial(r.tailnet()).to(new Peer("n", "n", List.of(), true, List.of())));
    }
}
