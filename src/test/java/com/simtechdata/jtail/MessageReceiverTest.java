package com.simtechdata.jtail;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** {@code Tailnet.waitFor...}: accept one connection and read it to the end, with a shared, reused listener. */
class MessageReceiverTest {
    final ServerSocket listener;
    final AtomicInteger listenCalls = new AtomicInteger();
    final Tailnet tailnet;
    final ExecutorService ex = Executors.newCachedThreadPool();

    MessageReceiverTest() throws IOException {
        listener = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        tailnet = (Tailnet) Proxy.newProxyInstance(Tailnet.class.getClassLoader(), new Class<?>[]{Tailnet.class}, (proxy, m, args) -> {
            switch (m.getName()) {
                case "listen" -> { listenCalls.incrementAndGet(); return listener; }
                case "hashCode" -> { return System.identityHashCode(proxy); }
                case "equals" -> { return proxy == args[0]; }
                case "toString" -> { return "FakeTailnet"; }
                default -> throw new UnsupportedOperationException(m.getName());
            }
        });
    }

    @AfterEach void tearDown() throws IOException {
        ex.shutdownNow();
        listener.close();
    }

    Future<?> send(byte[] data, boolean linger) {
        return ex.submit(() -> {
            try (Socket s = new Socket(InetAddress.getLoopbackAddress(), listener.getLocalPort())) {
                s.getOutputStream().write(data);
                s.getOutputStream().flush();
                if (linger) Thread.sleep(2000);
            }
            return null;
        });
    }

    @Test @Timeout(30)
    void readsOneConnectionToEofAndReusesTheListener() throws Exception {
        Future<?> first = send("first message".getBytes(), false);
        assertArrayEquals("first message".getBytes(), MessageReceiver.receive(tailnet, 4000, null));
        first.get(5, TimeUnit.SECONDS);

        byte[] big = new byte[500_000];
        new java.util.Random(5).nextBytes(big);
        Future<?> second = send(big, false);
        assertArrayEquals(big, MessageReceiver.receive(tailnet, 4000, Duration.ofSeconds(10)));
        second.get(5, TimeUnit.SECONDS);

        assertEquals(1, listenCalls.get(), "one listener per tailnet and port, so back-to-back senders are queued");
        assertFalse(listener.isClosed());
    }

    @Test @Timeout(30)
    void emptyMessageIsAnEmptyArray() throws Exception {
        send(new byte[0], false);
        assertEquals(0, MessageReceiver.receive(tailnet, 4001, Duration.ofSeconds(10)).length);
    }

    @Test @Timeout(30)
    void timesOutWaitingForAConnectionButKeepsTheListener() throws Exception {
        long t0 = System.nanoTime();
        assertThrows(SocketTimeoutException.class, () -> MessageReceiver.receive(tailnet, 4002, Duration.ofMillis(300)));
        assertTrue(System.nanoTime() - t0 >= 250_000_000L);
        assertFalse(listener.isClosed(), "the next call must still be able to receive");

        send("late".getBytes(), false);
        assertArrayEquals("late".getBytes(), MessageReceiver.receive(tailnet, 4002, Duration.ofSeconds(10)));
        assertEquals(1, listenCalls.get());
    }

    @Test @Timeout(30)
    void aSenderThatStallsMidMessageHitsTheOverallDeadline() throws Exception {
        send("partial".getBytes(), true);                // connects, writes, then neither closes nor sends more
        long t0 = System.nanoTime();
        assertThrows(SocketTimeoutException.class, () -> MessageReceiver.receive(tailnet, 4003, Duration.ofMillis(500)));
        long elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0);
        assertTrue(elapsed < 1800, "the deadline covers the whole operation, not each read: " + elapsed + " ms");
    }

    @Test
    void argumentsAreValidatedBeforeListening() {
        assertThrows(IllegalArgumentException.class, () -> MessageReceiver.receive(tailnet, 0, null));
        assertThrows(IllegalArgumentException.class, () -> MessageReceiver.receive(tailnet, 65536, null));
        assertThrows(IllegalArgumentException.class, () -> MessageReceiver.receive(tailnet, 80, Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> MessageReceiver.receive(tailnet, 80, Duration.ofSeconds(-1)));
        assertEquals(0, listenCalls.get(), "invalid requests never open a listener");
    }
}
