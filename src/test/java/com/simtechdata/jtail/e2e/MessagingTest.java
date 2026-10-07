package com.simtechdata.jtail.e2e;

import static org.junit.jupiter.api.Assertions.*;

import com.simtechdata.jtail.JTail;
import com.simtechdata.jtail.Peer;
import com.simtechdata.jtail.Tailnet;
import com.simtechdata.jtail.testutil.Oracles;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.Random;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** Tailnet.dial().send() paired with Tailnet.waitFor...(), between two real JTail nodes. */
class MessagingTest {
    @Test @Timeout(120)
    void sendAndWaitForStringAndBytesBetweenNodes() throws Exception {
        try (Oracles.Running ctl = Oracles.start("go-control", "-authkey", "k")) {
            String url = ctl.expect("BASEURL ", 20_000).substring("BASEURL ".length());
            try (Tailnet a = JTail.network().authKey("k").hostname("msg-a").controlUrl(url).joinTimeout(Duration.ofSeconds(45)).join();
                 Tailnet b = JTail.network().authKey("k").hostname("msg-b").controlUrl(url).joinTimeout(Duration.ofSeconds(45)).join()) {
                ExecutorService ex = Executors.newCachedThreadPool();
                try {
                    // String, addressed by name
                    Future<String> text = ex.submit(() -> a.waitForString(9301, Duration.ofSeconds(30)));
                    Thread.sleep(300);                      // let the receiver start listening before sending
                    b.dial().to("msg-a").port(9301).timeout(Duration.ofSeconds(10)).payload("héllo tailnet").send();
                    assertEquals("héllo tailnet", text.get(30, TimeUnit.SECONDS));

                    // byte[] (binary, larger than one buffer), addressed by Peer
                    byte[] data = new byte[300_000];
                    new Random(3).nextBytes(data);
                    Future<byte[]> bytes = ex.submit(() -> a.waitForByteArray(9302));
                    Thread.sleep(300);
                    Peer peerA = b.peers().stream().filter(p -> p.name().startsWith("msg-a")).findFirst().orElseThrow();
                    b.dial().to(peerA).port(9302).payload(data).send();
                    assertArrayEquals(data, bytes.get(30, TimeUnit.SECONDS));

                    // empty message and the reverse direction
                    Future<String> empty = ex.submit(() -> b.waitForString(9303, Duration.ofSeconds(30)));
                    Thread.sleep(300);
                    a.dial().to(b.address().getHostAddress()).port(9303).payload("").send();
                    assertEquals("", empty.get(30, TimeUnit.SECONDS));

                    // messages sent while the receiver is between waitFor calls are queued, not refused
                    Future<String> first = ex.submit(() -> a.waitForString(9305, Duration.ofSeconds(30)));
                    Thread.sleep(300);
                    b.dial().to("msg-a").port(9305).timeout(Duration.ofSeconds(10)).payload("first").send();
                    assertEquals("first", first.get(30, TimeUnit.SECONDS));
                    b.dial().to("msg-a").port(9305).timeout(Duration.ofSeconds(10)).payload("second").send();
                    b.dial().to("msg-a").port(9305).timeout(Duration.ofSeconds(10)).payload("third").send();
                    assertEquals("second", a.waitForString(9305, Duration.ofSeconds(10)));
                    assertEquals("third", a.waitForString(9305, Duration.ofSeconds(10)));

                    // nothing arrives: the wait times out instead of hanging
                    long t0 = System.nanoTime();
                    assertThrows(SocketTimeoutException.class, () -> a.waitForString(9304, Duration.ofMillis(800)));
                    assertTrue((System.nanoTime() - t0) / 1_000_000 < 5000);

                    // nobody listening: send fails with a clear connection error
                    assertThrows(SocketException.class, () -> b.dial().to("msg-a").port(9399).timeout(Duration.ofSeconds(10)).payload("x").send());
                } finally {
                    ex.shutdownNow();
                }
            }
        }
    }
}
