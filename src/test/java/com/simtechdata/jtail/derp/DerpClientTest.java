package com.simtechdata.jtail.derp;

import static org.junit.jupiter.api.Assertions.*;

import com.simtechdata.jtail.crypto.X25519;
import com.simtechdata.jtail.tailcfg.Derp;
import com.simtechdata.jtail.testutil.Oracles;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

class DerpClientTest {
    record Got(byte[] src, byte[] data) {}

    static DerpClient connect(int port, byte[] priv, BlockingQueue<Got> sink) throws Exception {
        Derp.Node n = new Derp.Node("t1", 1, "127.0.0.1", "", "127.0.0.1", "none", -1, false, port, true, false);
        return DerpClient.connect(n, priv, new DerpClient.Listener() {
            @Override public void onPacket(byte[] src, byte[] data) { sink.add(new Got(src, data)); }
        });
    }

    @Test @Timeout(60)
    void relaysPacketsBetweenTwoClientsViaGoDerpServer() throws Exception {
        try (Oracles.Running o = Oracles.start("go-control")) {
            o.line(); // BASEURL
            int port = Integer.parseInt(o.line().substring("DERP ".length()));
            byte[] privA = X25519.generatePrivate(), privB = X25519.generatePrivate();
            BlockingQueue<Got> gotA = new LinkedBlockingQueue<>(), gotB = new LinkedBlockingQueue<>();
            try (DerpClient a = connect(port, privA, gotA); DerpClient b = connect(port, privB, gotB)) {
                a.notePreferred(true);
                b.notePreferred(true);
                byte[] pubA = X25519.publicKey(privA), pubB = X25519.publicKey(privB);

                byte[] pkt = new byte[1200];
                for (int i = 0; i < pkt.length; i++) pkt[i] = (byte) (i * 3);
                // B may not be registered yet at the server when A sends the first packet; retry briefly.
                Got g = null;
                for (int i = 0; i < 20 && g == null; i++) {
                    a.send(pubB, pkt);
                    g = gotB.poll(250, TimeUnit.MILLISECONDS);
                }
                assertNotNull(g, "B never received A's packet");
                assertArrayEquals(pubA, g.src());
                assertArrayEquals(pkt, g.data());

                b.send(pubA, "reply".getBytes());
                Got r = gotA.poll(5, TimeUnit.SECONDS);
                assertNotNull(r);
                assertArrayEquals(pubB, r.src());
                assertArrayEquals("reply".getBytes(), r.data());
            }
        }
    }
}
