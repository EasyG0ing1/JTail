package com.simtechdata.jtail.wg;

import com.simtechdata.jtail.crypto.ChaCha20Poly1305;
import java.util.concurrent.atomic.AtomicLong;

/** A pair of transport keys derived from one handshake. */
final class Keypair {
    final ChaCha20Poly1305 send, recv;
    final int localIndex, remoteIndex;
    final boolean isInitiator;
    final long created = System.nanoTime();
    final AtomicLong sendCounter = new AtomicLong();
    final ReplayWindow replay = new ReplayWindow();

    Keypair(byte[] sendKey, byte[] recvKey, int localIndex, int remoteIndex, boolean isInitiator) {
        this.send = new ChaCha20Poly1305(sendKey);
        this.recv = new ChaCha20Poly1305(recvKey);
        this.localIndex = localIndex;
        this.remoteIndex = remoteIndex;
        this.isInitiator = isInitiator;
    }

    long ageNanos() { return System.nanoTime() - created; }
}
