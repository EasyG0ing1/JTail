package com.simtechdata.jtail.control.noise;

import static org.junit.jupiter.api.Assertions.*;

import com.simtechdata.jtail.crypto.X25519;
import java.io.*;
import java.util.Arrays;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;

class ControlHandshakeTest {
    /** A pair of connected in-memory pipes. */
    private static final class Pipe {
        final PipedInputStream aIn = new PipedInputStream(1 << 16), bIn = new PipedInputStream(1 << 16);
        final PipedOutputStream aOut, bOut;
        Pipe() throws IOException { aOut = new PipedOutputStream(bIn); bOut = new PipedOutputStream(aIn); }
    }

    @Test
    void clientServerHandshakeAndTransport() throws Exception {
        byte[] ctrlPriv = X25519.generatePrivate(), ctrlPub = X25519.publicKey(ctrlPriv);
        byte[] machPriv = X25519.generatePrivate(), machPub = X25519.publicKey(machPriv);
        Pipe p = new Pipe();
        ExecutorService ex = Executors.newSingleThreadExecutor();
        Future<NoiseConn> srv = ex.submit(() -> ControlHandshake.server(p.bIn, p.bOut, ctrlPriv));
        NoiseConn client = ControlHandshake.client(p.aIn, p.aOut, machPriv, ctrlPub, 88);
        NoiseConn server = srv.get(5, TimeUnit.SECONDS);

        assertEquals(88, server.protocolVersion());
        assertArrayEquals(machPub, server.peerPublicKey());
        assertArrayEquals(ctrlPub, client.peerPublicKey());
        assertArrayEquals(client.handshakeHash(), server.handshakeHash());

        byte[] big = new byte[10_000]; // spans multiple records
        for (int i = 0; i < big.length; i++) big[i] = (byte) (i * 31);
        Future<byte[]> got = ex.submit(() -> server.inputStream().readNBytes(big.length));
        client.write(big);
        assertArrayEquals(big, got.get(5, TimeUnit.SECONDS));

        Future<byte[]> back = ex.submit(() -> client.readRecord());
        server.write("hi".getBytes());
        assertArrayEquals("hi".getBytes(), back.get(5, TimeUnit.SECONDS));
        ex.shutdownNow();
    }

    @Test
    void wrongControlKeyIsRejected() throws Exception {
        byte[] ctrlPriv = X25519.generatePrivate();
        byte[] otherPub = X25519.publicKey(X25519.generatePrivate());
        byte[] machPriv = X25519.generatePrivate();
        Pipe p = new Pipe();
        ExecutorService ex = Executors.newSingleThreadExecutor();
        Future<NoiseConn> srv = ex.submit(() -> ControlHandshake.server(p.bIn, p.bOut, ctrlPriv));
        p.aOut.write(ControlHandshake.clientInit(machPriv, otherPub, 1).initiationMessage());
        assertThrows(ExecutionException.class, () -> srv.get(5, TimeUnit.SECONDS));
        ex.shutdownNow();
    }

    @Test
    void initiationLayout() {
        byte[] init = ControlHandshake.clientInit(X25519.generatePrivate(), X25519.publicKey(X25519.generatePrivate()), 0x0102)
                .initiationMessage();
        assertEquals(101, init.length);
        assertArrayEquals(new byte[]{1, 2, 1, 0, 96}, Arrays.copyOf(init, 5));
    }
}
