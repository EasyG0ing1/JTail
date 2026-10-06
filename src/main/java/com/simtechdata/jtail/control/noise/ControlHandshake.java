package com.simtechdata.jtail.control.noise;

import com.simtechdata.jtail.crypto.ChaCha20Poly1305;
import com.simtechdata.jtail.crypto.X25519;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;

/**
 * Noise_IK handshake used by Tailscale's "ts2021" control protocol (control/controlbase).
 * The client initiation message is split from its continuation so it can ride inside the HTTP upgrade request.
 */
public final class ControlHandshake {
    static final int MSG_INITIATION = 1, MSG_RESPONSE = 2, MSG_ERROR = 3;
    static final int INIT_LEN = 101;
    static final int RESP_LEN = 51;
    private static final String VERSION_PREFIX = "Tailscale Control Protocol v";

    private ControlHandshake() {}

    private static byte[] prologue(int version) {
        return (VERSION_PREFIX + version).getBytes(StandardCharsets.US_ASCII);
    }

    /** State between sending the initiation and reading the server's response. */
    public static final class ClientPending {
        private final SymmetricState s;
        private final byte[] machinePriv, ephPriv, controlPub;
        private final int version;
        private final byte[] initiation;

        private ClientPending(SymmetricState s, byte[] machinePriv, byte[] ephPriv, byte[] controlPub,
                              int version, byte[] initiation) {
            this.s = s; this.machinePriv = machinePriv; this.ephPriv = ephPriv;
            this.controlPub = controlPub; this.version = version; this.initiation = initiation;
        }

        /** The 101-byte message to send first (typically base64'd into the X-Tailscale-Handshake header). */
        public byte[] initiationMessage() { return initiation.clone(); }

        /** Reads the server response from {@code in} and completes the handshake. */
        public NoiseConn finish(InputStream in, OutputStream out) throws IOException {
            byte[] hdr = readFully(in, 3);
            int type = hdr[0] & 0xFF;
            int len = ((hdr[1] & 0xFF) << 8) | (hdr[2] & 0xFF);
            if (type == MSG_ERROR) {
                throw new IOException("control server error: " + new String(readFully(in, len), StandardCharsets.UTF_8));
            }
            if (type != MSG_RESPONSE) throw new IOException("unexpected handshake response type " + type);
            if (len != RESP_LEN - 3) throw new IOException("wrong handshake response length " + len);
            byte[] payload = readFully(in, len);
            byte[] ctrlEph = Arrays.copyOfRange(payload, 0, 32);
            byte[] tag = Arrays.copyOfRange(payload, 32, 48);
            try {
                s.mixHash(ctrlEph);
                s.mixDH(ephPriv, ctrlEph);                                // ee
                ChaCha20Poly1305 c = s.mixDH(machinePriv, ctrlEph);       // se
                s.decryptAndHash(c, tag);
            } catch (AEADBadTagException e) {
                throw new IOException("handshake response authentication failed", e);
            }
            ChaCha20Poly1305[] ciphers = s.split();
            return new NoiseConn(in, out, ciphers[0], ciphers[1], s.h, controlPub, version);
        }
    }

    /** Builds the client initiation: {@code -> e, es, s, ss} after prologue and {@code <- s}. */
    public static ClientPending clientInit(byte[] machinePriv, byte[] controlPub, int version) {
        SymmetricState s = new SymmetricState();
        s.mixHash(prologue(version));
        s.mixHash(controlPub);

        byte[] ephPriv = X25519.generatePrivate();
        byte[] ephPub = X25519.publicKey(ephPriv);
        s.mixHash(ephPub);
        ChaCha20Poly1305 c = s.mixDH(ephPriv, controlPub);                         // es
        byte[] encMachine = s.encryptAndHash(c, X25519.publicKey(machinePriv));    // 48 bytes
        c = s.mixDH(machinePriv, controlPub);                                      // ss
        byte[] tag = s.encryptAndHash(c, new byte[0]);                             // 16 bytes

        byte[] init = new byte[INIT_LEN];
        init[0] = (byte) (version >> 8);
        init[1] = (byte) version;
        init[2] = MSG_INITIATION;
        init[3] = 0;
        init[4] = (byte) (INIT_LEN - 5);
        System.arraycopy(ephPub, 0, init, 5, 32);
        System.arraycopy(encMachine, 0, init, 37, 48);
        System.arraycopy(tag, 0, init, 85, 16);
        return new ClientPending(s, machinePriv, ephPriv, controlPub, version, init);
    }

    /** Synchronous convenience: sends the initiation on {@code out}, then finishes. */
    public static NoiseConn client(InputStream in, OutputStream out, byte[] machinePriv, byte[] controlPub,
                                   int version) throws IOException {
        ClientPending p = clientInit(machinePriv, controlPub, version);
        out.write(p.initiationMessage());
        out.flush();
        return p.finish(in, out);
    }

    /**
     * Server side of the handshake. JTail only needs this for loopback tests and for a future in-process
     * test control server; it mirrors controlbase.Server.
     */
    public static NoiseConn server(InputStream in, OutputStream out, byte[] controlPriv) throws IOException {
        byte[] init = readFully(in, INIT_LEN);
        int version = ((init[0] & 0xFF) << 8) | (init[1] & 0xFF);
        if (init[2] != MSG_INITIATION) throw new IOException("unexpected handshake message type");
        if ((((init[3] & 0xFF) << 8) | (init[4] & 0xFF)) != INIT_LEN - 5) throw new IOException("wrong length");

        SymmetricState s = new SymmetricState();
        s.mixHash(prologue(version));
        byte[] controlPub = X25519.publicKey(controlPriv);
        s.mixHash(controlPub);

        byte[] machEph = Arrays.copyOfRange(init, 5, 37);
        byte[] machineEnc = Arrays.copyOfRange(init, 37, 85);
        byte[] tag = Arrays.copyOfRange(init, 85, 101);
        byte[] machinePub;
        try {
            s.mixHash(machEph);
            ChaCha20Poly1305 c = s.mixDH(controlPriv, machEph);                    // es
            machinePub = s.decryptAndHash(c, machineEnc);
            c = s.mixDH(controlPriv, machinePub);                                  // ss
            s.decryptAndHash(c, tag);
        } catch (AEADBadTagException e) {
            throw new IOException("client initiation authentication failed", e);
        }

        byte[] ephPriv = X25519.generatePrivate();
        byte[] ephPub = X25519.publicKey(ephPriv);
        s.mixHash(ephPub);
        s.mixDH(ephPriv, machEph);                                                 // ee
        ChaCha20Poly1305 c = s.mixDH(ephPriv, machinePub);                         // se
        byte[] respTag = s.encryptAndHash(c, new byte[0]);

        byte[] resp = new byte[RESP_LEN];
        resp[0] = MSG_RESPONSE;
        resp[2] = (byte) (RESP_LEN - 3);
        System.arraycopy(ephPub, 0, resp, 3, 32);
        System.arraycopy(respTag, 0, resp, 35, 16);
        ChaCha20Poly1305[] ciphers = s.split();
        out.write(resp);
        out.flush();
        return new NoiseConn(in, out, ciphers[1], ciphers[0], s.h, machinePub, version);
    }

    static byte[] readFully(InputStream in, int n) throws IOException {
        byte[] b = new byte[n];
        int off = 0;
        while (off < n) {
            int r = in.read(b, off, n - off);
            if (r < 0) throw new EOFException();
            off += r;
        }
        return b;
    }
}
