package com.simtechdata.jtail.control.noise;

import com.simtechdata.jtail.crypto.ChaCha20Poly1305;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;

/**
 * Post-handshake Noise transport: 1-byte type (4), 2-byte big-endian length, ChaCha20-Poly1305 ciphertext.
 * Nonces are 12 bytes: 4 zero bytes then a big-endian 64-bit counter (as in Tailscale's controlbase).
 */
public final class NoiseConn implements AutoCloseable {
    static final int MAX_MESSAGE = 4096;
    static final int HEADER = 3;
    static final int MAX_PLAINTEXT = MAX_MESSAGE - HEADER - ChaCha20Poly1305.TAG_SIZE;
    static final byte TYPE_RECORD = 4;

    private final InputStream in;
    private final OutputStream out;
    private final ChaCha20Poly1305 tx, rx;
    private final byte[] handshakeHash;
    private final byte[] peer;
    private final int version;
    private final Object txLock = new Object(), rxLock = new Object(); // independent: reads block while writes proceed
    private long txNonce, rxNonce;

    NoiseConn(InputStream in, OutputStream out, ChaCha20Poly1305 tx, ChaCha20Poly1305 rx,
              byte[] handshakeHash, byte[] peer, int version) {
        this.in = in;
        this.out = out;
        this.tx = tx;
        this.rx = rx;
        this.handshakeHash = handshakeHash;
        this.peer = peer;
        this.version = version;
    }

    public int protocolVersion() { return version; }
    public byte[] handshakeHash() { return handshakeHash.clone(); }
    public byte[] peerPublicKey() { return peer.clone(); }

    private static byte[] nonce(long counter) {
        byte[] n = new byte[ChaCha20Poly1305.NONCE_SIZE];
        for (int i = 0; i < 8; i++) n[11 - i] = (byte) (counter >>> (8 * i));
        return n;
    }

    /** Encrypts and sends data, splitting into records as needed. */
    public void write(byte[] data, int off, int len) throws IOException {
        synchronized (txLock) { writeLocked(data, off, len); }
    }

    private void writeLocked(byte[] data, int off, int len) throws IOException {
        while (len > 0) {
            int n = Math.min(len, MAX_PLAINTEXT);
            if (txNonce == -1L) throw new IOException("cipher exhausted");
            byte[] ct = tx.seal(nonce(txNonce++), Arrays.copyOfRange(data, off, off + n), null);
            byte[] msg = new byte[HEADER + ct.length];
            msg[0] = TYPE_RECORD;
            msg[1] = (byte) (ct.length >> 8);
            msg[2] = (byte) ct.length;
            System.arraycopy(ct, 0, msg, HEADER, ct.length);
            out.write(msg);
            off += n;
            len -= n;
        }
        out.flush();
    }

    public void write(byte[] data) throws IOException { write(data, 0, data.length); }

    /** Reads and decrypts exactly one record; returns its plaintext, or null on clean EOF at a record boundary. */
    public byte[] readRecord() throws IOException {
        synchronized (rxLock) { return readRecordLocked(); }
    }

    private byte[] readRecordLocked() throws IOException {
        byte[] hdr = new byte[HEADER];
        int first = in.read();
        if (first < 0) return null;
        hdr[0] = (byte) first;
        readFully(hdr, 1, HEADER - 1);
        if (hdr[0] != TYPE_RECORD) throw new IOException("unexpected message type " + hdr[0]);
        int len = ((hdr[1] & 0xFF) << 8) | (hdr[2] & 0xFF);
        if (HEADER + len > MAX_MESSAGE) throw new IOException("record too large: " + len);
        byte[] ct = new byte[len];
        readFully(ct, 0, len);
        try {
            return rx.open(nonce(rxNonce++), ct, null);
        } catch (AEADBadTagException e) {
            throw new IOException("record authentication failed", e);
        }
    }

    private void readFully(byte[] b, int off, int len) throws IOException {
        while (len > 0) {
            int n = in.read(b, off, len);
            if (n < 0) throw new EOFException();
            off += n;
            len -= n;
        }
    }

    /** Stream view over decrypted records, handy for layering HTTP/2 or line-based protocols. */
    public InputStream inputStream() {
        return new InputStream() {
            private byte[] cur = new byte[0];
            private int pos;

            @Override public int read() throws IOException {
                byte[] one = new byte[1];
                return read(one, 0, 1) < 0 ? -1 : one[0] & 0xFF;
            }

            @Override public int read(byte[] b, int off, int len) throws IOException {
                if (len == 0) return 0;
                while (pos >= cur.length) {
                    byte[] rec = readRecord();
                    if (rec == null) return -1;
                    cur = rec;
                    pos = 0;
                }
                int n = Math.min(len, cur.length - pos);
                System.arraycopy(cur, pos, b, off, n);
                pos += n;
                return n;
            }
        };
    }

    public OutputStream outputStream() {
        return new OutputStream() {
            @Override public void write(int b) throws IOException { NoiseConn.this.write(new byte[]{(byte) b}); }
            @Override public void write(byte[] b, int off, int len) throws IOException { NoiseConn.this.write(b, off, len); }
            @Override public void flush() throws IOException { out.flush(); }
        };
    }

    @Override public void close() throws IOException {
        try { out.close(); } finally { in.close(); }
    }
}
