package com.simtechdata.jtail.magicsock;

import com.simtechdata.jtail.crypto.NaClBox;
import com.simtechdata.jtail.tailcfg.IpPrefix;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Tailscale's "disco" NAT-traversal discovery protocol messages and their NaCl-box envelope
 * (port of tailscale.com/disco). Peer-relay messages (types 4-9) are intentionally not implemented.
 */
public final class Disco {
    private Disco() {}

    public static final byte[] MAGIC = "TS💬".getBytes(StandardCharsets.UTF_8); // "TS💬", 6 bytes
    public static final int TYPE_PING = 1, TYPE_PONG = 2, TYPE_CALL_ME_MAYBE = 3;
    private static final int KEY = 32, NONCE = 24;

    public sealed interface Message permits Ping, Pong, CallMeMaybe, Unknown {}

    /** @param nodeKey optional sender node key (32 bytes) or null; @param padding padding bytes length */
    public record Ping(byte[] txId, byte[] nodeKey, int padding) implements Message {}
    public record Pong(byte[] txId, InetSocketAddress src) implements Message {}
    public record CallMeMaybe(List<InetSocketAddress> endpoints) implements Message {}
    public record Unknown(int type) implements Message {}

    // ---- message encoding ----

    public static byte[] marshal(Message m) {
        if (m instanceof Ping p) {
            int n = 12 + (p.nodeKey != null ? 32 : 0) + p.padding;
            byte[] out = new byte[2 + n];
            out[0] = TYPE_PING;
            System.arraycopy(p.txId, 0, out, 2, 12);
            if (p.nodeKey != null) System.arraycopy(p.nodeKey, 0, out, 14, 32);
            return out;
        } else if (m instanceof Pong p) {
            byte[] out = new byte[2 + 12 + 18];
            out[0] = TYPE_PONG;
            System.arraycopy(p.txId, 0, out, 2, 12);
            putEndpoint(out, 14, p.src);
            return out;
        } else if (m instanceof CallMeMaybe c) {
            byte[] out = new byte[2 + 18 * c.endpoints.size()];
            out[0] = TYPE_CALL_ME_MAYBE;
            for (int i = 0; i < c.endpoints.size(); i++) putEndpoint(out, 2 + 18 * i, c.endpoints.get(i));
            return out;
        }
        throw new IllegalArgumentException("cannot marshal " + m);
    }

    private static void putEndpoint(byte[] out, int off, InetSocketAddress a) {
        byte[] ip = a.getAddress().getAddress();
        if (ip.length == 4) { // IPv4 as 4-in-6 mapped
            out[off + 10] = (byte) 0xff;
            out[off + 11] = (byte) 0xff;
            System.arraycopy(ip, 0, out, off + 12, 4);
        } else {
            System.arraycopy(ip, 0, out, off, 16);
        }
        out[off + 16] = (byte) (a.getPort() >> 8);
        out[off + 17] = (byte) a.getPort();
    }

    private static InetSocketAddress getEndpoint(byte[] b, int off) {
        byte[] ip = Arrays.copyOfRange(b, off, off + 16);
        boolean mapped = true;
        for (int i = 0; i < 10; i++) if (ip[i] != 0) mapped = false;
        if (mapped && ip[10] == (byte) 0xff && ip[11] == (byte) 0xff) ip = Arrays.copyOfRange(ip, 12, 16);
        int port = ((b[off + 16] & 0xFF) << 8) | (b[off + 17] & 0xFF);
        try {
            return new InetSocketAddress(InetAddress.getByAddress(ip), port);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /** Parses a decrypted message; returns null if malformed. */
    public static Message parse(byte[] p) {
        if (p.length < 2) return null;
        int type = p[0] & 0xFF;
        byte[] body = Arrays.copyOfRange(p, 2, p.length);
        switch (type) {
            case TYPE_PING: {
                if (body.length < 12) return null;
                byte[] tx = Arrays.copyOf(body, 12);
                int padding = body.length - 12;
                byte[] nk = null;
                if (body.length >= 12 + 32) {
                    byte[] k = Arrays.copyOfRange(body, 12, 44);
                    if (!Arrays.equals(k, new byte[32])) { nk = k; padding -= 32; }
                }
                return new Ping(tx, nk, padding);
            }
            case TYPE_PONG:
                if (body.length < 12 + 18) return null;
                return new Pong(Arrays.copyOf(body, 12), getEndpoint(body, 12));
            case TYPE_CALL_ME_MAYBE: {
                if (body.length % 18 != 0 || p[1] != 0 || body.length == 0) return new CallMeMaybe(List.of());
                List<InetSocketAddress> eps = new ArrayList<>();
                for (int i = 0; i < body.length; i += 18) eps.add(getEndpoint(body, i));
                return new CallMeMaybe(eps);
            }
            default:
                return new Unknown(type);
        }
    }

    // ---- envelope ----

    public static boolean looksLikeDisco(byte[] p) {
        if (p.length < MAGIC.length + KEY + NONCE) return false;
        for (int i = 0; i < MAGIC.length; i++) if (p[i] != MAGIC[i]) return false;
        return true;
    }

    /** The sender's disco public key from a disco-looking datagram. */
    public static byte[] source(byte[] p) { return Arrays.copyOfRange(p, MAGIC.length, MAGIC.length + KEY); }

    /** Builds the wire datagram: magic || ourDiscoPublic || nonce || box(message). */
    public static byte[] seal(byte[] ourDiscoPublic, NaClBox shared, Message m) {
        byte[] boxed = shared.sealWithNonce(marshal(m)); // nonce(24) || box
        byte[] out = new byte[MAGIC.length + KEY + boxed.length];
        System.arraycopy(MAGIC, 0, out, 0, MAGIC.length);
        System.arraycopy(ourDiscoPublic, 0, out, MAGIC.length, KEY);
        System.arraycopy(boxed, 0, out, MAGIC.length + KEY, boxed.length);
        return out;
    }

    /** Opens a disco datagram with the shared box for its sender; returns null on authentication failure. */
    public static Message open(byte[] datagram, NaClBox shared) {
        byte[] boxed = Arrays.copyOfRange(datagram, MAGIC.length + KEY, datagram.length);
        byte[] plain = shared.openWithNonce(boxed);
        return plain == null ? null : parse(plain);
    }

    static byte[] ipOf(String s) { return IpPrefix.parseIp(s); }
}
