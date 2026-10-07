package com.simtechdata.jtail.state;

import com.simtechdata.jtail.JTailException;
import com.simtechdata.jtail.crypto.X25519;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Properties;

/**
 * The three long-lived key pairs a Tailscale node owns: machine (control-plane identity), node (WireGuard identity)
 * and disco (NAT-traversal). Persisting these lets a restarted deployment keep the same node and IP; generating
 * fresh ones registers a brand-new node.
 */
public final class NodeIdentity {
    private final byte[] machinePriv, nodePriv, discoPriv, nlPublic;

    private NodeIdentity(byte[] machinePriv, byte[] nodePriv, byte[] discoPriv, byte[] nlPublic) {
        this.machinePriv = machinePriv;
        this.nodePriv = nodePriv;
        this.discoPriv = discoPriv;
        this.nlPublic = nlPublic;
    }

    /**
     * Tailnet-lock public key (Ed25519). JTail does not participate in tailnet lock signing, so only the public half
     * is kept; it is sent at registration the way the Go client sends its own.
     */
    private static byte[] newNlPublic() {
        try {
            byte[] x509 = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic().getEncoded();
            return java.util.Arrays.copyOfRange(x509, x509.length - 32, x509.length);
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static NodeIdentity generate() {
        return new NodeIdentity(X25519.generatePrivate(), X25519.generatePrivate(), X25519.generatePrivate(), newNlPublic());
    }

    public byte[] machinePrivate() { return machinePriv.clone(); }
    public byte[] nodePrivate() { return nodePriv.clone(); }
    public byte[] discoPrivate() { return discoPriv.clone(); }
    public byte[] machinePublic() { return X25519.publicKey(machinePriv); }
    public byte[] nodePublic() { return X25519.publicKey(nodePriv); }
    public byte[] discoPublic() { return X25519.publicKey(discoPriv); }
    public byte[] nlPublic() { return nlPublic.clone(); }

    /** Loads the identity stored in {@code file}, or creates and saves a new one if the file does not exist. */
    public static NodeIdentity loadOrCreate(Path file) {
        try {
            if (Files.exists(file)) {
                Properties p = new Properties();
                try (InputStream in = Files.newInputStream(file)) { p.load(in); }
                String nl = p.getProperty("nl");
                NodeIdentity loaded = new NodeIdentity(
                        KeyText.decode(KeyText.MACHINE_PRIVATE, p.getProperty("machine")),
                        KeyText.decode(KeyText.MACHINE_PRIVATE, p.getProperty("node")),
                        KeyText.decode(KeyText.MACHINE_PRIVATE, p.getProperty("disco")),
                        nl == null ? newNlPublic() : KeyText.decode(KeyText.NODE_PUBLIC, nl));
                if (nl == null) loaded.save(file); // upgrade older identity files in place
                return loaded;
            }
            NodeIdentity id = generate();
            id.save(file);
            return id;
        } catch (IOException | RuntimeException e) {
            throw new JTailException("cannot load node identity from " + file, e);
        }
    }

    /** Atomically writes the identity with owner-only permissions where the filesystem supports it. */
    public void save(Path file) throws IOException {
        Path dir = file.toAbsolutePath().getParent();
        Files.createDirectories(dir);
        Path tmp = Files.createTempFile(dir, ".jtail-identity", ".tmp");
        try {
            try { Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-------")); }
            catch (UnsupportedOperationException ignored) { /* non-POSIX filesystem */ }
            Properties p = new Properties();
            p.setProperty("machine", KeyText.encode(KeyText.MACHINE_PRIVATE, machinePriv));
            p.setProperty("node", KeyText.encode(KeyText.MACHINE_PRIVATE, nodePriv));
            p.setProperty("disco", KeyText.encode(KeyText.MACHINE_PRIVATE, discoPriv));
            p.setProperty("nl", KeyText.encode(KeyText.NODE_PUBLIC, nlPublic));
            try (OutputStream out = Files.newOutputStream(tmp)) { p.store(out, "JTail node identity - keep secret"); }
            Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}
