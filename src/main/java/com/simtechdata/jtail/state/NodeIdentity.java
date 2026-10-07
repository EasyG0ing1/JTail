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
    private final byte[] machinePriv, nodePriv, discoPriv;

    private NodeIdentity(byte[] machinePriv, byte[] nodePriv, byte[] discoPriv) {
        this.machinePriv = machinePriv;
        this.nodePriv = nodePriv;
        this.discoPriv = discoPriv;
    }

    public static NodeIdentity generate() {
        return new NodeIdentity(X25519.generatePrivate(), X25519.generatePrivate(), X25519.generatePrivate());
    }

    public byte[] machinePrivate() { return machinePriv.clone(); }
    public byte[] nodePrivate() { return nodePriv.clone(); }
    public byte[] discoPrivate() { return discoPriv.clone(); }
    public byte[] machinePublic() { return X25519.publicKey(machinePriv); }
    public byte[] nodePublic() { return X25519.publicKey(nodePriv); }
    public byte[] discoPublic() { return X25519.publicKey(discoPriv); }

    /** Loads the identity stored in {@code file}, or creates and saves a new one if the file does not exist. */
    public static NodeIdentity loadOrCreate(Path file) {
        try {
            if (Files.exists(file)) {
                Properties p = new Properties();
                try (InputStream in = Files.newInputStream(file)) { p.load(in); }
                return new NodeIdentity(
                        KeyText.decode(KeyText.MACHINE_PRIVATE, p.getProperty("machine")),
                        KeyText.decode(KeyText.MACHINE_PRIVATE, p.getProperty("node")),
                        KeyText.decode(KeyText.MACHINE_PRIVATE, p.getProperty("disco")));
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
            try (OutputStream out = Files.newOutputStream(tmp)) { p.store(out, "JTail node identity - keep secret"); }
            Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}
