package com.simtechdata.jtail.state;

import static org.junit.jupiter.api.Assertions.*;

import com.simtechdata.jtail.JTail;
import com.simtechdata.jtail.JTailConfig;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NodeIdentityTest {
    @Test
    void persistsAndReloadsSameKeys(@TempDir Path dir) {
        Path f = dir.resolve("sub/identity.properties");
        NodeIdentity a = NodeIdentity.loadOrCreate(f);
        NodeIdentity b = NodeIdentity.loadOrCreate(f);
        assertArrayEquals(a.nodePublic(), b.nodePublic());
        assertArrayEquals(a.machinePublic(), b.machinePublic());
        assertArrayEquals(a.discoPublic(), b.discoPublic());
        assertFalse(java.util.Arrays.equals(a.nodePublic(), a.machinePublic()));
        assertTrue(Files.exists(f));
    }

    @Test
    void keyTextRoundTripAndValidation() {
        byte[] k = new byte[32];
        k[5] = 7;
        assertArrayEquals(k, KeyText.decode(KeyText.NODE_PUBLIC, KeyText.encode(KeyText.NODE_PUBLIC, k)));
        assertThrows(IllegalArgumentException.class, () -> KeyText.decode(KeyText.NODE_PUBLIC, "nodekey:zz"));
    }

    @Test
    void builderRequiresAuthKeyAndAppliesDefaults() {
        assertThrows(NullPointerException.class, () -> JTail.network().build());
        JTailConfig c = JTail.network().authKey("tskey-auth-x").tag("tag:worker").ephemeral(true).build();
        assertEquals(JTailConfig.DEFAULT_CONTROL_URL, c.controlUrl());
        assertNotNull(c.hostname());
        assertEquals(java.util.List.of("tag:worker"), c.advertiseTags());
    }

    @Test
    void plaintextControlUrlIsRefusedUnlessLoopbackOrExplicit() {
        assertThrows(IllegalArgumentException.class,
                () -> JTail.network().authKey("k").controlUrl("http://control.example.com").build());
        assertDoesNotThrow(() -> JTail.network().authKey("k").controlUrl("http://127.0.0.1:8080").build());
        assertDoesNotThrow(() -> JTail.network().authKey("k").controlUrl("http://10.0.0.5").allowInsecureControl(true).build());
        assertThrows(IllegalArgumentException.class, () -> JTail.network().authKey("k").controlUrl("ftp://x").build());
    }

    @Test
    void rotateNodeKeyPersistsAndReportsOldKey(@TempDir Path dir) {
        Path f = dir.resolve("id.properties");
        NodeIdentity a = NodeIdentity.loadOrCreate(f);
        byte[] before = a.nodePublic();
        byte[] old = a.rotateNodeKey();
        assertArrayEquals(before, old);
        assertFalse(java.util.Arrays.equals(before, a.nodePublic()));
        assertArrayEquals(a.nodePublic(), NodeIdentity.loadOrCreate(f).nodePublic(), "rotated key must survive reload");
        assertArrayEquals(a.machinePublic(), NodeIdentity.loadOrCreate(f).machinePublic(), "machine key must not change");
    }

    @Test
    void ephemeralIsOffByDefault() {
        assertFalse(JTail.network().authKey("k").build().ephemeral());
        assertTrue(JTail.network().authKey("k").ephemeral(true).build().ephemeral());
    }
}
