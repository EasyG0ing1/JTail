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
}
