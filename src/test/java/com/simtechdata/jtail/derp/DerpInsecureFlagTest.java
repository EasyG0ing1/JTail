package com.simtechdata.jtail.derp;

import static org.junit.jupiter.api.Assertions.*;

import com.simtechdata.jtail.tailcfg.Derp;
import org.junit.jupiter.api.Test;

/** The control server's InsecureForTests flag must not disable certificate checks unless the JVM also opts in. */
class DerpInsecureFlagTest {
    static Derp.Node node(boolean insecureForTests) {
        return new Derp.Node("n", 1, "derp.example", "", "", "", 0, false, 443, insecureForTests, false);
    }

    @Test
    void serverFlagAloneIsIgnored() {
        String prior = System.getProperty(DerpClient.ALLOW_INSECURE_PROPERTY);
        try {
            System.clearProperty(DerpClient.ALLOW_INSECURE_PROPERTY);
            assertFalse(DerpClient.insecureAllowed(node(true)), "a remote DERP map must not turn off verification");
            System.setProperty(DerpClient.ALLOW_INSECURE_PROPERTY, "false");
            assertFalse(DerpClient.insecureAllowed(node(true)));
        } finally {
            restore(prior);
        }
    }

    @Test
    void localOptInIsRequiredAndSufficientOnlyWithTheServerFlag() {
        String prior = System.getProperty(DerpClient.ALLOW_INSECURE_PROPERTY);
        try {
            System.setProperty(DerpClient.ALLOW_INSECURE_PROPERTY, "true");
            assertTrue(DerpClient.insecureAllowed(node(true)));
            assertFalse(DerpClient.insecureAllowed(node(false)), "a relay that did not ask for it stays verified");
        } finally {
            restore(prior);
        }
    }

    static void restore(String prior) {
        if (prior == null) System.clearProperty(DerpClient.ALLOW_INSECURE_PROPERTY);
        else System.setProperty(DerpClient.ALLOW_INSECURE_PROPERTY, prior);
    }
}
