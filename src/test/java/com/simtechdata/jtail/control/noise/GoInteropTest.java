package com.simtechdata.jtail.control.noise;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.simtechdata.jtail.crypto.Hex;
import com.simtechdata.jtail.crypto.X25519;
import java.io.*;
import java.net.Socket;
import java.nio.file.*;
import org.junit.jupiter.api.Test;

/**
 * Verifies wire compatibility against Tailscale's real Go controlbase.Server.
 * Enabled by -Djtail.oracle.dir=/dir/containing/go-oracle (see interop/build-oracle.sh); skipped otherwise.
 */
class GoInteropTest {
    @Test
    void javaClientTalksToGoServer() throws Exception {
        String dir = System.getProperty("jtail.oracle.dir");
        assumeTrue(dir != null && Files.isExecutable(Path.of(dir, "go-oracle")), "Go oracle not configured");
        Process p = new ProcessBuilder(Path.of(dir, "go-oracle").toString()).redirectErrorStream(true).start();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            String addr = r.readLine().substring("ADDR ".length());
            byte[] controlPub = Hex.parse(r.readLine().substring("PUB ".length()));
            String[] hp = addr.split(":");
            byte[] machPriv = X25519.generatePrivate();
            try (Socket s = new Socket(hp[0], Integer.parseInt(hp[1]))) {
                NoiseConn c = ControlHandshake.client(s.getInputStream(), s.getOutputStream(), machPriv, controlPub, 1);
                byte[] msg = new byte[9000];
                for (int i = 0; i < msg.length; i++) msg[i] = (byte) (i ^ (i >> 8));
                c.write(msg);
                assertArrayEquals(msg, c.inputStream().readNBytes(msg.length));
                String line = r.readLine();
                assertTrue(line.startsWith("HANDSHAKE_OK version=1 peer=" + Hex.of(X25519.publicKey(machPriv))), line);
            }
        } finally {
            p.destroy();
        }
    }
}
