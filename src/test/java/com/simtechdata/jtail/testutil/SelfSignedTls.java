package com.simtechdata.jtail.testutil;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;

/**
 * A throwaway self-signed server certificate for tests, generated with the {@code keytool} of the running JDK so no
 * test resource or private key has to be committed.
 */
public final class SelfSignedTls {
    private SelfSignedTls() {}

    /** Creates a PKCS12 keystore under {@code dir} and returns a server socket factory that presents its certificate. */
    public static SSLServerSocketFactory serverFactory(Path dir) throws Exception {
        Path keystore = dir.resolve("test-server.p12");
        Path keytool = Path.of(System.getProperty("java.home"), "bin", "keytool");
        Process p = new ProcessBuilder(keytool.toString(), "-genkeypair", "-alias", "test", "-keyalg", "RSA", "-keysize", "2048",
                "-dname", "CN=localhost", "-validity", "2", "-storetype", "PKCS12", "-keystore", keystore.toString(),
                "-storepass", "changeit", "-keypass", "changeit")
                .redirectErrorStream(true).start();
        String output;
        try (InputStream in = p.getInputStream()) { output = new String(in.readAllBytes()); }
        if (!p.waitFor(60, TimeUnit.SECONDS) || p.exitValue() != 0) throw new IllegalStateException("keytool failed: " + output);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystore)) { ks.load(in, "changeit".toCharArray()); }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "changeit".toCharArray());
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        return ctx.getServerSocketFactory();
    }
}
