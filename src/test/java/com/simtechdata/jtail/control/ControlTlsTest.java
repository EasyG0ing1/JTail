package com.simtechdata.jtail.control;

import static org.junit.jupiter.api.Assertions.*;

import java.net.ServerSocket;
import java.net.Socket;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.Test;

class ControlTlsTest {
    @Test
    void controlConnectionsVerifyTheServerHostname() throws Exception {
        try (ServerSocket server = new ServerSocket(0);
             Socket raw = new Socket("127.0.0.1", server.getLocalPort())) {
            // No handshake is started here, so no certificate is needed; we check the parameters the handshake will use.
            SSLSocket ssl = ControlClient.wrapTls(raw, "control.example", server.getLocalPort());
            try {
                assertEquals("HTTPS", ssl.getSSLParameters().getEndpointIdentificationAlgorithm(),
                        "a certificate must match the control host name, not just be signed by a trusted CA");
                assertTrue(ssl.getUseClientMode(), "JTail is the TLS client");
            } finally {
                ssl.close();
            }
        }
    }
}
