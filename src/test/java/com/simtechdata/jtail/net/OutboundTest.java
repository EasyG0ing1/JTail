package com.simtechdata.jtail.net;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

class OutboundTest {
    @Test
    void readLineStripsCrLfAndStopsAtTheNewline() throws IOException {
        ByteArrayInputStream in = new ByteArrayInputStream("HTTP/1.1 101\r\nUpgrade: x\r\n\r\nrest".getBytes());
        assertEquals("HTTP/1.1 101", Outbound.readLine(in));
        assertEquals("Upgrade: x", Outbound.readLine(in));
        assertEquals("", Outbound.readLine(in));
        assertEquals("rest", new String(in.readAllBytes()), "nothing past the line may be consumed");
    }

    @Test
    void readLineFailsOnEofAndOverlongLines() {
        assertThrows(EOFException.class, () -> Outbound.readLine(new ByteArrayInputStream(new byte[0])));
        byte[] huge = new byte[20_000];
        java.util.Arrays.fill(huge, (byte) 'a');
        assertThrows(IOException.class, () -> Outbound.readLine(new ByteArrayInputStream(huge)),
                "an unbounded header line would exhaust memory");
    }

    @Test @Timeout(20)
    void connectsDirectlyWhenNoProxyApplies() throws IOException {
        try (ServerSocket server = new ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
            try (Socket s = Outbound.connect("127.0.0.1", "127.0.0.1", server.getLocalPort(),
                    URI.create("https://127.0.0.1"), 5000)) {
                assertTrue(s.isConnected());
                assertTrue(s.getTcpNoDelay());
                try (Socket accepted = server.accept()) {
                    assertNotNull(accepted);
                }
            }
        }
    }

    @Test
    void connectionRefusedIsReportedAsIoException() throws IOException {
        int freePort;
        try (ServerSocket s = new ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) { freePort = s.getLocalPort(); }
        int port = freePort;
        assertThrows(IOException.class, () -> Outbound.connect("127.0.0.1", "127.0.0.1", port, URI.create("https://127.0.0.1"), 2000));
    }
}
