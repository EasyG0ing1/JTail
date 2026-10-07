package com.simtechdata.jtail.http2;

import static org.junit.jupiter.api.Assertions.*;

import com.simtechdata.jtail.crypto.Hex;
import com.simtechdata.jtail.testutil.Oracles;
import java.io.ByteArrayOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

class Http2ClientTest {
    @Test
    void hpackRfc7541Examples() throws Exception {
        // RFC 7541 C.4.1: Huffman-coded request "www.example.com"
        Hpack.Decoder d = new Hpack.Decoder(4096);
        var hs = d.decode(Hex.parse("828684418cf1e3c2e5f23a6ba0ab90f4ff"));
        assertEquals(":method", hs.get(0)[0]);
        assertEquals("GET", hs.get(0)[1]);
        assertEquals("www.example.com", hs.get(3)[1]);
        // C.4.2 reuses the dynamic table entry added above (index 62) and adds cache-control: no-cache
        hs = d.decode(Hex.parse("828684be5886a8eb10649cbf"));
        assertEquals(":authority", hs.get(3)[0]);
        assertEquals("www.example.com", hs.get(3)[1]);
        assertEquals("cache-control", hs.get(4)[0]);
        assertEquals("no-cache", hs.get(4)[1]);
    }

    @Test
    void hpackEncodeDecodeRoundTrip() throws Exception {
        List<String[]> in = List.of(new String[]{":method", "POST"}, new String[]{":path", "/machine/register"},
                new String[]{"x-custom-name", "v".repeat(300)});
        var out = new Hpack.Decoder(4096).decode(Hpack.encode(in));
        assertEquals(3, out.size());
        assertEquals("/machine/register", out.get(1)[1]);
        assertEquals(300, out.get(2)[1].length());
    }

    @Test
    void talksToGoH2Server() throws Exception {
        try (Oracles.Running o = Oracles.start("go-h2")) {
            String[] hp = o.line().substring(5).split(":");
            try (Socket sock = new Socket(hp[0], Integer.parseInt(hp[1]));
                 Http2Connection c = new Http2Connection(sock.getInputStream(), sock.getOutputStream())) {
                // echo with a body larger than the default 64K window and a custom header
                byte[] body = new byte[200_000];
                for (int i = 0; i < body.length; i++) body[i] = (byte) (i * 13);
                var r = c.request("POST", "localhost", "/echo", java.util.Collections.singletonList(new String[]{"x-custom", "hello"}), body);
                assertEquals(200, r.status());
                assertEquals("POST", r.header("x-seen-method"));
                assertEquals("hello", r.header("x-seen-header"));
                assertArrayEquals(body, r.readAll());

                // large response (> window) read on the same connection
                var big = c.request("GET", "localhost", "/big", null, null);
                assertEquals(300_000, big.readAll().length);

                // non-200 with body
                var tea = c.request("GET", "localhost", "/teapot", null, null);
                assertEquals(418, tea.status());
                assertEquals("short and stout\n", new String(tea.readAll(), StandardCharsets.UTF_8));

                // streaming: first chunk must arrive before the response ends
                var st = c.request("GET", "localhost", "/stream", null, null);
                var in = st.body();
                byte[] first = new byte[7];
                assertEquals(7, in.readNBytes(first, 0, 7));
                assertEquals("chunk0\n", new String(first, StandardCharsets.UTF_8));
                ByteArrayOutputStream rest = new ByteArrayOutputStream();
                in.transferTo(rest);
                assertEquals("chunk1\nchunk2\nchunk3\nchunk4\n", rest.toString(StandardCharsets.UTF_8));
            }
        }
    }
}
