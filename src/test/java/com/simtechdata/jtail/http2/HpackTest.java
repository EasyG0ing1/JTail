package com.simtechdata.jtail.http2;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.Test;

/** HPACK edge cases that the RFC examples in Http2ClientTest do not reach. Malformed input must fail cleanly. */
class HpackTest {
    @Test
    void indexedStaticEntriesDecode() throws IOException {
        var hs = new Hpack.Decoder(4096).decode(new byte[]{(byte) 0x82, (byte) 0x87}); // :method GET, :scheme https
        assertEquals(":method", hs.get(0)[0]);
        assertEquals("GET", hs.get(0)[1]);
        assertEquals("https", hs.get(1)[1]);
    }

    @Test
    void indexOutOfRangeIsRejected() {
        assertThrows(IOException.class, () -> new Hpack.Decoder(4096).decode(new byte[]{(byte) 0xC8}), "index 72 with an empty dynamic table");
        assertThrows(IOException.class, () -> new Hpack.Decoder(4096).decode(new byte[]{(byte) 0x80}), "index 0 is never valid");
    }

    @Test
    void integerOverflowIsRejected() {
        byte[] block = {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x7F};
        assertThrows(IOException.class, () -> new Hpack.Decoder(4096).decode(block));
    }

    @Test
    void truncatedStringsAreRejected() {
        // literal with a 5-byte name that is only 2 bytes long
        assertThrows(IOException.class, () -> new Hpack.Decoder(4096).decode(new byte[]{0x00, 0x05, 'a', 'b'}));
    }

    @Test
    void tableSizeUpdateAboveTheAllowedMaximumIsRejected() {
        // 0x3F 0xE1 0x3F encodes a table-size update to 8192, which exceeds the 4096 this decoder allows
        assertThrows(IOException.class, () -> new Hpack.Decoder(4096).decode(new byte[]{0x3F, (byte) 0xE1, 0x3F}));
    }

    @Test
    void tableSizeUpdateWithinTheLimitEvictsEntries() throws IOException {
        Hpack.Decoder d = new Hpack.Decoder(4096);
        // literal with incremental indexing: new name "x-a", value "1" (goes to the dynamic table at index 62)
        d.decode(new byte[]{0x40, 0x03, 'x', '-', 'a', 0x01, '1'});
        assertEquals("x-a", d.decode(new byte[]{(byte) 0xBE}).get(0)[0], "entry is reachable before the update");
        d.decode(new byte[]{0x20});                         // size update to 0 evicts everything
        assertThrows(IOException.class, () -> d.decode(new byte[]{(byte) 0xBE}));
    }

    @Test
    void invalidHuffmanDataIsRejected() {
        // literal without indexing, new name encoded in Huffman with four 0xFF bytes (the EOS prefix)
        byte[] block = {0x00, (byte) 0x84, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x00};
        assertThrows(IOException.class, () -> new Hpack.Decoder(4096).decode(block));
    }

    @Test
    void encodedHeadersOfAnySizeRoundTrip() throws IOException {
        List<String[]> in = List.of(new String[]{"content-type", "application/json"},
                new String[]{"x-big", "z".repeat(20_000)});
        var out = new Hpack.Decoder(4096).decode(Hpack.encode(in));
        assertEquals(2, out.size());
        assertEquals("application/json", out.get(0)[1]);
        assertEquals(20_000, out.get(1)[1].length());
    }
}
