package com.simtechdata.jtail.http2;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;

/** HPACK (RFC 7541) header compression: a full decoder and a simple non-indexing encoder. */
public final class Hpack {
    private Hpack() {}

    /** Lazily built binary decode tree for the Huffman code. */
    private static final int[][] TREE = buildTree();

    private static int[][] buildTree() {
        // node -> {child0, child1}; leaves encoded as -(symbol+1)
        List<int[]> nodes = new ArrayList<>();
        nodes.add(new int[]{0, 0});
        for (int sym = 0; sym < 256; sym++) {
            int code = HpackTables.CODES[sym], len = HpackTables.LENGTHS[sym], cur = 0;
            for (int i = len - 1; i >= 0; i--) {
                int bit = (code >>> i) & 1;
                if (i == 0) {
                    nodes.get(cur)[bit] = -(sym + 1);
                } else {
                    int next = nodes.get(cur)[bit];
                    if (next <= 0) {
                        next = nodes.size();
                        nodes.add(new int[]{0, 0});
                        nodes.get(cur)[bit] = next;
                    }
                    cur = next;
                }
            }
        }
        return nodes.toArray(new int[0][]);
    }

    static byte[] huffmanDecode(byte[] in, int off, int len) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(len * 2);
        int node = 0, bitsSinceSymbol = 0;
        boolean allOnes = true;
        for (int i = off; i < off + len; i++) {
            for (int b = 7; b >= 0; b--) {
                int bit = (in[i] >> b) & 1;
                int nxt = TREE[node][bit];
                bitsSinceSymbol++;
                allOnes &= bit == 1;
                if (nxt < 0) {
                    out.write(-nxt - 1);
                    node = 0;
                    bitsSinceSymbol = 0;
                    allOnes = true;
                } else if (nxt == 0) {
                    throw new IOException("hpack: invalid huffman code (EOS in data)");
                } else {
                    node = nxt;
                }
            }
        }
        if (bitsSinceSymbol > 7 || !allOnes) throw new IOException("hpack: invalid huffman padding");
        return out.toByteArray();
    }

    /** Header decoder holding the connection's dynamic table. One instance per HTTP/2 connection and direction. */
    public static final class Decoder {
        private final ArrayDeque<String[]> dynamic = new ArrayDeque<>(); // newest first
        private int dynamicSize;
        private int maxTableSize;
        private final int allowedMaxTableSize;

        public Decoder(int maxTableSize) {
            this.maxTableSize = maxTableSize;
            this.allowedMaxTableSize = maxTableSize;
        }

        public List<String[]> decode(byte[] block) throws IOException {
            List<String[]> out = new ArrayList<>();
            int[] pos = {0};
            while (pos[0] < block.length) {
                int b = block[pos[0]] & 0xFF;
                if ((b & 0x80) != 0) { // indexed
                    out.add(entry((int) readInt(block, pos, 7)));
                } else if ((b & 0xC0) == 0x40) { // literal with incremental indexing
                    String[] h = literal(block, pos, 6);
                    insert(h);
                    out.add(h);
                } else if ((b & 0xE0) == 0x20) { // dynamic table size update
                    int size = (int) readInt(block, pos, 5);
                    if (size > allowedMaxTableSize) throw new IOException("hpack: table size update too large");
                    maxTableSize = size;
                    evict();
                } else { // literal without indexing (0000) or never indexed (0001)
                    out.add(literal(block, pos, 4));
                }
            }
            return out;
        }

        private String[] literal(byte[] b, int[] pos, int prefix) throws IOException {
            int idx = (int) readInt(b, pos, prefix);
            String name = idx == 0 ? readString(b, pos) : entry(idx)[0];
            return new String[]{name, readString(b, pos)};
        }

        private String[] entry(int index) throws IOException {
            if (index <= 0) throw new IOException("hpack: zero index");
            if (index <= HpackTables.STATIC.length) return HpackTables.STATIC[index - 1];
            int d = index - HpackTables.STATIC.length - 1;
            if (d >= dynamic.size()) throw new IOException("hpack: index out of range " + index);
            int i = 0;
            for (String[] e : dynamic) if (i++ == d) return e;
            throw new IOException("hpack: index out of range");
        }

        private void insert(String[] h) {
            int size = 32 + h[0].getBytes(StandardCharsets.ISO_8859_1).length + h[1].getBytes(StandardCharsets.ISO_8859_1).length;
            dynamic.addFirst(h);
            dynamicSize += size;
            evict();
        }

        private void evict() {
            while (dynamicSize > maxTableSize && !dynamic.isEmpty()) {
                String[] e = dynamic.removeLast();
                dynamicSize -= 32 + e[0].getBytes(StandardCharsets.ISO_8859_1).length + e[1].getBytes(StandardCharsets.ISO_8859_1).length;
            }
        }
    }

    static long readInt(byte[] b, int[] pos, int prefixBits) throws IOException {
        int mask = (1 << prefixBits) - 1;
        long v = b[pos[0]++] & mask;
        if (v < mask) return v;
        int shift = 0;
        while (true) {
            if (pos[0] >= b.length) throw new IOException("hpack: truncated integer");
            int x = b[pos[0]++] & 0xFF;
            v += (long) (x & 0x7F) << shift;
            if (v > Integer.MAX_VALUE) throw new IOException("hpack: integer overflow");
            if ((x & 0x80) == 0) return v;
            shift += 7;
        }
    }

    private static String readString(byte[] b, int[] pos) throws IOException {
        if (pos[0] >= b.length) throw new IOException("hpack: truncated string");
        boolean huff = (b[pos[0]] & 0x80) != 0;
        int len = (int) readInt(b, pos, 7);
        if (pos[0] + len > b.length) throw new IOException("hpack: truncated string");
        byte[] raw = huff ? huffmanDecode(b, pos[0], len) : java.util.Arrays.copyOfRange(b, pos[0], pos[0] + len);
        pos[0] += len;
        return new String(raw, StandardCharsets.ISO_8859_1);
    }

    /** Encodes headers as literals without indexing (no dynamic table state, no Huffman). */
    public static byte[] encode(List<String[]> headers) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (String[] h : headers) {
            int nameIdx = 0;
            for (int i = 0; i < HpackTables.STATIC.length; i++) {
                if (HpackTables.STATIC[i][0].equals(h[0])) { nameIdx = i + 1; break; }
            }
            writeInt(out, nameIdx, 4, 0x00);
            if (nameIdx == 0) writeString(out, h[0]);
            writeString(out, h[1]);
        }
        return out.toByteArray();
    }

    private static void writeString(ByteArrayOutputStream out, String s) {
        byte[] b = s.getBytes(StandardCharsets.ISO_8859_1);
        writeInt(out, b.length, 7, 0x00);
        out.writeBytes(b);
    }

    static void writeInt(ByteArrayOutputStream out, long v, int prefixBits, int flags) {
        int mask = (1 << prefixBits) - 1;
        if (v < mask) { out.write(flags | (int) v); return; }
        out.write(flags | mask);
        v -= mask;
        while (v >= 128) { out.write((int) (v & 0x7F) | 0x80); v >>= 7; }
        out.write((int) v);
    }
}
