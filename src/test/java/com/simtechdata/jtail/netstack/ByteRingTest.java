package com.simtechdata.jtail.netstack;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayDeque;
import java.util.Random;
import org.junit.jupiter.api.Test;

class ByteRingTest {
    @Test
    void behavesLikeAByteQueueUnderRandomOperations() {
        ByteRing r = new ByteRing(5000);
        ArrayDeque<Byte> model = new ArrayDeque<>();
        Random rnd = new Random(3);
        for (int i = 0; i < 20_000; i++) {
            int n = rnd.nextInt(700);
            if (rnd.nextBoolean()) {
                byte[] src = new byte[n];
                rnd.nextBytes(src);
                int w = r.write(src, 0, n);
                assertEquals(Math.min(n, 5000 - model.size()), w, "write must stop at the logical capacity");
                for (int k = 0; k < w; k++) model.addLast(src[k]);
            } else {
                byte[] dst = new byte[n];
                int g = r.read(dst, 0, n);
                assertEquals(Math.min(n, model.size()), g);
                for (int k = 0; k < g; k++) assertEquals(model.pollFirst(), dst[k], "bytes must come out in order");
            }
            assertEquals(model.size(), r.size());
            assertEquals(5000 - model.size(), r.free());
        }
    }

    @Test
    void peekDoesNotConsumeAndDiscardSkips() {
        ByteRing r = new ByteRing(64);
        r.write("abcdef".getBytes(), 0, 6);
        byte[] two = new byte[2];
        assertEquals(2, r.peek(3, two, 0, 2));
        assertEquals("de", new String(two));
        assertEquals(6, r.size(), "peek must not consume");
        assertEquals(0, r.peek(10, two, 0, 2), "offsets past the end read nothing");
        r.discard(4);
        assertEquals(2, r.read(two, 0, 2));
        assertEquals("ef", new String(two));
        assertEquals(0, r.read(two, 0, 2), "an empty buffer reads zero bytes, not -1");
    }

    @Test
    void growsOnDemandAndRespectsCapacityExactly() {
        ByteRing r = new ByteRing(1_000_000);
        byte[] data = new byte[300_000];
        new Random(9).nextBytes(data);
        assertEquals(data.length, r.write(data, 0, data.length));
        byte[] out = new byte[data.length];
        assertEquals(data.length, r.read(out, 0, out.length));
        assertArrayEquals(data, out);
        assertEquals(1_000_000, r.write(new byte[2_000_000], 0, 2_000_000), "accepts exactly its capacity");
        assertEquals(0, r.write(new byte[1], 0, 1), "full buffers accept nothing");
    }
}
