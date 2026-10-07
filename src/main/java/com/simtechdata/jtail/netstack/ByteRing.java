package com.simtechdata.jtail.netstack;

/**
 * A circular byte buffer with a fixed logical capacity whose backing array grows on demand, so idle connections
 * do not each pin hundreds of kilobytes. Not thread-safe; callers synchronise.
 */
final class ByteRing {
    private static final int INITIAL = 16 * 1024;
    private final int capacity;
    private byte[] buf;
    private int head, size;

    ByteRing(int capacity) {
        this.capacity = capacity;
        this.buf = new byte[Math.min(capacity, INITIAL)];
    }

    int size() { return size; }
    int capacity() { return capacity; }
    int free() { return capacity - size; }

    private void ensure(int needed) {
        if (needed <= buf.length) return;
        int n = buf.length;
        while (n < needed) n = Math.min(capacity, n * 2);
        byte[] nb = new byte[n];
        peek(0, nb, 0, size);   // linearise into the new array
        buf = nb;
        head = 0;
    }

    /** Appends up to {@code len} bytes; returns how many fit within the logical capacity. */
    int write(byte[] src, int off, int len) {
        int n = Math.min(len, free());
        if (n == 0) return 0;
        ensure(size + n);
        int tail = (head + size) % buf.length;
        int first = Math.min(n, buf.length - tail);
        System.arraycopy(src, off, buf, tail, first);
        if (n > first) System.arraycopy(src, off + first, buf, 0, n - first);
        size += n;
        return n;
    }

    /** Copies up to {@code len} bytes starting {@code offset} bytes after the head, without consuming. */
    int peek(int offset, byte[] dst, int dstOff, int len) {
        if (offset >= size) return 0;
        int n = Math.min(len, size - offset);
        int start = (head + offset) % buf.length;
        int first = Math.min(n, buf.length - start);
        System.arraycopy(buf, start, dst, dstOff, first);
        if (n > first) System.arraycopy(buf, 0, dst, dstOff + first, n - first);
        return n;
    }

    void discard(int n) {
        n = Math.min(n, size);
        head = (head + n) % buf.length;
        size -= n;
        if (size == 0) head = 0;
    }

    int read(byte[] dst, int off, int len) {
        int n = peek(0, dst, off, len);
        discard(n);
        return n;
    }
}
