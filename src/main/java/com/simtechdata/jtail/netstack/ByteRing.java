package com.simtechdata.jtail.netstack;

/** A fixed-capacity circular byte buffer. Not thread-safe; callers synchronise. */
final class ByteRing {
    private final byte[] buf;
    private int head, size;

    ByteRing(int capacity) { buf = new byte[capacity]; }

    int size() { return size; }
    int capacity() { return buf.length; }
    int free() { return buf.length - size; }

    /** Appends up to {@code len} bytes; returns how many fit. */
    int write(byte[] src, int off, int len) {
        int n = Math.min(len, free());
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
    }

    int read(byte[] dst, int off, int len) {
        int n = peek(0, dst, off, len);
        discard(n);
        return n;
    }
}
