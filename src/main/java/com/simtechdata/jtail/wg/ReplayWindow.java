package com.simtechdata.jtail.wg;

/** Sliding-window replay filter for WireGuard transport counters (RFC 6479 style, 8192-bit window). */
final class ReplayWindow {
    private static final int SIZE = 8192;
    private final long[] bitmap = new long[SIZE / 64];
    private long last = -1; // highest counter accepted so far, -1 = none

    /** Returns true and records {@code counter} if it is new and within the window. */
    synchronized boolean check(long counter) {
        if (counter < 0) return false;
        if (last < 0 || counter > last) {
            long diff = last < 0 ? SIZE : counter - last;
            if (diff >= SIZE) { java.util.Arrays.fill(bitmap, 0L); }
            else {
                for (long c = last + 1; c <= counter; c++) clear((int) (c & (SIZE - 1)));
            }
            set((int) (counter & (SIZE - 1)));
            last = counter;
            return true;
        }
        if (last - counter >= SIZE) return false; // too old
        int idx = (int) (counter & (SIZE - 1));
        if (get(idx)) return false;
        set(idx);
        return true;
    }

    private boolean get(int i) { return (bitmap[i >> 6] & (1L << (i & 63))) != 0; }
    private void set(int i) { bitmap[i >> 6] |= 1L << (i & 63); }
    private void clear(int i) { bitmap[i >> 6] &= ~(1L << (i & 63)); }
}
