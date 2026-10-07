package com.simtechdata.jtail;

import java.time.LocalTime;

/**
 * Temporary diagnostic tracing to {@code System.err}. Enabled with {@code -Djtail.trace=true} (or the environment
 * variable {@code JTAIL_TRACE=true}); costs one boolean check per call site when disabled.
 */
public final class Trace {
    /** Whether tracing is on. */
    public static final boolean ON = Boolean.getBoolean("jtail.trace") || "true".equalsIgnoreCase(System.getenv("JTAIL_TRACE"));

    private Trace() {}

    /**
     * Prints one trace line.
     *
     * @param area short component tag, e.g. {@code wg}
     * @param msg  the message
     */
    public static void log(String area, String msg) {
        if (ON) System.err.println("[jtail-trace " + LocalTime.now().withNano(0) + "] " + area + ": " + msg);
    }

    /** Short hex of the first bytes of a key, for readable traces. */
    public static String key(byte[] k) {
        if (k == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(4, k.length); i++) sb.append(String.format("%02x", k[i]));
        return sb.toString();
    }
}
