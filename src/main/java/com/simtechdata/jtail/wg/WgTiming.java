package com.simtechdata.jtail.wg;

/**
 * WireGuard session timers (whitepaper section 6.1). The defaults are the protocol's constants; shorter values exist
 * so tests can exercise rekeying without waiting minutes. Interoperability requires the defaults.
 */
public record WgTiming(long rekeyAfterNanos, long rejectAfterNanos, long rekeyTimeoutNanos, long keepaliveTimeoutNanos,
                       long rekeyAttemptNanos) {
    private static final long S = 1_000_000_000L;
    public static final WgTiming DEFAULT = new WgTiming(120 * S, 180 * S, 5 * S, 10 * S, 90 * S);

    /** Compressed timers for tests (rekey after 2 s, hard expiry after 6 s). */
    public static WgTiming fastForTests() { return new WgTiming(2 * S, 6 * S, S, S, 10 * S); }
}
