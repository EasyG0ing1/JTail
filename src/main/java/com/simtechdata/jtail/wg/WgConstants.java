package com.simtechdata.jtail.wg;

/** WireGuard protocol constants (whitepaper section 5.4 and 6.1). */
final class WgConstants {
    private WgConstants() {}

    static final byte MSG_INITIATION = 1, MSG_RESPONSE = 2, MSG_COOKIE = 3, MSG_TRANSPORT = 4;
    static final int INITIATION_LEN = 148, RESPONSE_LEN = 92, COOKIE_LEN = 64;
    static final int TRANSPORT_HEADER = 16, TAG = 16, MIN_TRANSPORT = TRANSPORT_HEADER + TAG;

    static final String CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    static final String IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com";
    static final String LABEL_MAC1 = "mac1----";
    static final String LABEL_COOKIE = "cookie--";

    static final long REKEY_AFTER_MESSAGES = 1L << 60;
    static final long REJECT_AFTER_MESSAGES = -1L - (1L << 13); // 2^64 - 2^13 - 1, as unsigned
    static final long NANOS = 1_000_000_000L;
    static final long REKEY_AFTER_TIME = 120 * NANOS;
    static final long REJECT_AFTER_TIME = 180 * NANOS;
    static final long REKEY_ATTEMPT_TIME = 90 * NANOS;
    static final long REKEY_TIMEOUT = 5 * NANOS;
    static final long KEEPALIVE_TIMEOUT = 10 * NANOS;
    static final int MAX_QUEUED_PACKETS = 128;
}
