package com.simtechdata.jtail;

/**
 * Entry point. Joining a tailnet takes one call:
 * <pre>{@code
 * try (Tailnet net = JTail.network()
 *         .authKey(System.getenv("TS_AUTHKEY"))
 *         .hostname("worker-" + id)
 *         .stateDir(Path.of("jtail-state"))
 *         .join()) {
 *     Socket s = net.dial("db-server", 5432);
 * }
 * }</pre>
 * Run any number of deployments with the same (reusable) auth key and distinct hostnames; each appears as its own
 * node in the tailnet.
 */
public final class JTail {
    private JTail() {}

    /** Starts configuring a tailnet membership. */
    public static JTailConfig.Builder network() { return new JTailConfig.Builder(); }

    /** Shortest form: join with just an auth key, using defaults for everything else. */
    public static Tailnet join(String authKey) { return network().authKey(authKey).join(); }

    /** Joins using an explicit config. */
    public static Tailnet join(JTailConfig config) {
        return TailnetNode.join(config);
    }
}
