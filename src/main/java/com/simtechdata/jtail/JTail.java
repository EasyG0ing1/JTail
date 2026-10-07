package com.simtechdata.jtail;

/**
 * Entry point of the library: joins a tailnet and returns a {@link Tailnet}.
 *
 * <p>Joining takes one call. Configure the node with the builder returned by {@link #network()} and finish with
 * {@code join()}:
 * <pre>{@code
 * try (Tailnet net = JTail.network()
 *         .authKey(System.getenv("TS_AUTHKEY"))   // reusable auth key from the admin console
 *         .hostname("worker-" + id)               // unique per deployment
 *         .stateDir(Path.of("jtail-state"))       // optional: keep the same identity across restarts
 *         .join()) {
 *     Socket s = net.dial("db-server", 5432);
 * }
 * }</pre>
 *
 * <p>Run any number of deployments of the same program with one reusable auth key and distinct hostnames; each appears
 * as its own node in the tailnet.
 *
 * @see Tailnet
 * @see JTailConfig
 */
public final class JTail {
    private JTail() {}

    /**
     * Starts configuring a tailnet membership.
     *
     * <p>Call setters on the returned builder, then {@code join()} to connect or {@code build()} to create a reusable
     * {@link JTailConfig} without contacting the network. Only {@code authKey} is required (unless interactive login is
     * enabled with {@link JTailConfig.Builder#onLoginRequired}).
     *
     * @return a new builder with default settings
     */
    public static JTailConfig.Builder network() { return new JTailConfig.Builder(); }

    /**
     * Joins a tailnet using only an auth key, with defaults for everything else (hostname = this machine's name, no
     * persisted identity, not ephemeral, Tailscale's control server).
     *
     * <p>Equivalent to {@code network().authKey(authKey).join()}. The caller must {@link Tailnet#close() close} the
     * result.
     *
     * @param authKey an auth key such as {@code tskey-auth-...}; never hard-code it, read it from the environment
     * @return the joined tailnet
     * @throws JTailException if registration fails, the control server is unreachable, or the join times out
     * @throws NullPointerException if {@code authKey} is {@code null}
     * @throws IllegalArgumentException if {@code authKey} is blank
     */
    public static Tailnet join(String authKey) { return network().authKey(authKey).join(); }

    /**
     * Joins a tailnet using a prepared configuration, blocking until the node is registered and usable (bounded by
     * {@link JTailConfig#joinTimeout()}).
     *
     * @param config the settings, normally from {@link JTailConfig.Builder#build()}
     * @return the joined tailnet; the caller must {@link Tailnet#close() close} it
     * @throws JTailException if registration fails, the control server is unreachable, interactive login is required
     *                        but not configured, or the join times out
     */
    public static Tailnet join(JTailConfig config) {
        return TailnetNode.join(config);
    }
}
