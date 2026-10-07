package com.simtechdata.jtail;

import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Immutable settings for joining a tailnet.
 *
 * <p>Create one with {@link JTail#network()} and {@link Builder#build()}, then pass it to
 * {@link JTail#join(JTailConfig)}; or skip the intermediate object and call {@link Builder#join()} directly. The
 * getters on this class report the effective values after defaults were applied.
 *
 * @see JTail#network()
 */
public final class JTailConfig {
    /** Tailscale's hosted control server, used unless {@link Builder#controlUrl(String)} says otherwise. */
    public static final URI DEFAULT_CONTROL_URL = URI.create("https://controlplane.tailscale.com");

    private final String authKey;
    private final String hostname;
    private final URI controlUrl;
    private final Path stateDir;
    private final boolean ephemeral;
    private final List<String> advertiseTags;
    private final int udpPort;
    private final java.time.Duration joinTimeout;
    private final boolean includeLoopbackEndpoints;
    private final boolean allowInsecureControl;
    private final boolean acceptRoutes;
    private final boolean directPaths;
    private final java.util.function.Consumer<String> loginHandler;

    private JTailConfig(Builder b) {
        this.authKey = b.authKey;
        this.hostname = b.hostname;
        this.controlUrl = b.controlUrl;
        this.stateDir = b.stateDir;
        this.ephemeral = b.ephemeral;
        this.advertiseTags = List.copyOf(b.tags);
        this.udpPort = b.udpPort;
        this.joinTimeout = b.joinTimeout;
        this.includeLoopbackEndpoints = b.includeLoopback;
        this.allowInsecureControl = b.allowInsecureControl;
        this.acceptRoutes = b.acceptRoutes;
        this.directPaths = b.directPaths;
        this.loginHandler = b.loginHandler;
    }

    /** @return the auth key used to register the node, or {@code null} when interactive login is used */
    public String authKey() { return authKey; }
    /** @return the node's name as it will appear in the tailnet */
    public String hostname() { return hostname; }
    /** @return the control server URL */
    public URI controlUrl() { return controlUrl; }
    /** @return the directory where the node identity is persisted, or {@code null} for a throwaway in-memory identity */
    public Path stateDir() { return stateDir; }
    /** @return {@code true} if the node is removed from the tailnet automatically when it goes offline (default {@code false}) */
    public boolean ephemeral() { return ephemeral; }
    /** @return the ACL tags requested for this node, such as {@code tag:worker}; empty if none */
    public List<String> advertiseTags() { return advertiseTags; }
    /** @return the local UDP port for direct connections; {@code 0} means any free port */
    public int udpPort() { return udpPort; }
    /** @return how long {@code join()} waits for the node to become usable (default 60 seconds) */
    public java.time.Duration joinTimeout() { return joinTimeout; }
    /** @return whether loopback addresses are advertised as endpoints (only useful when several nodes share one host) */
    public boolean includeLoopbackEndpoints() { return includeLoopbackEndpoints; }
    /** @return whether a plain {@code http://} control URL is allowed for non-loopback hosts (default {@code false}) */
    public boolean allowInsecureControl() { return allowInsecureControl; }
    /** @return whether traffic for subnets advertised by peers (subnet routers) is routed in addition to tailnet addresses */
    public boolean acceptRoutes() { return acceptRoutes; }
    /** @return whether direct UDP paths between peers are attempted (default {@code true}); {@code false} relays everything via DERP */
    public boolean directPaths() { return directPaths; }
    /** @return the interactive-login handler, or {@code null} if none was configured */
    public java.util.function.Consumer<String> loginHandler() { return loginHandler; }

    /**
     * Fluent builder for {@link JTailConfig}. Every setter returns the builder so calls can be chained; finish with
     * {@link #join()} to connect or {@link #build()} to create a configuration without contacting the network.
     */
    public static final class Builder {
        private String authKey;
        private String hostname;
        private URI controlUrl = DEFAULT_CONTROL_URL;
        private Path stateDir;
        private boolean ephemeral = false;   // persistent node by default
        private final List<String> tags = new ArrayList<>();
        private int udpPort;
        private java.time.Duration joinTimeout = java.time.Duration.ofSeconds(60);
        private boolean includeLoopback;
        private boolean allowInsecureControl;
        private boolean acceptRoutes;
        private boolean directPaths = true;
        private java.util.function.Consumer<String> loginHandler;

        /**
         * Sets the auth key used to register the node without an interactive login. Required unless
         * {@link #onLoginRequired(java.util.function.Consumer)} is used.
         *
         * <p>Create a reusable key in the Tailscale admin console (Settings, Keys) or with
         * {@code headscale preauthkeys create}. Treat it like a password: read it from an environment variable rather
         * than hard-coding it.
         *
         * @param key an auth key such as {@code tskey-auth-...}
         * @return this builder
         */
        public Builder authKey(String key) { this.authKey = key; return this; }

        /**
         * Sets the node's name in the tailnet. Make it unique for each running instance of your program.
         *
         * @param name the hostname (letters, digits and hyphens work best); defaults to this machine's hostname
         * @return this builder
         */
        public Builder hostname(String name) { this.hostname = name; return this; }

        /**
         * Sets the control server to use, for example a self-hosted Headscale. Defaults to Tailscale's hosted server.
         *
         * <p>Use an {@code https://} URL. A plain {@code http://} URL is refused for any host other than the local
         * machine unless {@link #allowInsecureControl(boolean)} is enabled.
         *
         * @param url the control server URL
         * @return this builder
         * @throws IllegalArgumentException if the URL is malformed
         */
        public Builder controlUrl(String url) { this.controlUrl = URI.create(url); return this; }

        /**
         * Sets a directory where the node's identity (its private keys) is saved in {@code identity.properties}, so the
         * node keeps the same address after a restart. Without it a new identity, and therefore a new node, is created
         * on every run.
         *
         * <p>Protect the directory: anyone who can read it can impersonate the node. Do not share one directory between
         * instances that run at the same time.
         *
         * @param dir the directory; created if it does not exist
         * @return this builder
         */
        public Builder stateDir(Path dir) { this.stateDir = dir; return this; }

        /**
         * Sets whether the node is ephemeral: an ephemeral node is removed from the tailnet automatically when it goes
         * offline, which suits short-lived programs. The default is {@code false} (the node persists).
         *
         * @param value {@code true} for an ephemeral node
         * @return this builder
         */
        public Builder ephemeral(boolean value) { this.ephemeral = value; return this; }

        /**
         * Requests an ACL tag for the node, such as {@code tag:worker}. May be called several times. The auth key must
         * be permitted to apply the tag, otherwise registration fails.
         *
         * @param tag the tag, including the {@code tag:} prefix
         * @return this builder
         */
        public Builder tag(String tag) { this.tags.add(tag); return this; }

        /**
         * Fixes the local UDP port used for direct peer connections, for example because a firewall must allow it.
         *
         * @param port the UDP port, or {@code 0} (the default) for any free port
         * @return this builder
         */
        public Builder udpPort(int port) { this.udpPort = port; return this; }

        /**
         * Sets the maximum time {@code join()} blocks while registering and waiting for the first network map. The
         * default is 60 seconds. For interactive login, where a person must finish the login, use a longer value.
         *
         * @param d the timeout
         * @return this builder
         */
        public Builder joinTimeout(java.time.Duration d) { this.joinTimeout = d; return this; }

        /**
         * Also advertises loopback ({@code 127.0.0.1}) endpoints. Only useful for tests where several nodes run on one
         * machine; leave it off otherwise.
         *
         * @param v {@code true} to advertise loopback endpoints
         * @return this builder
         */
        public Builder includeLoopbackEndpoints(boolean v) { this.includeLoopback = v; return this; }

        /**
         * Permits a plain {@code http://} control URL for a non-loopback host. <strong>Insecure.</strong> The control server's key is fetched
         * over that URL, so an on-path attacker could impersonate the server and capture the auth key; only enable
         * this on a network you fully trust.
         *
         * @param v {@code true} to allow plaintext control URLs
         * @return this builder
         */
        public Builder allowInsecureControl(boolean v) { this.allowInsecureControl = v; return this; }

        /**
         * Controls NAT traversal. Disable to force every packet through DERP relays, e.g. when UDP is blocked or when
         * you do not want to reveal this host's addresses to peers. The default is {@code true}.
         *
         * @param v {@code false} to relay all traffic through DERP
         * @return this builder
         */
        public Builder directPaths(boolean v) { this.directPaths = v; return this; }

        /**
         * Routes traffic for subnets that peers advertise and the tailnet administrator approved (like
         * {@code tailscale up --accept-routes}), in addition to tailnet addresses. The default is {@code false}.
         *
         * @param v {@code true} to accept subnet routes
         * @return this builder
         */
        public Builder acceptRoutes(boolean v) { this.acceptRoutes = v; return this; }

        /**
         * Enables interactive login for deployments without an auth key: the handler receives a URL to open in a
         * browser, and {@code join()} blocks until the login completes. Use {@link #authKey} for unattended nodes.
         *
         * @param handler receives the login URL; show it to the user (print it, open a browser, ...)
         * @return this builder
         */
        public Builder onLoginRequired(java.util.function.Consumer<String> handler) { this.loginHandler = handler; return this; }

        /**
         * Validates the settings and creates an immutable configuration without contacting the network. Pass the result
         * to {@link JTail#join(JTailConfig)} when you are ready to connect.
         *
         * @return the configuration
         * @throws NullPointerException     if neither an auth key nor a login handler was set
         * @throws IllegalArgumentException if the auth key is blank or the control URL is not acceptable
         */
        public JTailConfig build() {
            if (authKey == null && loginHandler == null) {
                throw new NullPointerException("authKey is required (or provide onLoginRequired for interactive login)");
            }
            if (authKey != null && authKey.isBlank()) throw new IllegalArgumentException("authKey must not be blank");
            if (hostname == null) hostname = defaultHostname();
            checkControlUrl();
            return new JTailConfig(this);
        }

        /**
         * Builds the configuration and joins the tailnet, blocking until the node is registered and usable.
         *
         * @return the joined tailnet; the caller must {@link Tailnet#close() close} it
         * @throws JTailException           if registration fails, the control server is unreachable, interactive login
         *                                  is required but not configured, or the join times out
         * @throws NullPointerException     if neither an auth key nor a login handler was set
         * @throws IllegalArgumentException if the auth key is blank or the control URL is not acceptable
         */
        public Tailnet join() { return JTail.join(build()); }

        private void checkControlUrl() {
            String scheme = controlUrl.getScheme();
            if (scheme == null || !(scheme.equals("https") || scheme.equals("http"))) {
                throw new IllegalArgumentException("controlUrl must be http(s): " + controlUrl);
            }
            if (scheme.equals("http") && !allowInsecureControl) {
                String host = controlUrl.getHost();
                boolean local = host != null && (host.equals("localhost") || host.startsWith("127.") || host.equals("::1") || host.equals("[::1]"));
                if (!local) {
                    throw new IllegalArgumentException("refusing plaintext control URL " + controlUrl
                            + " (the auth key could be intercepted); use https or allowInsecureControl(true)");
                }
            }
        }

        private static String defaultHostname() {
            try { return java.net.InetAddress.getLocalHost().getHostName(); }
            catch (java.io.IOException e) { return "jtail-node"; }
        }
    }
}
