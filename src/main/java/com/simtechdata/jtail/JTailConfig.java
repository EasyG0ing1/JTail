package com.simtechdata.jtail;

import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Immutable settings for joining a tailnet. Build with {@link JTail#network()}. */
public final class JTailConfig {
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
    }

    public String authKey() { return authKey; }
    public String hostname() { return hostname; }
    public URI controlUrl() { return controlUrl; }
    /** Where the node identity is persisted, or {@code null} for a throwaway in-memory identity. */
    public Path stateDir() { return stateDir; }
    public boolean ephemeral() { return ephemeral; }
    public List<String> advertiseTags() { return advertiseTags; }
    /** Local UDP port for direct WireGuard/disco traffic; 0 picks a free port. */
    public int udpPort() { return udpPort; }
    /** How long {@link JTail#join} waits for the node to become usable. */
    public java.time.Duration joinTimeout() { return joinTimeout; }
    /** Advertise loopback addresses as endpoints (only useful when several nodes share one host, e.g. tests). */
    public boolean includeLoopbackEndpoints() { return includeLoopbackEndpoints; }

    /** Fluent builder; finish with {@link #join()} to connect. */
    public static final class Builder {
        private String authKey;
        private String hostname;
        private URI controlUrl = DEFAULT_CONTROL_URL;
        private Path stateDir;
        private boolean ephemeral;
        private final List<String> tags = new ArrayList<>();
        private int udpPort;
        private java.time.Duration joinTimeout = java.time.Duration.ofSeconds(60);
        private boolean includeLoopback;

        /** A reusable auth key (tskey-auth-...) created in the admin console. Required. */
        public Builder authKey(String key) { this.authKey = key; return this; }

        /** Name for this node. Defaults to the machine's hostname. Make it unique per deployment. */
        public Builder hostname(String name) { this.hostname = name; return this; }

        /** Alternative control server such as a self-hosted Headscale. Defaults to Tailscale's. */
        public Builder controlUrl(String url) { this.controlUrl = URI.create(url); return this; }

        /** Directory used to remember this node's identity across restarts. Omit for a throwaway node. */
        public Builder stateDir(Path dir) { this.stateDir = dir; return this; }

        /** Ephemeral nodes are automatically removed from the tailnet when they go offline. */
        public Builder ephemeral(boolean value) { this.ephemeral = value; return this; }

        /** Requests an ACL tag such as {@code tag:worker}; the auth key must be allowed to apply it. */
        public Builder tag(String tag) { this.tags.add(tag); return this; }

        /** Fixes the local UDP port used for direct peer connections (default: any free port). */
        public Builder udpPort(int port) { this.udpPort = port; return this; }

        /** Maximum time {@code join()} blocks while registering and waiting for the first network map. */
        public Builder joinTimeout(java.time.Duration d) { this.joinTimeout = d; return this; }

        /** Also advertise 127.0.0.1-style endpoints; for tests where several nodes run on one machine. */
        public Builder includeLoopbackEndpoints(boolean v) { this.includeLoopback = v; return this; }

        public JTailConfig build() {
            Objects.requireNonNull(authKey, "authKey is required");
            if (authKey.isBlank()) throw new IllegalArgumentException("authKey must not be blank");
            if (hostname == null) hostname = defaultHostname();
            return new JTailConfig(this);
        }

        /** Builds the config and joins the tailnet. */
        public Tailnet join() { return JTail.join(build()); }

        private static String defaultHostname() {
            try { return java.net.InetAddress.getLocalHost().getHostName(); }
            catch (java.io.IOException e) { return "jtail-node"; }
        }
    }
}
