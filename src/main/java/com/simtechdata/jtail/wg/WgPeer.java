package com.simtechdata.jtail.wg;

import com.simtechdata.jtail.tailcfg.IpPrefix;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.List;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.atomic.AtomicLong;

/** A remote WireGuard peer: its key, allowed IPs, session state and statistics. */
public final class WgPeer {
    final byte[] publicKey;
    final byte[] staticStatic;                  // X25519(ourPriv, peerPub), precomputed
    volatile List<IpPrefix> allowedIPs;
    volatile Object endpoint;                   // opaque path hint set from the transport layer
    volatile int persistentKeepaliveSeconds;
    private volatile Object userData;

    // guarded by this
    Keypair current, previous, next;
    Handshake.InitiatorState pending;
    long pendingSentNanos;
    long lastInitiationSentNanos;               // 0 = never
    long handshakeAttemptStartNanos;
    byte[] lastMac1Sent;
    byte[] cookie;
    long cookieNanos;
    byte[] lastTimestamp = new byte[12];
    long lastInitiationConsumedNanos;
    final ArrayDeque<byte[]> staged = new ArrayDeque<>();
    ScheduledFuture<?> retryTimer, keepaliveTimer, persistentTimer;
    boolean keepaliveScheduled;
    long lastSendNanos, lastReceiveNanos;
    volatile Instant lastHandshake;

    final AtomicLong rxBytes = new AtomicLong(), txBytes = new AtomicLong();

    WgPeer(byte[] publicKey, byte[] staticStatic, List<IpPrefix> allowedIPs) {
        this.publicKey = publicKey;
        this.staticStatic = staticStatic;
        this.allowedIPs = List.copyOf(allowedIPs);
    }

    byte[] staticSecret() { return staticStatic; }

    public byte[] publicKey() { return publicKey.clone(); }
    public List<IpPrefix> allowedIPs() { return allowedIPs; }
    public Object endpoint() { return endpoint; }
    public void setEndpoint(Object e) { this.endpoint = e; }
    public Instant lastHandshake() { return lastHandshake; }
    public long rxBytes() { return rxBytes.get(); }
    public long txBytes() { return txBytes.get(); }
    public Object userData() { return userData; }
    public void setUserData(Object o) { this.userData = o; }
    public void setPersistentKeepalive(int seconds) { this.persistentKeepaliveSeconds = seconds; }

    /** True if a session with usable keys exists right now. */
    public synchronized boolean hasSession() {
        return current != null && current.ageNanos() < WgConstants.REJECT_AFTER_TIME;
    }
}
