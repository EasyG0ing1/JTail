package com.simtechdata.jtail.netstack;

import java.io.IOException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.TreeMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * One TCP connection (a transmission control block): RFC 9293 state machine with RFC 6298 retransmission timing,
 * slow start / congestion avoidance / fast retransmit + NewReno recovery (RFC 5681/6582), window scaling (RFC 7323),
 * out-of-order reassembly and zero-window probing. Blocking {@link #read}/{@link #write} serve the socket adapters.
 */
public final class TcpConn {
    enum State { SYN_SENT, SYN_RCVD, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT, CLOSING, LAST_ACK, TIME_WAIT, CLOSED }

    /** Services the owning stack provides to a connection. */
    interface Host {
        void output(byte[] ipPacket);
        java.util.concurrent.ScheduledExecutorService timers();
        void connectionClosed(TcpConn c);
        void passiveEstablished(TcpConn c);
    }

    static final int SEND_BUF = 512 * 1024, RECV_BUF = 256 * 1024, RCV_WSCALE = 3;
    private static final long MIN_RTO_MS = 200, MAX_RTO_MS = 60_000, INITIAL_RTO_MS = 1000;
    private static final int MAX_RETRIES = 12, MAX_SYN_RETRIES = 6, MAX_OOO_SEGMENTS = 256;
    private static final long TIME_WAIT_MS = 10_000, FIN_WAIT2_MS = 60_000;
    private static final SecureRandom RNG = new SecureRandom();

    private final Host host;
    final byte[] localIp, remoteIp;
    final int localPort, remotePort;
    private final int baseMss;

    private State state;
    private final Object lock = new Object();

    // send side
    private int iss, sndUna, sndNxt, sndMax, sndWl1, sndWl2;
    private long sndWnd;
    private int sndWscale;
    private int mss;
    private final ByteRing sendQ = new ByteRing(SEND_BUF);
    private int sendBaseSeq;                 // sequence number of sendQ's first byte
    private boolean finQueued;
    private int finSeq;
    private long cwnd, ssthresh;
    private int dupAcks;
    private boolean inRecovery;
    private int recover;
    private long srttMs = -1, rttvarMs;
    private long rtoMs = INITIAL_RTO_MS;
    private int retries;
    private ScheduledFuture<?> rtoTimer, closeTimer;
    private int rttSeq;
    private long rttStartNanos;
    private boolean rttActive;

    // receive side
    private int irs, rcvNxt;
    private int rcvWscale;
    private final ByteRing recvQ = new ByteRing(RECV_BUF);
    private final TreeMap<Integer, byte[]> oooMap = new TreeMap<>((a, b) -> a - b); // out-of-order segments by seq
    private boolean finReceived;
    private boolean pendingFinSeqKnown;
    private int pendingFinSeq;
    private int lastAdvertisedWindow;

    // keepalive (SO_KEEPALIVE)
    private boolean keepAlive;
    private long kaIdleMs = 60_000, kaIntervalMs = 15_000;
    private int kaMaxProbes = 8, kaProbes;
    private long lastRecvNanos = System.nanoTime();
    private ScheduledFuture<?> kaTimer;

    // lifecycle
    private boolean appClosed, readShutdown;
    private IOException error;
    private boolean passive;
    private boolean notifiedPassive;

    private TcpConn(Host host, byte[] localIp, int localPort, byte[] remoteIp, int remotePort, int baseMss) {
        this.host = host;
        this.localIp = localIp;
        this.localPort = localPort;
        this.remoteIp = remoteIp;
        this.remotePort = remotePort;
        this.baseMss = baseMss;
    }

    // seq arithmetic
    private static boolean lt(int a, int b) { return (a - b) < 0; }
    private static boolean le(int a, int b) { return (a - b) <= 0; }
    private static boolean gt(int a, int b) { return (a - b) > 0; }
    private static boolean ge(int a, int b) { return (a - b) >= 0; }


    // ---- creation ----

    static TcpConn active(Host host, byte[] localIp, int localPort, byte[] remoteIp, int remotePort, int baseMss) {
        TcpConn c = new TcpConn(host, localIp, localPort, remoteIp, remotePort, baseMss);
        synchronized (c.lock) {
            c.iss = RNG.nextInt();
            c.sndUna = c.iss; c.sndNxt = c.iss + 1; c.sndMax = c.sndNxt;
            c.sendBaseSeq = c.iss + 1;
            c.mss = baseMss;
            c.cwnd = initialCwnd(baseMss);
            c.ssthresh = Long.MAX_VALUE / 4;
            c.rcvWscale = RCV_WSCALE;
            c.state = State.SYN_SENT;
            c.sendSyn(false);
            c.armRto();
        }
        return c;
    }

    static TcpConn passive(Host host, byte[] localIp, int localPort, byte[] remoteIp, int remotePort, int baseMss,
                           TcpSegment syn) {
        TcpConn c = new TcpConn(host, localIp, localPort, remoteIp, remotePort, baseMss);
        synchronized (c.lock) {
            c.passive = true;
            c.irs = syn.seq;
            c.rcvNxt = syn.seq + 1;
            c.iss = RNG.nextInt();
            c.sndUna = c.iss; c.sndNxt = c.iss + 1; c.sndMax = c.sndNxt;
            c.sendBaseSeq = c.iss + 1;
            c.mss = syn.mss > 0 ? Math.min(baseMss, syn.mss) : Math.min(baseMss, 536);
            if (syn.wscale >= 0) { c.sndWscale = syn.wscale; c.rcvWscale = RCV_WSCALE; } else { c.sndWscale = 0; c.rcvWscale = 0; }
            c.sndWnd = syn.window;
            c.sndWl1 = syn.seq;
            c.cwnd = initialCwnd(c.mss);
            c.ssthresh = Long.MAX_VALUE / 4;
            c.state = State.SYN_RCVD;
            c.sendSyn(true);
            c.armRto();
        }
        return c;
    }

    private static long initialCwnd(int mss) { return 10L * mss; }

    // ---- application API ----

    /** Waits for the three-way handshake to finish. */
    void awaitEstablished(long timeoutMs) throws IOException {
        long deadline = timeoutMs <= 0 ? Long.MAX_VALUE : System.nanoTime() / 1_000_000 + timeoutMs;
        synchronized (lock) {
            while (state == State.SYN_SENT || state == State.SYN_RCVD) {
                if (error != null) throw error;
                long left = deadline == Long.MAX_VALUE ? 1000 : deadline - System.nanoTime() / 1_000_000;
                if (left <= 0) { abortLocked(new SocketTimeoutException("connect timed out"), true); throw error; }
                waitLock(Math.min(left, 1000));
            }
            if (state == State.CLOSED && error != null) throw error;
        }
    }

    /** Reads up to {@code len} bytes; blocks until data, EOF (-1), error, or timeout (SocketTimeoutException). */
    public int read(byte[] b, int off, int len, long timeoutMs) throws IOException {
        if (len == 0) return 0;
        long deadline = timeoutMs <= 0 ? Long.MAX_VALUE : System.nanoTime() / 1_000_000 + timeoutMs;
        synchronized (lock) {
            while (true) {
                if (readShutdown) return -1;
                if (recvQ.size() > 0) {
                    int before = windowLocked();
                    int n = recvQ.read(b, off, len);
                    // announce reopened window promptly so a sender stalled on a closed window resumes
                    int after = windowLocked();
                    if (before < mss && after >= mss || after - lastAdvertisedWindow >= RECV_BUF / 2) sendAck();
                    return n;
                }
                if (error != null) throw error;
                if (finReceived || state == State.CLOSED || state == State.TIME_WAIT) return -1;
                long left = deadline == Long.MAX_VALUE ? 1000 : deadline - System.nanoTime() / 1_000_000;
                if (left <= 0) throw new SocketTimeoutException("read timed out");
                waitLock(Math.min(left, 1000));
            }
        }
    }

    public int available() {
        synchronized (lock) { return recvQ.size(); }
    }

    /** Queues bytes for sending, blocking while the send buffer is full. */
    public void write(byte[] b, int off, int len) throws IOException {
        synchronized (lock) {
            while (len > 0) {
                if (error != null) throw error;
                if (appClosed || finQueued) throw new SocketException("Socket output is shutdown");
                if (state != State.ESTABLISHED && state != State.CLOSE_WAIT) {
                    if (state == State.SYN_SENT || state == State.SYN_RCVD) { waitLock(100); continue; }
                    throw new SocketException("Broken pipe");
                }
                int n = sendQ.write(b, off, len);
                if (n == 0) { waitLock(250); continue; }
                off += n;
                len -= n;
                trySend();
            }
        }
    }

    /** Half-close: sends FIN after queued data; reading remains possible. */
    public void shutdownOutput() {
        synchronized (lock) {
            if (finQueued || state == State.CLOSED || state == State.SYN_SENT) return;
            finQueued = true;
            finSeq = sendBaseSeq + sendQ.size();
            if (state == State.ESTABLISHED || state == State.SYN_RCVD) state = State.FIN_WAIT_1;
            else if (state == State.CLOSE_WAIT) state = State.LAST_ACK;
            trySend();
            lock.notifyAll();
        }
    }

    public void shutdownInput() {
        synchronized (lock) { readShutdown = true; lock.notifyAll(); }
    }

    /** Graceful close: FIN after pending data; the connection object lingers until the peer finishes. */
    public void close() {
        synchronized (lock) {
            appClosed = true;
            if (state == State.SYN_SENT) { abortLocked(new SocketException("closed"), false); return; }
            readShutdown = true;
            if (recvQ.size() > 0 && state != State.CLOSED) { // unread data being discarded: RFC 9293 says reset
                abortLocked(new SocketException("closed with unread data"), true);
                return;
            }
        }
        shutdownOutput();
    }

    /** Immediately resets the connection. */
    public void abort() {
        synchronized (lock) { abortLocked(new SocketException("connection aborted"), true); }
    }

    public byte[] remoteAddress() { return remoteIp.clone(); }
    public int remotePort() { return remotePort; }
    public byte[] localAddress() { return localIp.clone(); }
    public int localPort() { return localPort; }

    /**
     * Enables or disables TCP keepalive: after {@code idleMs} without any traffic, probe every {@code intervalMs};
     * after {@code maxProbes} unanswered probes the connection is reset. Defaults are 60 s / 15 s / 8 probes.
     */
    public void setKeepAlive(boolean on, long idleMs, long intervalMs, int maxProbes) {
        synchronized (lock) {
            keepAlive = on;
            kaIdleMs = idleMs; kaIntervalMs = intervalMs; kaMaxProbes = maxProbes;
            if (kaTimer != null) { kaTimer.cancel(false); kaTimer = null; }
            if (on && state != State.CLOSED) kaTimer = host.timers().scheduleWithFixedDelay(this::keepAliveTick, intervalMs, intervalMs, TimeUnit.MILLISECONDS);
        }
    }

    public void setKeepAlive(boolean on) { setKeepAlive(on, 60_000, 15_000, 8); }

    private void keepAliveTick() {
        synchronized (lock) {
            if (!keepAlive || (state != State.ESTABLISHED && state != State.CLOSE_WAIT)) return;
            if (sndUna != sndMax) return; // data is in flight; retransmission timing already covers liveness
            long idleMs = (System.nanoTime() - lastRecvNanos) / 1_000_000L;
            if (idleMs < kaIdleMs) return;
            if (kaProbes >= kaMaxProbes) {
                abortLocked(new SocketTimeoutException("keepalive timed out"), true);
                return;
            }
            kaProbes++;
            TcpSegment s = new TcpSegment(); // a segment with an old sequence number forces the peer to ACK
            s.seq = sndUna - 1;
            s.ack = rcvNxt;
            s.flags = TcpSegment.ACK;
            s.window = advertisedWindowField();
            emit(s);
        }
    }

    /** Waits until everything written so far has been acknowledged (or the connection ends); true if drained. */
    public boolean awaitSendDrained(long timeoutMs) {
        long deadline = System.nanoTime() + timeoutMs * 1_000_000L;
        synchronized (lock) {
            while (state != State.CLOSED && state != State.TIME_WAIT && error == null
                    && (sendQ.size() > 0 || (finQueued && lt(sndUna, finSeq + 1)) || state == State.SYN_SENT || state == State.SYN_RCVD)) {
                long left = (deadline - System.nanoTime()) / 1_000_000L;
                if (left <= 0) return false;
                try { lock.wait(Math.min(left, 100)); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return false; }
            }
            return error == null;
        }
    }

    public boolean isClosed() { synchronized (lock) { return state == State.CLOSED; } }
    public boolean isInputShutdown() { synchronized (lock) { return readShutdown; } }
    public boolean isOutputShutdown() { synchronized (lock) { return finQueued; } }
    State state() { synchronized (lock) { return state; } }

    private void waitLock(long ms) throws InterruptedIOExceptionWrapper {
        try { lock.wait(ms); } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOExceptionWrapper(e);
        }
    }

    /** Unchecked carrier so wait helpers stay simple; converted to InterruptedIOException at API boundaries. */
    private static final class InterruptedIOExceptionWrapper extends java.io.InterruptedIOException {
        InterruptedIOExceptionWrapper(InterruptedException e) { super("interrupted"); initCause(e); }
    }

    // ---- segment output ----

    private int windowLocked() { return recvQ.free(); }

    private int advertisedWindowField() {
        int w = windowLocked() >> rcvWscale;
        lastAdvertisedWindow = w << rcvWscale;
        return Math.min(w, 0xFFFF);
    }

    private void emit(TcpSegment s) {
        s.srcPort = localPort;
        s.dstPort = remotePort;
        host.output(IpPacket.build(localIp, remoteIp, IpPacket.PROTO_TCP, s.build(localIp, remoteIp)));
    }

    private void sendSyn(boolean withAck) {
        TcpSegment s = new TcpSegment();
        s.seq = iss;
        s.flags = TcpSegment.SYN | (withAck ? TcpSegment.ACK : 0);
        s.ack = withAck ? rcvNxt : 0;
        s.window = Math.min(windowLocked(), 0xFFFF);
        s.mss = baseMss;
        if (!passive || rcvWscale > 0) s.wscale = rcvWscale;
        emit(s);
    }

    private void sendAck() {
        TcpSegment s = new TcpSegment();
        s.seq = sndNxt;
        s.ack = rcvNxt;
        s.flags = TcpSegment.ACK;
        s.window = advertisedWindowField();
        emit(s);
    }

    private void sendRst(int seq) {
        TcpSegment s = new TcpSegment();
        s.seq = seq;
        s.flags = TcpSegment.RST;
        emit(s);
    }

    /** Transmits as much queued data (and FIN) as the congestion and receive windows allow. */
    private void trySend() {
        if (state == State.SYN_SENT || state == State.SYN_RCVD || state == State.CLOSED || state == State.TIME_WAIT) return;
        while (true) {
            int inflight = sndNxt - sndUna;
            long wnd = Math.min(cwnd, sndWnd);
            long avail = wnd - inflight;
            int dataEnd = sendBaseSeq + sendQ.size();
            int unsent = dataEnd - sndNxt;
            if (unsent > 0) {
                int len;
                if (avail <= 0) {
                    if (sndWnd == 0 && inflight == 0) len = 1; // zero-window probe
                    else break;
                } else {
                    len = (int) Math.min(Math.min(mss, unsent), avail);
                }
                byte[] data = new byte[len];
                sendQ.peek(sndNxt - sendBaseSeq, data, 0, len);
                TcpSegment s = new TcpSegment();
                s.seq = sndNxt;
                s.ack = rcvNxt;
                s.flags = TcpSegment.ACK | (len == unsent ? TcpSegment.PSH : 0);
                s.window = advertisedWindowField();
                s.data = data;
                if (!rttActive && !inRecovery) { rttActive = true; rttSeq = sndNxt + len; rttStartNanos = System.nanoTime(); }
                emit(s);
                sndNxt += len;
                if (gt(sndNxt, sndMax)) sndMax = sndNxt;
                armRtoIfIdle();
            } else if (finQueued && sndNxt == finSeq) {
                TcpSegment s = new TcpSegment();
                s.seq = sndNxt;
                s.ack = rcvNxt;
                s.flags = TcpSegment.FIN | TcpSegment.ACK;
                s.window = advertisedWindowField();
                emit(s);
                sndNxt++;
                if (gt(sndNxt, sndMax)) sndMax = sndNxt;
                armRtoIfIdle();
            } else {
                break;
            }
        }
    }

    // ---- timers ----

    private void armRtoIfIdle() {
        if (rtoTimer == null || rtoTimer.isDone()) armRto();
    }

    private void armRto() {
        cancelRto();
        rtoTimer = host.timers().schedule(this::onRto, rtoMs, TimeUnit.MILLISECONDS);
    }

    private void cancelRto() {
        if (rtoTimer != null) { rtoTimer.cancel(false); rtoTimer = null; }
    }

    private void onRto() {
        synchronized (lock) {
            if (state == State.CLOSED || state == State.TIME_WAIT) return;
            if (sndUna == sndMax && !(state == State.SYN_SENT || state == State.SYN_RCVD)) { rtoTimer = null; return; }
            retries++;
            int limit = (state == State.SYN_SENT || state == State.SYN_RCVD) ? MAX_SYN_RETRIES : MAX_RETRIES;
            if (retries > limit) {
                abortLocked(new SocketTimeoutException(state == State.SYN_SENT ? "connect timed out" : "connection timed out"), state != State.SYN_SENT);
                return;
            }
            rtoMs = Math.min(rtoMs * 2, MAX_RTO_MS);
            rttActive = false; // Karn's algorithm: no samples from retransmitted segments
            if (state == State.SYN_SENT) sendSyn(false);
            else if (state == State.SYN_RCVD) sendSyn(true);
            else {
                ssthresh = Math.max((sndMax - sndUna) / 2L, 2L * mss);
                cwnd = mss;
                inRecovery = false;
                dupAcks = 0;
                sndNxt = sndUna;           // go-back-N from the first unacknowledged byte
                trySendForce();
            }
            rtoTimer = host.timers().schedule(this::onRto, rtoMs, TimeUnit.MILLISECONDS);
        }
    }

    /** Like {@link #trySend} but guarantees at least one segment goes out (the retransmission). */
    private void trySendForce() {
        long saved = sndWnd;
        if (sndWnd == 0) sndWnd = 1; // let the probe/retransmit through; real window restored on next ACK
        trySend();
        sndWnd = saved;
    }

    // ---- segment input ----

    void onSegment(TcpSegment seg) {
        synchronized (lock) {
            lastRecvNanos = System.nanoTime();
            kaProbes = 0;
            try {
                processLocked(seg);
            } finally {
                lock.notifyAll();
            }
        }
    }

    private void processLocked(TcpSegment seg) {
        switch (state) {
            case CLOSED -> { return; }
            case SYN_SENT -> { processSynSent(seg); return; }
            default -> { }
        }

        // acceptability check (RFC 9293 3.10.7.4)
        int segLen = seg.seqLen();
        int wnd = Math.max(windowLocked(), 0);
        boolean acceptable;
        if (segLen == 0) acceptable = wnd == 0 ? seg.seq == rcvNxt : (ge(seg.seq, rcvNxt) && lt(seg.seq, rcvNxt + wnd));
        else acceptable = wnd != 0 && ((ge(seg.seq, rcvNxt) && lt(seg.seq, rcvNxt + wnd))
                || (ge(seg.seq + segLen - 1, rcvNxt) && lt(seg.seq + segLen - 1, rcvNxt + wnd)));
        if (!acceptable) {
            if (!seg.has(TcpSegment.RST)) sendAck();
            return;
        }

        if (seg.has(TcpSegment.RST)) {
            abortLocked(new SocketException(state == State.SYN_RCVD ? "Connection refused" : "Connection reset"), false);
            return;
        }
        if (seg.has(TcpSegment.SYN)) { // SYN in window after establishment: peer is confused
            if (state == State.SYN_RCVD && seg.seq == irs) { sendSyn(true); return; } // retransmitted SYN
            sendRst(sndNxt);
            abortLocked(new SocketException("Connection reset"), false);
            return;
        }
        if (!seg.has(TcpSegment.ACK)) return;

        if (state == State.SYN_RCVD) {
            if (!(lt(sndUna, seg.ack) && le(seg.ack, sndNxt))) { sendRst(seg.ack); return; }
            state = State.ESTABLISHED;
            sndUna = seg.ack;
            retries = 0;
            cancelRto();
            updateWindow(seg);
            if (passive && !notifiedPassive) { notifiedPassive = true; host.passiveEstablished(this); }
        }

        processAck(seg);
        if (state == State.CLOSED) return;
        processData(seg);
    }

    private void processSynSent(TcpSegment seg) {
        if (seg.has(TcpSegment.ACK) && !(lt(iss, seg.ack) && le(seg.ack, sndNxt))) {
            if (!seg.has(TcpSegment.RST)) sendRst(seg.ack);
            return;
        }
        if (seg.has(TcpSegment.RST)) {
            if (seg.has(TcpSegment.ACK)) abortLocked(new SocketException("Connection refused"), false);
            return;
        }
        if (!seg.has(TcpSegment.SYN)) return;
        irs = seg.seq;
        rcvNxt = seg.seq + 1;
        if (seg.mss > 0) mss = Math.min(baseMss, seg.mss); else mss = Math.min(baseMss, 536);
        if (seg.wscale >= 0) sndWscale = seg.wscale; else { sndWscale = 0; rcvWscale = 0; }
        if (seg.has(TcpSegment.ACK)) {
            sndUna = seg.ack;
            sndWnd = seg.window;
            sndWl1 = seg.seq;
            sndWl2 = seg.ack;
            cwnd = initialCwnd(mss);
            state = State.ESTABLISHED;
            retries = 0;
            rtoMs = INITIAL_RTO_MS;
            cancelRto();
            sendAck();
        } else { // simultaneous open
            state = State.SYN_RCVD;
            sendSyn(true);
        }
    }

    private void updateWindow(TcpSegment seg) {
        if (lt(sndWl1, seg.seq) || (sndWl1 == seg.seq && le(sndWl2, seg.ack))) {
            sndWnd = (long) seg.window << sndWscale;
            sndWl1 = seg.seq;
            sndWl2 = seg.ack;
        }
    }

    private void processAck(TcpSegment seg) {
        int ack = seg.ack;
        if (gt(ack, sndMax)) { sendAck(); return; }          // acks data we never sent
        if (lt(ack, sndUna)) return;                          // stale
        boolean windowOpened = ((long) seg.window << sndWscale) > sndWnd;
        updateWindow(seg);

        if (ack == sndUna) {
            boolean dup = seg.data.length == 0 && !seg.has(TcpSegment.FIN) && sndUna != sndMax && !windowOpened;
            if (dup) {
                dupAcks++;
                if (dupAcks == 3 && !inRecovery) { // fast retransmit
                    ssthresh = Math.max((sndMax - sndUna) / 2L, 2L * mss);
                    recover = sndMax;
                    inRecovery = true;
                    cwnd = ssthresh + 3L * mss;
                    rttActive = false;
                    retransmitFirst();
                } else if (inRecovery) {
                    cwnd += mss;
                    trySend();
                }
            } else if (windowOpened) {
                trySend();
            }
            return;
        }

        // new data acknowledged
        int acked = ack - sndUna;
        boolean finAcked = finQueued && ge(ack, finSeq + 1);
        int fromQueue = ack - sendBaseSeq;                     // bytes of sendQ now acknowledged
        if (fromQueue > sendQ.size()) fromQueue = sendQ.size();
        if (fromQueue > 0) { sendQ.discard(fromQueue); sendBaseSeq += fromQueue; }
        sndUna = ack;
        if (lt(sndNxt, sndUna)) sndNxt = sndUna;
        retries = 0;
        dupAcks = 0;

        if (rttActive && ge(ack, rttSeq)) {
            long sample = Math.max(1, (System.nanoTime() - rttStartNanos) / 1_000_000);
            if (srttMs < 0) { srttMs = sample; rttvarMs = sample / 2; }
            else { rttvarMs = (3 * rttvarMs + Math.abs(srttMs - sample)) / 4; srttMs = (7 * srttMs + sample) / 8; }
            rtoMs = Math.max(MIN_RTO_MS, Math.min(MAX_RTO_MS, srttMs + Math.max(10, 4 * rttvarMs)));
            rttActive = false;
        }

        if (inRecovery) {
            if (ge(ack, recover)) { cwnd = ssthresh; inRecovery = false; }
            else { retransmitFirst(); cwnd = Math.max(cwnd - acked + mss, mss); } // NewReno partial ack
        } else if (cwnd < ssthresh) {
            cwnd += Math.min(acked, mss);
        } else {
            cwnd += Math.max(1L, (long) mss * mss / Math.max(cwnd, 1));
        }

        if (sndUna == sndMax) cancelRto(); else armRto();
        lock.notifyAll();   // writers waiting for buffer space

        if (finAcked) onFinAcked();
        trySend();
    }

    private void retransmitFirst() {
        int save = sndNxt;
        sndNxt = sndUna;
        int unsent = sendBaseSeq + sendQ.size() - sndNxt;
        if (unsent > 0) {
            int len = Math.min(mss, unsent);
            byte[] data = new byte[len];
            sendQ.peek(sndNxt - sendBaseSeq, data, 0, len);
            TcpSegment s = new TcpSegment();
            s.seq = sndNxt; s.ack = rcvNxt; s.flags = TcpSegment.ACK; s.window = advertisedWindowField(); s.data = data;
            emit(s);
        } else if (finQueued && sndNxt == finSeq) {
            TcpSegment s = new TcpSegment();
            s.seq = sndNxt; s.ack = rcvNxt; s.flags = TcpSegment.FIN | TcpSegment.ACK; s.window = advertisedWindowField();
            emit(s);
        }
        sndNxt = save;
    }

    private void onFinAcked() {
        switch (state) {
            case FIN_WAIT_1 -> {
                state = State.FIN_WAIT_2;
                scheduleClose(FIN_WAIT2_MS);
            }
            case CLOSING -> enterTimeWait();
            case LAST_ACK -> finish(null);
            default -> { }
        }
    }

    private void processData(TcpSegment seg) {
        boolean needAck = false;
        byte[] data = seg.data;
        int seq = seg.seq;
        if (data.length > 0 && (state == State.ESTABLISHED || state == State.FIN_WAIT_1 || state == State.FIN_WAIT_2)) {
            if (appClosed) { sendRst(sndNxt); abortLocked(new SocketException("data after close"), false); return; }
            // trim to the receive window and drop already-received prefix
            if (lt(seq, rcvNxt)) {
                int skip = rcvNxt - seq;
                if (skip >= data.length) { data = new byte[0]; } else { data = Arrays.copyOfRange(data, skip, data.length); seq = rcvNxt; }
            }
            int room = windowLocked() - (seq - rcvNxt);
            if (data.length > room) data = Arrays.copyOf(data, Math.max(room, 0));
            if (data.length > 0) {
                if (seq == rcvNxt) {
                    int n = recvQ.write(data, 0, data.length);
                    rcvNxt += n;
                    drainOoo();
                } else if (oooMap.size() < MAX_OOO_SEGMENTS) {
                    oooMap.put(seq, data);
                }
                needAck = true;
            } else if (seg.data.length > 0) {
                needAck = true;
            }
        }
        if (seg.has(TcpSegment.FIN)) {
            int finAt = seg.seq + seg.data.length;
            if (finAt == rcvNxt) acceptFin(); else { pendingFinSeqKnown = true; pendingFinSeq = finAt; }
            needAck = true;
        } else if (pendingFinSeqKnown && pendingFinSeq == rcvNxt) {
            acceptFin();
            needAck = true;
        }
        if (needAck) sendAck();
        if (recvQ.size() > 0 || finReceived) lock.notifyAll();
    }

    private void drainOoo() {
        while (!oooMap.isEmpty()) {
            var e = oooMap.firstEntry();
            int s = e.getKey();
            if (gt(s, rcvNxt)) break;
            oooMap.remove(s);
            byte[] d = e.getValue();
            int skip = rcvNxt - s;
            if (skip >= d.length) continue;
            int n = recvQ.write(d, skip, d.length - skip);
            rcvNxt += n;
            if (n < d.length - skip) break;
        }
        if (pendingFinSeqKnown && pendingFinSeq == rcvNxt) acceptFin();
    }

    private void acceptFin() {
        if (finReceived) return;
        finReceived = true;
        pendingFinSeqKnown = false;
        rcvNxt++;
        switch (state) {
            case ESTABLISHED -> state = State.CLOSE_WAIT;
            case FIN_WAIT_1 -> state = State.CLOSING; // our FIN is not yet acknowledged (else we'd be in FIN_WAIT_2)
            case FIN_WAIT_2 -> enterTimeWait();
            default -> { }
        }
    }

    private void enterTimeWait() {
        state = State.TIME_WAIT;
        cancelRto();
        scheduleClose(TIME_WAIT_MS);
    }

    private void scheduleClose(long ms) {
        if (closeTimer != null) closeTimer.cancel(false);
        closeTimer = host.timers().schedule(() -> { synchronized (lock) { finish(null); lock.notifyAll(); } }, ms, TimeUnit.MILLISECONDS);
    }

    // ---- teardown ----

    private void abortLocked(IOException cause, boolean sendReset) {
        if (state == State.CLOSED) return;
        if (sendReset && state != State.SYN_SENT && state != State.TIME_WAIT) sendRst(sndNxt);
        finish(cause);
    }

    private void finish(IOException cause) {
        if (state == State.CLOSED) return;
        state = State.CLOSED;
        if (cause != null && error == null) error = cause;
        cancelRto();
        if (closeTimer != null) closeTimer.cancel(false);
        if (kaTimer != null) kaTimer.cancel(false);
        lock.notifyAll();
        host.connectionClosed(this);
    }

    @Override public String toString() {
        return "TcpConn[" + localPort + "->" + remotePort + " " + state + "]";
    }
}
