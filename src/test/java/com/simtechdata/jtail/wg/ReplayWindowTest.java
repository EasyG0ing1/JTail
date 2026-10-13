package com.simtechdata.jtail.wg;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class ReplayWindowTest {
    @Test
    void acceptsEachCounterOnceAndRejectsReplays() {
        ReplayWindow w = new ReplayWindow();
        assertTrue(w.check(0));
        assertFalse(w.check(0), "a replayed counter must be rejected");
        assertTrue(w.check(5));
        assertTrue(w.check(3), "out-of-order counters inside the window are accepted once");
        assertFalse(w.check(3));
        assertFalse(w.check(-1), "negative counters are never valid");
    }

    @Test
    void rejectsCountersThatFellOutOfTheWindow() {
        ReplayWindow w = new ReplayWindow();
        assertTrue(w.check(10_000));
        assertFalse(w.check(1807), "more than 8192 behind the newest counter");
        assertFalse(w.check(1808), "the newest counter's own slot is a replay");
        assertTrue(w.check(1809), "just inside the window and never seen");
    }

    @Test
    void largeForwardJumpClearsOldState() {
        ReplayWindow w = new ReplayWindow();
        assertTrue(w.check(1));
        assertTrue(w.check(100_000));
        assertFalse(w.check(100_000));
        assertFalse(w.check(1), "counter 1 is far too old after the jump");
    }
}
