package com.simtechdata.jtail;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class PeerTest {
  @Test
  void connectedReflectsOnline() {
    assertTrue(new Peer("a.ts.net", "a", List.of(), true, List.of()).connected());
    assertFalse(new Peer("b.ts.net", "b", List.of(), false, List.of()).connected());
  }
}
