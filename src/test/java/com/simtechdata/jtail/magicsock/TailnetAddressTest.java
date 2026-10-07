package com.simtechdata.jtail.magicsock;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import org.junit.jupiter.api.Test;

class TailnetAddressTest {
  private static boolean t(String ip) throws Exception { return Magicsock.isTailnetAddress(InetAddress.getByName(ip)); }

  @Test void tailnetRanges() throws Exception {
    assertTrue(t("100.127.47.13"));
    assertTrue(t("100.64.0.1"));
    assertTrue(t("fd7a:115c:a1e0::d2d:2f0e"));
  }

  @Test void physicalAddresses() throws Exception {
    assertFalse(t("192.168.1.11"));
    assertFalse(t("100.128.0.1"));
    assertFalse(t("100.63.255.255"));
    assertFalse(t("2600:6c51:607f:3a56::1"));
  }
}
