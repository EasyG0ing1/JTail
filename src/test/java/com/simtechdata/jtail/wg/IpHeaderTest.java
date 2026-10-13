package com.simtechdata.jtail.wg;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

class IpHeaderTest {
    static byte[] v4(int totalLen, int padTo) {
        byte[] p = new byte[padTo];
        p[0] = 0x45;
        p[2] = (byte) (totalLen >> 8);
        p[3] = (byte) totalLen;
        System.arraycopy(new byte[]{100, 64, 0, 2}, 0, p, 12, 4);
        System.arraycopy(new byte[]{100, 64, 0, 1}, 0, p, 16, 4);
        return p;
    }

    @Test
    void readsAddressesAndVersion() {
        byte[] p = v4(20, 20);
        assertEquals(4, IpHeader.version(p));
        assertArrayEquals(new byte[]{100, 64, 0, 2}, IpHeader.src(p));
        assertArrayEquals(new byte[]{100, 64, 0, 1}, IpHeader.dst(p));

        byte[] six = new byte[40];
        six[0] = 0x60;
        six[8] = 1;   // src ::1 style marker
        six[24] = 2;  // dst marker
        assertEquals(6, IpHeader.version(six));
        assertEquals(16, IpHeader.src(six).length);
        assertEquals(16, IpHeader.dst(six).length);
        assertEquals(2, IpHeader.dst(six)[0], "IPv6 destination starts at byte 24");
    }

    @Test
    void unknownOrTruncatedPacketsHaveNoAddresses() {
        assertEquals(0, IpHeader.version(new byte[0]));
        assertEquals(9, IpHeader.version(new byte[]{(byte) 0x95}));
        assertNull(IpHeader.src(new byte[]{0x45, 0, 0}));
        assertNull(IpHeader.dst(new byte[]{0x45, 0, 0}));
        assertNull(IpHeader.src(new byte[]{(byte) 0x95}));
        assertNull(IpHeader.src(new byte[]{0x60, 0}));
        assertNull(IpHeader.dst(new byte[]{0x60, 0}));
    }

    @Test
    void trimRemovesWireGuardPaddingUsingTheLengthField() {
        byte[] padded = v4(28, 32);
        byte[] trimmed = IpHeader.trim(padded);
        assertNotNull(trimmed);
        assertEquals(28, trimmed.length);
        assertSame(trimmed, IpHeader.trim(trimmed), "an unpadded packet is returned as is");
        assertArrayEquals(Arrays.copyOf(padded, 28), trimmed);
    }

    @Test
    void trimRejectsMalformedLengths() {
        assertNull(IpHeader.trim(v4(40, 20)), "length field larger than the packet");
        assertNull(IpHeader.trim(v4(10, 20)), "length field below the minimum header size");
        assertNull(IpHeader.trim(new byte[]{0x45, 0, 0, 20}), "shorter than an IPv4 header");
        assertNull(IpHeader.trim(new byte[]{0x70, 0, 0, 0}), "unknown IP version");
        byte[] six = new byte[60];
        six[0] = 0x60;
        six[4] = 0;
        six[5] = 30;                     // payload length 30 => total 70 > 60
        assertNull(IpHeader.trim(six));
        six[5] = 10;                     // total 50 <= 60, trimmed
        assertEquals(50, IpHeader.trim(six).length);
    }
}
