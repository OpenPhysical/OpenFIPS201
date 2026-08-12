package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import org.junit.jupiter.api.Test;

class TLVLengthTest {

  @Test
  void writesAndReadsSupportedLengthForms() {
    byte[] buffer = new byte[8];

    assertEquals((short) 1, TLV.writeLength(buffer, (short) 0, (short) 0x7F));
    assertArrayEquals(new byte[] {(byte) 0x7F}, slice(buffer, 0, 1));

    assertEquals((short) 2, TLV.writeLength(buffer, (short) 0, (short) 0x80));
    assertArrayEquals(new byte[] {(byte) 0x81, (byte) 0x80}, slice(buffer, 0, 2));

    assertEquals((short) 3, TLV.writeLength(buffer, (short) 0, (short) 0x0100));
    assertArrayEquals(new byte[] {(byte) 0x82, (byte) 0x01, (byte) 0x00}, slice(buffer, 0, 3));

    byte[] tlv = new byte[] {(byte) 0x5F, (byte) 0xC1, (byte) 0x5A, (byte) 0x81, (byte) 0x80};
    assertEquals((short) 0x80, TLV.readLength(tlv, (short) 0, (short) tlv.length, false));
    assertEquals((short) 5, TLV.dataOffset(tlv, (short) 0, (short) tlv.length, false));
  }

  @Test
  void rejectsUnsupportedOrTruncatedLengths() {
    assertIsoReason(
        ISO7816.SW_WRONG_LENGTH, () -> TLV.writeLength(new byte[4], (short) 0, (short) -1));
    assertIsoReason(
        ISO7816.SW_WRONG_DATA,
        () -> TLV.readLength(new byte[] {0x30, (byte) 0x80}, (short) 0, (short) 2, true));
    assertIsoReason(
        ISO7816.SW_WRONG_DATA,
        () -> TLV.readLength(new byte[] {0x30, (byte) 0x83, 0, 0, 1}, (short) 0, (short) 5, true));
    assertIsoReason(
        ISO7816.SW_WRONG_DATA,
        () -> TLV.readLength(new byte[] {0x30, (byte) 0x82, 0x01}, (short) 0, (short) 3, true));
  }

  @Test
  void strictDerRejectsNonMinimalLengthForms() {
    assertIsoReason(
        ISO7816.SW_WRONG_DATA,
        () -> TLV.readLength(new byte[] {0x30, (byte) 0x81, 0x7F}, (short) 0, (short) 3, true));
    assertIsoReason(
        ISO7816.SW_WRONG_DATA,
        () ->
            TLV.readLength(
                new byte[] {0x30, (byte) 0x82, 0x00, (byte) 0x80}, (short) 0, (short) 4, true));

    assertEquals(
        (short) 0x7F,
        TLV.readLength(new byte[] {0x30, (byte) 0x81, 0x7F}, (short) 0, (short) 3, false));
  }

  @Test
  void computesObjectEndWithBoundsChecks() {
    byte[] object = new byte[] {0x30, 0x03, 0x01, 0x02, 0x03};
    assertEquals((short) 5, TLV.objectEnd(object, (short) 0, (short) object.length, true));
    assertIsoReason(ISO7816.SW_WRONG_DATA, () -> TLV.objectEnd(object, (short) 0, (short) 4, true));
  }

  private static byte[] slice(byte[] buffer, int offset, int length) {
    byte[] out = new byte[length];
    System.arraycopy(buffer, offset, out, 0, length);
    return out;
  }

  private static void assertIsoReason(short reason, ThrowingRunnable runnable) {
    ISOException thrown = assertThrows(ISOException.class, runnable::run);
    assertEquals(reason, thrown.getReason());
  }

  private interface ThrowingRunnable {
    void run();
  }
}
