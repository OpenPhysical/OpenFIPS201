package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import org.junit.jupiter.api.Test;

class PIVAttestationDerValidationTest {

  @Test
  void acceptsStructurallyValidNameAndValidity() {
    byte[] name = new byte[] {0x30, 0x03, 0x31, 0x01, 0x00};
    byte[] validity =
        new byte[] {
          0x30, 0x1E, 0x17, 0x0D, 0x32, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30,
          0x30, 0x5A, 0x17, 0x0D, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30,
          0x30, 0x5A
        };

    PIVAttestation.validateDerName(name, (short) 0, (short) name.length);
    PIVAttestation.validateDerValidity(validity, (short) 0, (short) validity.length);
  }

  @Test
  void rejectsMalformedDerProfileElements() {
    assertWrongData(
        () -> PIVAttestation.validateDerName(new byte[] {0x31, 0x00}, (short) 0, (short) 2));
    assertWrongData(
        () -> PIVAttestation.validateDerName(new byte[] {0x30, 0x00, 0x00}, (short) 0, (short) 3));
    assertWrongData(
        () -> PIVAttestation.validateDerName(new byte[] {0x30, (byte) 0x80}, (short) 0, (short) 2));
    assertWrongData(
        () ->
            PIVAttestation.validateDerName(
                new byte[] {0x30, (byte) 0x81, 0x01, 0x00}, (short) 0, (short) 4));
    assertWrongData(
        () ->
            PIVAttestation.validateDerValidity(
                new byte[] {0x30, 0x03, 0x16, 0x01, 0x5A}, (short) 0, (short) 5));
  }

  private static void assertWrongData(ThrowingRunnable runnable) {
    ISOException thrown = assertThrows(ISOException.class, runnable::run);
    assertEquals(ISO7816.SW_WRONG_DATA, thrown.getReason());
  }

  private interface ThrowingRunnable {
    void run();
  }
}
