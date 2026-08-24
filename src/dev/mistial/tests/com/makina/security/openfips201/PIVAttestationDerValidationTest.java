package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class PIVAttestationDerValidationTest {

  @Test
  void acceptsStructurallyValidNameAndValidity() {
    byte[] name = validName("Issuer");
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
  void rejectsMalformedNameHierarchyAndNonCanonicalTimes() {
    assertWrongData(
        () ->
            PIVAttestation.validateDerName(
                new byte[] {0x30, 0x03, 0x31, 0x01, 0x00}, (short) 0, (short) 5));
    assertWrongData(
        () ->
            PIVAttestation.validateDerValidity(
                validity("260101000000X", "300101000000Z"), (short) 0, (short) 32));
    assertWrongData(
        () ->
            PIVAttestation.validateDerValidity(
                validity("260230000000Z", "300101000000Z"), (short) 0, (short) 32));
    assertWrongData(
        () ->
            PIVAttestation.validateDerValidity(
                validity("300101000000Z", "260101000000Z"), (short) 0, (short) 32));
    assertWrongData(
        () ->
            PIVAttestation.validateDerValidity(
                new byte[] {
                  0x30, 0x20, 0x18, 0x0F, 0x32, 0x30, 0x34, 0x39, 0x30, 0x31, 0x30, 0x31, 0x30,
                  0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D, 0x34, 0x39, 0x30, 0x31, 0x30,
                  0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A
                },
                (short) 0,
                (short) 34));
  }

  @Test
  void rejectsMalformedDirectoryStringsAndUnsortedRdnSets() {
    assertWrongData(
        () ->
            PIVAttestation.validateDerName(
                new byte[] {
                  0x30,
                  0x0D,
                  0x31,
                  0x0B,
                  0x30,
                  0x09,
                  0x06,
                  0x03,
                  0x55,
                  0x04,
                  0x03,
                  0x0C,
                  0x02,
                  (byte) 0xC0,
                  (byte) 0xAF
                },
                (short) 0,
                (short) 15));
    assertWrongData(
        () ->
            PIVAttestation.validateDerName(
                new byte[] {
                  0x30, 0x0C, 0x31, 0x0A, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x01, 0x40
                },
                (short) 0,
                (short) 14));
    assertWrongData(
        () ->
            PIVAttestation.validateDerName(
                new byte[] {
                  0x30, 0x0C, 0x31, 0x0A, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x14, 0x01, 0x41
                },
                (short) 0,
                (short) 14));
    assertWrongData(
        () ->
            PIVAttestation.validateDerName(
                new byte[] {
                  0x30, 0x16, 0x31, 0x14, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x01,
                  0x42, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x01, 0x41
                },
                (short) 0,
                (short) 24));
  }

  @Test
  void interruptedIssuerNameCopyPreservesTheActiveProfile() throws Exception {
    try (MockedStatic<JCSystem> jcSystem = Mockito.mockStatic(JCSystem.class)) {
      jcSystem.when(JCSystem::getTransactionDepth).thenReturn((byte) 0);
      PIVAttestation attestation = new PIVAttestation();
      byte[] original = validName("Issuer One");
      byte[] replacement = validName("Issuer Two");
      attestation.updateElement(
          PIVAttestation.ELEMENT_SUBJECT, original, (short) 0, (short) original.length);
      attestation.markAuthorityActive();

      Field subjectField = PIVAttestation.class.getDeclaredField("subject");
      subjectField.setAccessible(true);
      byte[] activeBefore = ((byte[]) subjectField.get(attestation)).clone();

      try (MockedStatic<Util> util = Mockito.mockStatic(Util.class, Mockito.CALLS_REAL_METHODS)) {
        util.when(
                () ->
                    Util.arrayCopyNonAtomic(
                        Mockito.same(replacement),
                        Mockito.eq((short) 0),
                        Mockito.any(byte[].class),
                        Mockito.eq((short) 0),
                        Mockito.eq((short) replacement.length)))
            .thenAnswer(
                invocation -> {
                  byte[] destination = invocation.getArgument(2);
                  System.arraycopy(replacement, 0, destination, 0, 4);
                  throw new RuntimeException("simulated tear during persistent copy");
                });

        assertThrows(
            RuntimeException.class,
            () ->
                attestation.updateElement(
                    PIVAttestation.ELEMENT_SUBJECT,
                    replacement,
                    (short) 0,
                    (short) replacement.length));
      }

      assertArrayEquals(activeBefore, (byte[]) subjectField.get(attestation));
      assertTrue(attestation.isAuthorityActive());
    }
  }

  @Test
  void authorityActivationHasPersistentPendingAndCompletePhases() throws Exception {
    try (MockedStatic<JCSystem> jcSystem = Mockito.mockStatic(JCSystem.class)) {
      jcSystem.when(JCSystem::getTransactionDepth).thenReturn((byte) 0);
      PIVAttestation attestation = new PIVAttestation();
      java.lang.reflect.Method begin =
          PIVAttestation.class.getDeclaredMethod("beginAuthorityActivation");
      java.lang.reflect.Method pending =
          PIVAttestation.class.getDeclaredMethod("isAuthorityActivationPending");
      java.lang.reflect.Method complete =
          PIVAttestation.class.getDeclaredMethod("completeAuthorityActivation");

      begin.invoke(attestation);
      assertTrue((Boolean) pending.invoke(attestation));
      org.junit.jupiter.api.Assertions.assertFalse(attestation.isAuthorityActive());

      complete.invoke(attestation);
      org.junit.jupiter.api.Assertions.assertFalse((Boolean) pending.invoke(attestation));
      assertTrue(attestation.isAuthorityActive());
    }
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

  /** Confirms that a malformed DER fixture is rejected with {@code SW_WRONG_DATA}. */
  private static void assertWrongData(ThrowingRunnable runnable) {
    ISOException thrown = assertThrows(ISOException.class, runnable::run);
    assertEquals(ISO7816.SW_WRONG_DATA, thrown.getReason());
  }

  /**
   * Builds a canonical single-valued common-name RDN for positive validation tests.
   *
   * @param commonName UTF-8 common-name value
   * @return complete DER Name encoding
   */
  private static byte[] validName(String commonName) {
    byte[] value = commonName.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    byte[] encoded = new byte[value.length + 13];
    encoded[0] = 0x30;
    encoded[1] = (byte) (encoded.length - 2);
    encoded[2] = 0x31;
    encoded[3] = (byte) (encoded.length - 4);
    encoded[4] = 0x30;
    encoded[5] = (byte) (encoded.length - 6);
    encoded[6] = 0x06;
    encoded[7] = 0x03;
    encoded[8] = 0x55;
    encoded[9] = 0x04;
    encoded[10] = 0x03;
    encoded[11] = 0x0C;
    encoded[12] = (byte) value.length;
    System.arraycopy(value, 0, encoded, 13, value.length);
    return encoded;
  }

  /**
   * Builds a DER Validity sequence from two 13-octet RFC 5280 UTCTime values.
   *
   * @param notBefore first {@code YYMMDDHHMMSSZ} value
   * @param notAfter second {@code YYMMDDHHMMSSZ} value
   * @return complete DER Validity encoding
   */
  private static byte[] validity(String notBefore, String notAfter) {
    byte[] first = notBefore.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    byte[] second = notAfter.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    byte[] encoded = new byte[2 + 2 + first.length + 2 + second.length];
    encoded[0] = 0x30;
    encoded[1] = (byte) (encoded.length - 2);
    encoded[2] = 0x17;
    encoded[3] = (byte) first.length;
    System.arraycopy(first, 0, encoded, 4, first.length);
    short secondOffset = (short) (4 + first.length);
    encoded[secondOffset] = 0x17;
    encoded[(short) (secondOffset + 1)] = (byte) second.length;
    System.arraycopy(second, 0, encoded, secondOffset + 2, second.length);
    return encoded;
  }

  private interface ThrowingRunnable {
    void run();
  }
}
