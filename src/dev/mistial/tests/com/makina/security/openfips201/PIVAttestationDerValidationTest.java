package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import org.junit.jupiter.api.Test;

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

    DERValidator.validateDerName(name, (short) 0, (short) name.length);
    DERValidator.validateDerValidity(validity, (short) 0, (short) validity.length);
  }

  @Test
  void rejectsMalformedNameHierarchyAndNonCanonicalTimes() {
    assertWrongData(
        () ->
            DERValidator.validateDerName(
                new byte[] {0x30, 0x03, 0x31, 0x01, 0x00}, (short) 0, (short) 5));
    assertWrongData(
        () ->
            DERValidator.validateDerValidity(
                validity("260101000000X", "300101000000Z"), (short) 0, (short) 32));
    assertWrongData(
        () ->
            DERValidator.validateDerValidity(
                validity("260230000000Z", "300101000000Z"), (short) 0, (short) 32));
    assertWrongData(
        () ->
            DERValidator.validateDerValidity(
                validity("300101000000Z", "260101000000Z"), (short) 0, (short) 32));
    assertWrongData(
        () ->
            DERValidator.validateDerValidity(
                new byte[] {
                  0x30, 0x20, 0x18, 0x0F, 0x32, 0x30, 0x34, 0x39, 0x30, 0x31, 0x30, 0x31, 0x30,
                  0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D, 0x34, 0x39, 0x30, 0x31, 0x30,
                  0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A
                },
                (short) 0,
                (short) 34));
  }

  @Test
  void rejectsSameYearInvertedValidity() {
    // The years compare equal, so the month-through-second fields decide the order.
    assertWrongData(
        () ->
            DERValidator.validateDerValidity(
                validity("260601000000Z", "260101000000Z"), (short) 0, (short) 32));
    assertWrongData(
        () ->
            DERValidator.validateDerValidity(
                validity("260101000001Z", "260101000000Z"), (short) 0, (short) 32));
    byte[] equal = validity("260101000000Z", "260101000000Z");
    DERValidator.validateDerValidity(equal, (short) 0, (short) equal.length);
  }

  @Test
  void rejectsMalformedDirectoryStringsAndUnsortedRdnSets() {
    assertWrongData(
        () ->
            DERValidator.validateDerName(
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
            DERValidator.validateDerName(
                new byte[] {
                  0x30, 0x0C, 0x31, 0x0A, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x01, 0x40
                },
                (short) 0,
                (short) 14));
    assertWrongData(
        () ->
            DERValidator.validateDerName(
                new byte[] {
                  0x30, 0x0C, 0x31, 0x0A, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x14, 0x01, 0x41
                },
                (short) 0,
                (short) 14));
    assertWrongData(
        () ->
            DERValidator.validateDerName(
                new byte[] {
                  0x30, 0x16, 0x31, 0x14, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x01,
                  0x42, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x01, 0x41
                },
                (short) 0,
                (short) 24));
  }

  @Test
  void utf8AcceptsMultibyteAndRejectsOverlongForms() {
    assertAcceptedValue((byte) 0x0C, new byte[] {(byte) 0xC3, (byte) 0xA9});
    assertAcceptedValue((byte) 0x0C, new byte[] {(byte) 0xE2, (byte) 0x82, (byte) 0xAC});
    assertAcceptedValue(
        (byte) 0x0C, new byte[] {(byte) 0xF0, (byte) 0x9F, (byte) 0x98, (byte) 0x80});
    assertRejectedValue((byte) 0x0C, new byte[] {(byte) 0xE0, (byte) 0x80, (byte) 0xAF});
    assertRejectedValue(
        (byte) 0x0C, new byte[] {(byte) 0xF0, (byte) 0x80, (byte) 0x80, (byte) 0xAF});
    assertRejectedValue((byte) 0x0C, new byte[] {(byte) 0xED, (byte) 0xA0, (byte) 0x80});
    assertRejectedValue((byte) 0x0C, new byte[] {(byte) 0xC3});
  }

  @Test
  void bmpStringRejectsSurrogateCodeUnits() {
    assertAcceptedValue((byte) 0x1E, new byte[] {0x00, 0x41});
    assertRejectedValue((byte) 0x1E, new byte[] {(byte) 0xD8, 0x00});
    assertRejectedValue((byte) 0x1E, new byte[] {(byte) 0xDF, (byte) 0xFF});
    assertRejectedValue((byte) 0x1E, new byte[] {0x00, 0x41, 0x00});
  }

  @Test
  void numericStringRejectsLetters() {
    assertAcceptedValue((byte) 0x12, "12 34".getBytes(StandardCharsets.US_ASCII));
    assertRejectedValue((byte) 0x12, "12A4".getBytes(StandardCharsets.US_ASCII));
  }

  @Test
  void universalStringRejectsCodePointsAboveUnicodeRange() {
    assertAcceptedValue((byte) 0x1C, new byte[] {0x00, 0x00, 0x00, 0x41});
    assertAcceptedValue((byte) 0x1C, new byte[] {0x00, 0x10, (byte) 0xFF, (byte) 0xFF});
    assertRejectedValue((byte) 0x1C, new byte[] {0x00, 0x11, 0x00, 0x00});
    assertRejectedValue((byte) 0x1C, new byte[] {0x01, 0x00, 0x00, 0x41});
    assertRejectedValue((byte) 0x1C, new byte[] {0x00, 0x00, (byte) 0xD8, 0x00});
  }

  @Test
  void normalizeTimeExpandsUtcTimeCenturyAndCopiesGeneralizedTime() {
    assertNormalized(utcTime("490101000000Z"), "20490101000000");
    assertNormalized(utcTime("500101000000Z"), "19500101000000");
    assertNormalized(utcTime("991231235959Z"), "19991231235959");
    byte[] generalized = tlv((byte) 0x18, ascii("20500101120000Z"));
    assertNormalized(generalized, "20500101120000");
    assertWrongData(
        () ->
            DERValidator.normalizeTime(
                utcTime("491301000000Z"), (short) 0, new byte[14], (short) 0));
  }

  @Test
  void rejectsMalformedDerProfileElements() {
    assertWrongData(
        () -> DERValidator.validateDerName(new byte[] {0x31, 0x00}, (short) 0, (short) 2));
    assertWrongData(
        () -> DERValidator.validateDerName(new byte[] {0x30, 0x00, 0x00}, (short) 0, (short) 3));
    assertWrongData(
        () -> DERValidator.validateDerName(new byte[] {0x30, (byte) 0x80}, (short) 0, (short) 2));
    assertWrongData(
        () ->
            DERValidator.validateDerName(
                new byte[] {0x30, (byte) 0x81, 0x01, 0x00}, (short) 0, (short) 4));
    assertWrongData(
        () ->
            DERValidator.validateDerValidity(
                new byte[] {0x30, 0x03, 0x16, 0x01, 0x5A}, (short) 0, (short) 5));
  }

  private static void assertNormalized(byte[] time, String expected) {
    byte[] out = new byte[16];
    short length = DERValidator.normalizeTime(time, (short) 0, out, (short) 1);
    assertEquals(DERValidator.LENGTH_NORMALIZED_TIME, length);
    byte[] actual = new byte[14];
    System.arraycopy(out, 1, actual, 0, 14);
    assertArrayEquals(ascii(expected), actual);
  }

  private static void assertAcceptedValue(byte tag, byte[] value) {
    byte[] name = nameWith(tag, value);
    DERValidator.validateDerName(name, (short) 0, (short) name.length);
  }

  private static void assertRejectedValue(byte tag, byte[] value) {
    byte[] name = nameWith(tag, value);
    assertWrongData(() -> DERValidator.validateDerName(name, (short) 0, (short) name.length));
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
    return nameWith((byte) 0x0C, commonName.getBytes(StandardCharsets.UTF_8));
  }

  /** Builds a one-attribute common-name Name whose value uses the given string tag. */
  private static byte[] nameWith(byte tag, byte[] value) {
    byte[] attribute =
        tlv((byte) 0x30, concat(new byte[] {0x06, 0x03, 0x55, 0x04, 0x03}, tlv(tag, value)));
    return tlv((byte) 0x30, tlv((byte) 0x31, attribute));
  }

  private static byte[] utcTime(String value) {
    return tlv((byte) 0x17, ascii(value));
  }

  private static byte[] ascii(String value) {
    return value.getBytes(StandardCharsets.US_ASCII);
  }

  /**
   * Builds a DER Validity sequence from two 13-octet RFC 5280 UTCTime values.
   *
   * @param notBefore first {@code YYMMDDHHMMSSZ} value
   * @param notAfter second {@code YYMMDDHHMMSSZ} value
   * @return complete DER Validity encoding
   */
  private static byte[] validity(String notBefore, String notAfter) {
    return tlv((byte) 0x30, concat(utcTime(notBefore), utcTime(notAfter)));
  }

  private static byte[] tlv(byte tag, byte[] value) {
    if (value.length >= 0x80) throw new IllegalArgumentException("short-form fixtures only");
    byte[] result = new byte[value.length + 2];
    result[0] = tag;
    result[1] = (byte) value.length;
    System.arraycopy(value, 0, result, 2, value.length);
    return result;
  }

  private static byte[] concat(byte[] left, byte[] right) {
    byte[] result = new byte[left.length + right.length];
    System.arraycopy(left, 0, result, 0, left.length);
    System.arraycopy(right, 0, result, left.length, right.length);
    return result;
  }

  private interface ThrowingRunnable {
    void run();
  }
}
