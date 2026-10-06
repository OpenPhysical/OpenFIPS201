package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.JavaCardEngine;

/** White-box tests of the F9 certificate profile parser and OPID syntax. */
class PIVAttestationAuthorityCertificateTest {

  // B[F] and C[F] of the retired format-coded OPID layout, used only for negative cases.
  private static final int[] LEGACY_BATCH_DIGITS = {4, 4, 0, 0, 0, 2, 2, 2, 4, 4};
  private static final int[] LEGACY_CIN_DIGITS = {8, 8, 5, 6, 7, 6, 7, 8, 7, 8};

  private final JavaCardEngine engine = JavaCardEngine.create();
  private AutoCloseable context;

  @BeforeEach
  void enterEngine() throws Exception {
    Method asCurrent = engine.getClass().getMethod("asCurrent");
    context = (AutoCloseable) asCurrent.invoke(engine);
  }

  @AfterEach
  void leaveEngine() throws Exception {
    context.close();
  }

  @Test
  void acceptsSeventeenDigitOpidsWithValidLuhn() {
    assertAccepted(opid("0000000000000000"));
    assertAccepted(opid("9999999999999999"));
    assertAccepted(opid("1234000000000001"));
    assertAccepted(opid("1234987654321098"));
    assertAccepted(ascii("12345678901234569"));
    for (int i = 0; i < 50; i++) {
      StringBuilder payload = new StringBuilder();
      long value = 0x9E3779B97F4A7C15L * (i + 1);
      for (int d = 0; d < 16; d++) payload.append((char) ('0' + (int) ((value >>> (d * 4)) & 7)));
      assertAccepted(opid(payload.toString()));
    }
    // The OPID may sit at any offset inside the certificate buffer.
    byte[] padded = new byte[20];
    System.arraycopy(opid("1234567890123456"), 0, padded, 2, 17);
    PIVAttestation.validateOpid(padded, (short) 2, (short) 17);
  }

  @Test
  void rejectsOtherLengthsIncludingRetiredFormatCodedOpids() {
    assertRejected(opid("123456789012345"), "16 digits");
    assertRejected(opid("12345678901234567"), "18 digits");
    assertRejected(opid(""), "1 digit");
    assertRejected(new byte[0], "empty");
    for (int format = 0; format <= 9; format++) {
      int length = 4 + 1 + LEGACY_BATCH_DIGITS[format] + LEGACY_CIN_DIGITS[format] + 1;
      if (length == 17) continue;
      StringBuilder payload = new StringBuilder("1234").append(format);
      while (payload.length() < length - 1) payload.append('5');
      assertRejected(opid(payload.toString()), "retired format " + format + " OPID");
    }
  }

  @Test
  void rejectsBadLuhnAndNonDigits() {
    byte[] valid = opid("4321123456789012");
    for (int delta = 1; delta <= 9; delta++) {
      byte[] wrong = valid.clone();
      wrong[16] = (byte) ('0' + (wrong[16] - '0' + delta) % 10);
      assertRejected(wrong, "check digit +" + delta);
    }
    byte[] transposed = valid.clone();
    transposed[5] = valid[6];
    transposed[6] = valid[5];
    if (transposed[5] != transposed[6]) assertRejected(transposed, "adjacent transposition");
    for (int position : new int[] {0, 4, 10, 16}) {
      byte[] letter = valid.clone();
      letter[position] = 'A';
      assertRejected(letter, "letter at " + position);
      byte[] space = valid.clone();
      space[position] = ' ';
      assertRejected(space, "space at " + position);
    }
  }

  @Test
  void luhnMatchesPublishedVectors() {
    assertEquals('1', checkDigit("411111111111111"));
    assertEquals('4', checkDigit("555555555555444"));
    assertEquals('9', checkDigit("1234567890123456"));
    assertAccepted(ascii("12345678901234569"));
    assertRejected(ascii("12345678901234560"), "wrong check digit");
  }

  @Test
  void parserRecordsProfileOffsets() throws Exception {
    Fixture fixture = new Fixture();
    byte[] certificate = fixture.encode();
    byte[] buffer = new byte[certificate.length + 3];
    System.arraycopy(certificate, 0, buffer, 3, certificate.length);
    byte[] work = new byte[0x20];

    PIVAttestation.parseAuthorityCertificate(
        buffer, (short) 3, (short) certificate.length, work, (short) 2);

    assertSlice(buffer, work, 2 + PIVAttestation.PARSE_SUBJECT_OFFSET, fixture.subject);
    assertSlice(buffer, work, 2 + PIVAttestation.PARSE_VALIDITY_OFFSET, fixture.validity);
    assertSlice(buffer, work, 2 + PIVAttestation.PARSE_SPKI_OFFSET, fixture.spki);
    assertSlice(
        buffer, work, 2 + PIVAttestation.PARSE_OPID_OFFSET, fixture.opid.getBytes("US-ASCII"));
    short keyId = Util.getShort(work, (short) (2 + PIVAttestation.PARSE_KEY_ID_OFFSET));
    assertArrayEquals(fixture.keyId, Arrays.copyOfRange(buffer, keyId, keyId + 20));
  }

  @Test
  void parserRejectsProfileViolations() throws Exception {
    Fixture explicitDefault = new Fixture();
    explicitDefault.aki = extension("551D23", "010100", hex("30168014"), new byte[20]);
    assertParseRejected(explicitDefault.encode(), ISO7816.SW_WRONG_DATA, "explicit FALSE");

    Fixture criticalSki = new Fixture();
    criticalSki.ski = extension("551D0E", "0101FF", hex("0414"), new byte[20]);
    assertParseRejected(criticalSki.encode(), ISO7816.SW_WRONG_DATA, "critical SKI");

    Fixture akiWithoutKeyId = new Fixture();
    akiWithoutKeyId.aki = extension("551D23", "", hex("3000"), new byte[0]);
    assertParseRejected(akiWithoutKeyId.encode(), ISO7816.SW_WRONG_DATA, "AKI without keyId");

    Fixture wrongSkiLength = new Fixture();
    wrongSkiLength.ski = extension("551D0E", "", hex("0413"), new byte[19]);
    assertParseRejected(wrongSkiLength.encode(), ISO7816.SW_WRONG_DATA, "19-octet SKI");

    Fixture emptySignature = new Fixture();
    emptySignature.signature = hex("030100");
    assertParseRejected(emptySignature.encode(), ISO7816.SW_WRONG_DATA, "empty signature");

    Fixture unusedBits = new Fixture();
    unusedBits.signature = hex("03020101");
    assertParseRejected(unusedBits.encode(), ISO7816.SW_WRONG_DATA, "signature unused bits");

    Fixture largeSubject = new Fixture();
    largeSubject.subject = nameWithOpid(88, largeSubject.opid);
    assertEquals(0x81, largeSubject.subject.length);
    assertParseRejected(largeSubject.encode(), ISO7816.SW_FILE_FULL, "oversize subject");

    Fixture maximumSubject = new Fixture();
    maximumSubject.subject = nameWithOpid(87, maximumSubject.opid);
    assertEquals(0x80, maximumSubject.subject.length);
    byte[] certificate = maximumSubject.encode();
    PIVAttestation.parseAuthorityCertificate(
        certificate, (short) 0, (short) certificate.length, new byte[0x20], (short) 0);
  }

  @Test
  void parserRequiresEcdsaWithSha256WithoutParameters() throws Exception {
    String[][] algorithms = {
      {"300A06082A8648CE3D040303", "ecdsa-with-SHA384"},
      {"300D06092A864886F70D01010B0500", "sha256WithRSAEncryption"},
      {"300C06082A8648CE3D0403020500", "ecdsa-with-SHA256 with NULL parameters"},
      {"300806062A8648CE3D04", "truncated ECDSA OID"}
    };
    for (String[] algorithm : algorithms) {
      Fixture fixture = new Fixture();
      fixture.algorithm = hex(algorithm[0]);
      assertParseRejected(fixture.encode(), ISO7816.SW_WRONG_DATA, algorithm[1]);
    }
  }

  private static void assertAccepted(byte[] opid) {
    PIVAttestation.validateOpid(opid, (short) 0, (short) opid.length);
  }

  private static void assertRejected(byte[] opid, String reason) {
    ISOException thrown =
        assertThrows(
            ISOException.class,
            () -> PIVAttestation.validateOpid(opid, (short) 0, (short) opid.length),
            reason);
    assertEquals(ISO7816.SW_WRONG_DATA, thrown.getReason(), reason);
  }

  private static void assertParseRejected(byte[] certificate, short expected, String reason) {
    ISOException thrown =
        assertThrows(
            ISOException.class,
            () ->
                PIVAttestation.parseAuthorityCertificate(
                    certificate, (short) 0, (short) certificate.length, new byte[0x20], (short) 0),
            reason);
    assertEquals(expected, thrown.getReason(), reason);
  }

  private static void assertSlice(byte[] buffer, byte[] work, int field, byte[] expected) {
    short offset = Util.getShort(work, (short) field);
    short length = Util.getShort(work, (short) (field + 2));
    assertEquals(expected.length, length);
    assertArrayEquals(expected, Arrays.copyOfRange(buffer, offset, offset + length));
  }

  /** Appends the Luhn check digit to {@code payload} and returns the ASCII digits. */
  private static byte[] opid(String payload) {
    return ascii(payload + checkDigit(payload));
  }

  private static byte[] ascii(String value) {
    return value.getBytes(StandardCharsets.US_ASCII);
  }

  private static char checkDigit(String payload) {
    int sum = 0;
    boolean doubled = true;
    for (int i = payload.length() - 1; i >= 0; i--) {
      int digit = payload.charAt(i) - '0';
      if (doubled) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      sum += digit;
      doubled = !doubled;
    }
    return (char) ('0' + (10 - sum % 10) % 10);
  }

  /** A SAM-profile F9 certificate assembled from independent DER fields. */
  private static final class Fixture {
    final String opid = new String(opid("1234666666666666"), StandardCharsets.US_ASCII);
    final byte[] keyId = new byte[20];
    byte[] serial = hex("02104F1E2D3C4B5A69788796A5B4C3D2E1F0");
    byte[] algorithm = hex("300A06082A8648CE3D040302");
    byte[] issuer = name("Issuer SAM");
    byte[] validity =
        tlv(
            0x30,
            concat(
                tlv(0x17, "200101000000Z".getBytes(StandardCharsets.US_ASCII)),
                tlv(0x18, "20600101000000Z".getBytes(StandardCharsets.US_ASCII))));
    byte[] subject;
    byte[] spki;
    byte[] bc = extension("551D13", "0101FF", hex("30060101FF020100"), new byte[0]);
    byte[] ku = extension("551D0F", "0101FF", hex("03020204"), new byte[0]);
    byte[] ski;
    byte[] aki = extension("551D23", "", hex("30168014"), new byte[20]);
    byte[] signature = tlv(0x03, concat(new byte[] {0x00}, new byte[70]));

    Fixture() {
      Arrays.fill(keyId, (byte) 0x3C);
      subject = nameWithOpid(20, opid);
      byte[] point = new byte[65];
      point[0] = 0x04;
      spki = concat(hex("3059301306072A8648CE3D020106082A8648CE3D030107034200"), point);
      ski = extension("551D0E", "", hex("0414"), keyId);
    }

    byte[] encode() {
      byte[] extensions = tlv(0xA3, tlv(0x30, concat(bc, ku, ski, aki)));
      byte[] tbs =
          tlv(
              0x30,
              concat(
                  hex("A003020102"),
                  serial,
                  algorithm,
                  issuer,
                  validity,
                  subject,
                  spki,
                  extensions));
      return tlv(0x30, concat(tbs, algorithm, signature));
    }
  }

  private static byte[] extension(String oid, String critical, byte[] valuePrefix, byte[] value) {
    return tlv(
        0x30, concat(tlv(0x06, hex(oid)), hex(critical), tlv(0x04, concat(valuePrefix, value))));
  }

  private static byte[] name(String commonName) {
    byte[] value = commonName.getBytes(StandardCharsets.US_ASCII);
    return tlv(0x30, rdn("550403", 0x0C, value));
  }

  /** Builds {@code CN=<cnLength x 'C'>, serialNumber=<opid>} as a DER Name. */
  private static byte[] nameWithOpid(int cnLength, String opid) {
    byte[] cn = new byte[cnLength];
    Arrays.fill(cn, (byte) 'C');
    return tlv(
        0x30,
        concat(
            rdn("550403", 0x0C, cn),
            rdn("550405", 0x13, opid.getBytes(StandardCharsets.US_ASCII))));
  }

  private static byte[] rdn(String oid, int tag, byte[] value) {
    return tlv(0x31, tlv(0x30, concat(tlv(0x06, hex(oid)), tlv(tag, value))));
  }

  private static byte[] tlv(int tag, byte[] value) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(tag);
    if (value.length < 0x80) {
      out.write(value.length);
    } else if (value.length < 0x100) {
      out.write(0x81);
      out.write(value.length);
    } else {
      out.write(0x82);
      out.write(value.length >> 8);
      out.write(value.length);
    }
    out.write(value, 0, value.length);
    return out.toByteArray();
  }

  private static byte[] concat(byte[]... parts) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (byte[] part : parts) out.write(part, 0, part.length);
    return out.toByteArray();
  }

  private static byte[] hex(String value) {
    byte[] out = new byte[value.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(value.substring(2 * i, 2 * i + 2), 16);
    }
    return out;
  }
}
