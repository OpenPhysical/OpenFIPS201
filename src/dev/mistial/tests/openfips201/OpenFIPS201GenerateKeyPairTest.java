package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** GENERATE ASYMMETRIC KEY PAIR request validation, status words and advertised mechanisms. */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class OpenFIPS201GenerateKeyPairTest extends OpenFIPS201TestSupport {

  private static final int SLOT_AUTHENTICATION = 0x9A;
  private static final int SLOT_CARD_AUTHENTICATION = 0x9E;
  private static final byte ALG_RSA_2048 = (byte) 0x07;
  private static final byte ALG_ECC_P256 = (byte) 0x11;

  /**
   * SP 800-73-5 Part 2 Section 3.3.2: '6A 86' when "the cryptographic mechanism of the reference
   * data to be generated is different than the cryptographic mechanism of the reference data of a
   * given key reference", and '6A 80' for an "unrecognized cryptographic mechanism".
   */
  @Test
  void mechanismMismatchReturns6A86AndUnknownMechanismReturns6A80() {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before GENERATE mechanism checks");
          createKey(SLOT_AUTHENTICATION, ALG_ECC_P256, 0x01, 0x09, 0x04);
          assertSw(0x6A86, generate(SLOT_AUTHENTICATION, "AC03800107"), "RSA-2048 on a P-256 slot");
          assertSw(0x6A86, generate(SLOT_AUTHENTICATION, "AC03800114"), "P-384 on a P-256 slot");
          assertSw(0x6A80, generate(SLOT_AUTHENTICATION, "AC038001FE"), "Unrecognized mechanism");
          assertSw(0x6A80, generate(SLOT_AUTHENTICATION, "AC03800108"), "Symmetric mechanism");
          assertGenerated(generate(SLOT_AUTHENTICATION, "AC03800111"), "Matching mechanism");
        });
  }

  /**
   * SP 800-73-5 Part 1 Section 5.3 Table 6 defines parameter '81' as "Optional public exponent
   * encoded big-endian" for RSA and "None" for ECC; SP 800-78-5 Section 3.1 requires exponent
   * 65537. A parameter the card cannot honour is refused instead of ignored.
   */
  @Test
  void generationParameterMustBeHonourable() {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before GENERATE parameter checks");
          createKey(SLOT_AUTHENTICATION, ALG_RSA_2048, 0x01, 0x09, 0x04);
          createKey(SLOT_CARD_AUTHENTICATION, ALG_ECC_P256, 0x7F, 0x7F, 0x04);

          assertSw(0x6A80, generate(SLOT_AUTHENTICATION, "AC06800107810103"), "Exponent 3");
          assertSw(
              0x6A80, generate(SLOT_AUTHENTICATION, "AC0880010781030100 03"), "Exponent 65539");
          assertSw(0x6A80, generate(SLOT_AUTHENTICATION, "AC058001078100"), "Empty exponent");
          assertSw(0x6A80, generate(SLOT_CARD_AUTHENTICATION, "AC06800111810103"), "ECC parameter");
          assertSw(
              0x6A80, generate(SLOT_CARD_AUTHENTICATION, "AC058001118100"), "Empty ECC parameter");

          assertGenerated(
              generate(SLOT_AUTHENTICATION, "AC0880010781030100 01"), "Exponent 65537 is honoured");
        });
  }

  /**
   * SP 800-73-5 Part 2 Table 2 marks GENERATE ASYMMETRIC KEY PAIR "No" for the contactless
   * interface; without the issuer's contactless card-management opt-in the card returns '6A 81'.
   */
  @Test
  void contactlessGenerateIsUnsupportedWithoutContactlessAdministration() {
    withContactless(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT over contactless");
          assertSw(
              0x6A81,
              transmit(0x00, 0x47, 0x00, SLOT_AUTHENTICATION, hex("AC03800111")),
              "Contactless GENERATE must be unsupported");
        });
  }

  /**
   * SP 800-73-5 Part 2 Section 3.1.1: "Tag 0xAC encodes the cryptographic algorithms supported by
   * the PIV Card Application." RSA-1024 ('06') is not usable on any standard key reference and is
   * not advertised.
   */
  @Test
  void applicationPropertyTemplateOmitsRsa1024() {
    byte[] apt =
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 256)).getData();
    assertEquals(0x61, apt[0] & 0xFF, "SELECT returns the APT");
    int aptLength = derLength(apt, 1);
    assertEquals(apt.length, contentOffset(apt, 0) + aptLength, "APT length covers the response");

    byte[] algorithms =
        tlvValue(Arrays.copyOfRange(apt, contentOffset(apt, 0), apt.length), (byte) 0xAC);
    assertTrue(algorithms.length > 0, "APT advertises algorithms");
    int count = 0;
    for (int offset = 0; offset < algorithms.length; ) {
      int tag = algorithms[offset] & 0xFF;
      int length = algorithms[offset + 1] & 0xFF;
      if (tag == 0x80) {
        assertEquals(1, length, "Each algorithm identifier is one byte");
        assertTrue(algorithms[offset + 2] != (byte) 0x06, "RSA-1024 must not be advertised");
        count++;
      }
      offset += 2 + length;
    }
    assertTrue(count > 0, "At least one algorithm is advertised");
  }

  private ResponseAPDU generate(int slot, String template) {
    return transmit(0x84, 0x47, 0x00, slot, hex(template), 256);
  }

  private void assertGenerated(ResponseAPDU response, String context) {
    int sw = response.getSW();
    assertTrue(
        sw == 0x9000 || (sw & 0xFF00) == 0x6100,
        context + " expected success but was " + swHex(response));
  }

  private void createKey(int slot, byte algorithm, int contact, int contactless, int role) {
    assertSw(
        0x9000,
        transmit(
            0x84,
            0xDB,
            0xFF,
            0xFF,
            new byte[] {
              (byte) 0x66,
              (byte) 0x12,
              (byte) 0x8B,
              (byte) 0x01,
              (byte) slot,
              (byte) 0x8C,
              (byte) 0x01,
              (byte) contact,
              (byte) 0x8D,
              (byte) 0x01,
              (byte) contactless,
              (byte) 0x8E,
              (byte) 0x01,
              algorithm,
              (byte) 0x8F,
              (byte) 0x01,
              (byte) role,
              (byte) 0x90,
              (byte) 0x01,
              (byte) 0x00
            }),
        "Create key " + Integer.toHexString(slot));
  }
}
