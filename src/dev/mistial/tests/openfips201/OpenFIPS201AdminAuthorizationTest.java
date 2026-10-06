package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.util.concurrent.TimeUnit;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Interface and authorization rules for administrative commands and for PIN-protected private keys.
 */
@Timeout(value = 30, unit = TimeUnit.SECONDS)
class OpenFIPS201AdminAuthorizationTest extends OpenFIPS201TestSupport {

  private static final boolean FIPS_MODE = Boolean.getBoolean("fips.mode");
  private static final byte ALG_ECC_P256 = (byte) 0x11;
  private static final byte ROLE_KEY_ESTABLISH = (byte) 0x02;
  private static final byte ROLE_SIGN = (byte) 0x04;
  private static final byte[] REPLACEMENT = hex("3939393939393939");
  // P-256 base point G (SEC 2 Section 2.4.2), a valid ECDH peer public key.
  private static final byte[] P256_G =
      hex(
          "04"
              + "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
              + "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");

  /**
   * With contactless administration restricted (the default), a 9B session established over
   * contactless must not replace the PIN or PUK through any proprietary form, INS 24 P1=01
   * included.
   */
  @Test
  void contactlessManagementKeySessionCannotReplacePinOrPuk() {
    assumeFalse(FIPS_MODE, "The FIPS profile fixes the 9B contactless access rule to NEVER");
    byte[] definition =
        StandardCardProfile.managementKeyDefinition(StandardCardProfile.ADMIN_KEY_ALG);
    definition[10] = (byte) 0x7F; // 8D: 9B usable over contactless
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before 9B redefinition");
          assertSw(
              0x9000,
              transmit(0x84, 0xDB, 0xFF, 0xFF, hex("6706 8B019B 8E0108")),
              "Delete the contact-only 9B");
          assertSw(0x9000, transmit(0x84, 0xDB, 0xFF, 0xFF, definition), "Create contactless 9B");
          assertSw(
              0x9000,
              transmit(
                  0x84,
                  0x25,
                  0x01,
                  0x9B,
                  concat(
                      new byte[] {(byte) 0x80, (byte) 0x01, StandardCardProfile.ADMIN_KEY_ALG},
                      keyUpdateData(StandardCardProfile.ADMIN_KEY))),
              "Import 9B");
        });

    withContactless(
        () -> {
          authenticateCardManagementKey(
              StandardCardProfile.ADMIN_KEY_ALG, StandardCardProfile.ADMIN_KEY);
          assertSw(
              0x6982,
              transmit(0x80, 0x24, 0x01, 0x80, REPLACEMENT),
              "INS 24 P1=01 must not replace the PIN over contactless");
          assertSw(
              0x6982,
              transmit(0x80, 0x24, 0x01, 0x81, REPLACEMENT),
              "INS 24 P1=01 must not replace the PUK over contactless");
          assertSw(
              0x6982,
              transmit(0x80, 0x25, 0x01, 0x80, REPLACEMENT),
              "INS 25 P1=01 must not replace the PIN over contactless");
        });

    assertSw(0x9000, selectApplet(), "SELECT over contact");
    assertSw(0x9000, verifyPin(), "The original PIN is unchanged");
    assertSw(
        0x9000,
        transmit(0x00, 0x2C, 0x00, 0x80, concat(StandardCardProfile.PUK, REPLACEMENT)),
        "The original PUK is unchanged");
  }

  /**
   * SP 800-73-5 Part 2 Section 3.2.2: "If key reference '81' is specified and the command is not
   * submitted over the contact interface, then the card command SHALL fail." Table 2 marks RESET
   * RETRY COUNTER "No" for contactless. The contactless PIN and PUK flags relax neither.
   */
  @Test
  void contactlessPinAndPukFlagsDoNotEnablePukChangeOrRetryReset() {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before contactless flag configuration");
          assertSw(
              0x9000,
              transmit(0x84, 0xDB, 0xFF, 0xFF, hex("680AA0038301FFA1038101FF")),
              "Enable the contactless PIN and PUK flags");
        });

    withContactless(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT over contactless");
          ResponseAPDU change =
              transmit(0x00, 0x24, 0x00, 0x81, concat(StandardCardProfile.PUK, REPLACEMENT));
          assertSw(
              FIPS_MODE ? 0x6A81 : 0x6982, change, "CHANGE REFERENCE DATA 81 over contactless");
          assertSw(
              0x6A81,
              transmit(0x00, 0x2C, 0x00, 0x80, concat(StandardCardProfile.PUK, REPLACEMENT)),
              "RESET RETRY COUNTER over contactless");
        });

    assertSw(0x9000, selectApplet(), "SELECT over contact");
    assertSw(0x9000, verifyPin(), "The PIN was not reset over contactless");
    assertSw(
        0x9000,
        transmit(0x00, 0x2C, 0x00, 0x80, concat(StandardCardProfile.PUK, REPLACEMENT)),
        "The PUK was not changed over contactless");
  }

  /** SP 800-73-5 Part 1 Table 5: the digital signature key 9C requires PIN Always. */
  @Test
  void pinAlwaysKeyRequiresVerifyBeforeEachUse() {
    provisionGeneratedKey(0x9C, 0x02, 0x0A, ROLE_SIGN);
    assertSw(0x9000, selectApplet(), "SELECT before PIN Always use");
    assertSw(0x6982, sign(0x9C), "PIN Always key without VERIFY");
    assertSw(0x9000, verifyPin(), "VERIFY");
    assertSuccess(sign(0x9C), "PIN Always key immediately after VERIFY");
    assertSw(0x6982, sign(0x9C), "PIN Always is consumed by one use");
    assertSw(0x9000, verifyPin(), "VERIFY again");
    assertSuccess(sign(0x9C), "A new VERIFY authorizes one more use");
  }

  /** SP 800-73-5 Part 1 Table 5: the PIV authentication key 9A requires the PIN. */
  @Test
  void pinKeyRejectsUseWithoutVerify() {
    provisionGeneratedKey(0x9A, 0x01, 0x09, ROLE_SIGN);
    assertSw(0x9000, selectApplet(), "SELECT before PIN key use");
    assertSw(0x6982, sign(0x9A), "PIN key without VERIFY");
    assertSw(0x9000, verifyPin(), "VERIFY");
    assertSuccess(sign(0x9A), "PIN key after VERIFY");
    assertSuccess(sign(0x9A), "PIN status persists for a PIN key");
  }

  /** SP 800-73-5 Part 1 Table 5: the key management key 9D requires the PIN. */
  @Test
  void keyManagementKeyRejectsAgreementWithoutVerify() {
    provisionGeneratedKey(0x9D, 0x01, 0x09, ROLE_KEY_ESTABLISH);
    assertSw(0x9000, selectApplet(), "SELECT before key agreement");
    byte[] request =
        tlv((byte) 0x7C, concat(tlv((byte) 0x82, new byte[0]), tlv((byte) 0x85, P256_G)));
    assertSw(0x6982, transmit(0x00, 0x87, ALG_ECC_P256, 0x9D, request, 256), "ECDH without VERIFY");
    assertSw(0x9000, verifyPin(), "VERIFY");
    assertSuccess(transmit(0x00, 0x87, ALG_ECC_P256, 0x9D, request, 256), "ECDH after VERIFY");
  }

  private void provisionGeneratedKey(
      final int slot, final int contact, final int contactless, final byte role) {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before key provisioning");
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
                    ALG_ECC_P256,
                    (byte) 0x8F,
                    (byte) 0x01,
                    role,
                    (byte) 0x90,
                    (byte) 0x01,
                    (byte) 0x00
                  }),
              "Create key " + Integer.toHexString(slot));
          assertSuccess(
              transmit(0x84, 0x47, 0x00, slot, hex("AC03800111"), 256),
              "Generate key " + Integer.toHexString(slot));
        });
  }

  private ResponseAPDU sign(int slot) {
    byte[] digest = new byte[32];
    for (int i = 0; i < digest.length; i++) digest[i] = (byte) (0x40 + i);
    return transmit(
        0x00,
        0x87,
        ALG_ECC_P256,
        slot,
        tlv((byte) 0x7C, concat(tlv((byte) 0x82, new byte[0]), tlv((byte) 0x81, digest))),
        256);
  }

  private ResponseAPDU verifyPin() {
    return transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN);
  }

  private static void assertSuccess(ResponseAPDU response, String context) {
    int sw = response.getSW();
    assertTrue(
        sw == 0x9000 || (sw & 0xFF00) == 0x6100,
        context + " expected success but was " + swHex(response));
  }
}
