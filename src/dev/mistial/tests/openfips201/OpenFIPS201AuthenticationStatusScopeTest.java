package dev.mistial.tests.openfips201;

import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import javacard.framework.ISO7816;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Scope of a failed GENERAL AUTHENTICATE.
 *
 * <p>SP 800-73-5 Part 2 Section 2.4.2: "An aborted or failed execution of an authentication
 * protocol SHALL set the security status indicator associated with the credential used in the
 * protocol to FALSE." Only that credential is affected: the PIN security status and the status of a
 * different key survive the failure.
 */
class OpenFIPS201AuthenticationStatusScopeTest extends OpenFIPS201TestSupport {
  private static final byte ALG_ECC_P256 = (byte) 0x11;
  private static final byte ALG_AES_128 = StandardCardProfile.ADMIN_KEY_ALG;
  private static final byte KEY_CARD_AUTHENTICATION = (byte) 0x9E;
  private static final byte KEY_CARD_MANAGEMENT = StandardCardProfile.ADMIN_KEY_REF;
  private static final byte[] PROBE_OBJECT_TAG_LIST = hex("5C035FFF10");

  @BeforeEach
  void provisionCardAuthenticationKeyAndProbeObject() {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before provisioning");
          assertSw(
              0x9000,
              transmit(0x84, 0xDB, 0xFF, 0xFF, hex("66128B019E8C017F8D017F8E01118F0104900100")),
              "Define the card authentication key 9E");
          collectResponse(
              transmit(0x84, 0x47, 0x00, KEY_CARD_AUTHENTICATION & 0xFF, hex("AC03800111"), 256),
              "Generate 9E");
          assertSw(
              0x9000,
              transmit(0x84, 0xDB, 0xFF, 0xFF, hex("64128B035FFF108C017F8D017F91019B92020010")),
              "Create the 9B-administered probe object");
        });
    assertSw(0x9000, selectApplet(), "SELECT after provisioning");
  }

  @Test
  void failedAuthenticationWithAnotherKeyKeepsPinAndManagementKeyStatus() {
    authenticateCardManagementKey(ALG_AES_128, StandardCardProfile.ADMIN_KEY);
    assertSw(0x9000, transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN), "VERIFY");
    assertSw(0x9000, putProbe(), "9B authorizes the probe PUT DATA");

    // Case 1B with a challenge one octet short of the 9E block length.
    assertSw(
        ISO7816.SW_WRONG_DATA,
        transmit(
            0x00,
            0x87,
            ALG_ECC_P256,
            KEY_CARD_AUTHENTICATION & 0xFF,
            tlv(
                (byte) 0x7C,
                concat(tlv((byte) 0x81, new byte[31]), tlv((byte) 0x82, new byte[0])))),
        "A malformed 9E signature request fails");

    assertSw(0x9000, transmit(0x00, 0x20, 0x00, 0x80), "The PIN security status survives");
    assertSw(0x9000, putProbe(), "The 9B security status survives a failure of another key");
  }

  @Test
  void failedAuthenticationOfTheManagementKeyClearsOnlyItsStatus() {
    authenticateCardManagementKey(ALG_AES_128, StandardCardProfile.ADMIN_KEY);
    assertSw(0x9000, transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN), "VERIFY");
    assertSw(0x9000, putProbe(), "9B authorizes the probe PUT DATA");

    assertSw(0x9000, transmit(0x00, 0x87, ALG_AES_128, 0x9B, hex("7C028100")), "9B challenge");
    assertSw(
        ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
        transmit(
            0x00,
            0x87,
            ALG_AES_128,
            KEY_CARD_MANAGEMENT & 0xFF,
            tlv((byte) 0x7C, tlv((byte) 0x82, new byte[16]))),
        "A wrong 9B cryptogram fails");

    assertSw(
        ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
        putProbe(),
        "The failed exchange sets the 9B security status to FALSE");
    assertSw(0x9000, transmit(0x00, 0x20, 0x00, 0x80), "The PIN security status survives");
    collectResponse(
        transmit(
            0x00,
            0x87,
            ALG_ECC_P256,
            KEY_CARD_AUTHENTICATION & 0xFF,
            tlv(
                (byte) 0x7C,
                concat(tlv((byte) 0x81, new byte[32]), tlv((byte) 0x82, new byte[0])))),
        "Other keys remain usable after the 9B failure");
  }

  /** PUT DATA of an object whose administration requires 9B: '9000' only while 9B is verified. */
  private javax.smartcardio.ResponseAPDU putProbe() {
    return transmit(0x00, 0xDB, 0x3F, 0xFF, concat(PROBE_OBJECT_TAG_LIST, hex("530100")));
  }
}
