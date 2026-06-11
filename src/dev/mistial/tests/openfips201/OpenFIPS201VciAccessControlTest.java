package dev.mistial.tests.openfips201;

import javacard.framework.APDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * Verifies that the Virtual Contact Interface (VCI) is enforced as a contactless access condition.
 *
 * <p>Aligned with NIST SP 800-73-5 Part 2, verifying that objects gated by VCI access mode
 * (0x08) are blocked over contactless until secure messaging is established, while remaining
 * accessible normally over the contact interface.
 */
class OpenFIPS201VciAccessControlTest extends OpenFIPS201TestSupport {

  private static final byte[] TEST_OBJECT_ID = {(byte) 0x5F, (byte) 0xC1, (byte) 0x5A};
  private static final byte[] TEST_TAG_LIST = {
    (byte) 0x5C, (byte) 0x03, (byte) 0x5F, (byte) 0xC1, (byte) 0x5A
  };
  private static final byte ACCESS_MODE_ALWAYS = (byte) 0x7F;
  private static final byte ACCESS_MODE_VCI = (byte) 0x08;

  /** Creates and populates a test data object with contact ALWAYS and the given contactless mode. */
  private void createObject(final byte contactlessMode) {
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before create-object");
            byte[] create =
                tlv(
                    (byte) 0x64,
                    concat(
                        tlv((byte) 0x8B, TEST_OBJECT_ID),
                        new byte[] {
                          (byte) 0x8C, (byte) 0x01, ACCESS_MODE_ALWAYS,
                          (byte) 0x8D, (byte) 0x01, contactlessMode,
                          (byte) 0x91, (byte) 0x01, (byte) 0x9B
                        }));
            assertSw(0x9000, transmit(0x84, 0xDB, 0x3F, 0x00, create), "Create test object");
            assertSw(
                0x9000,
                transmit(0x84, 0xDB, 0x3F, 0xFF, concat(TEST_TAG_LIST, hex("530101"))),
                "Populate test object");
          }
        });
  }

  /**
   * Verifies that contactless read of a VCI-gated object is denied without VCI.
   *
   * <p>Aligned with NIST SP 800-73-5 Part 2, Section 4.2. Security status must not be satisfied.
   */
  @Test
  void contactlessReadOfVciObjectIsDeniedWithoutVci() {
    createObject(ACCESS_MODE_VCI);

    try (MockedStatic<APDU> mockedApdu = Mockito.mockStatic(APDU.class)) {
      mockedApdu
          .when(APDU::getProtocol)
          .thenReturn((byte) (APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A | APDU.PROTOCOL_T1));
      assertSw(0x9000, selectApplet(), "SELECT over contactless");
      ResponseAPDU blocked = transmit(0x00, 0xCB, 0x3F, 0xFF, TEST_TAG_LIST, 0);
      assertSw(
          0x6982,
          blocked,
          "Contactless GET DATA of a VCI-gated object must fail closed before VCI is established");
    }
  }

  /**
   * Verifies that contact read of a VCI-gated object succeeds regardless of VCI state.
   *
   * <p>Aligned with NIST SP 800-73-5 Part 2, Section 4.2 (VCI condition only restricts contactless interface).
   */
  @Test
  void contactReadOfVciObjectSucceeds() {
    createObject(ACCESS_MODE_VCI);

    assertSw(0x9000, selectApplet(), "SELECT over contact");
    ResponseAPDU response = transmit(0x00, 0xCB, 0x3F, 0xFF, TEST_TAG_LIST, 0);
    assertSw(
        0x9000, response, "The VCI condition has no effect on the contact interface");
  }

  /**
   * Verifies that contactless read of an ALWAYS-gated object succeeds without VCI.
   *
   * <p>Aligned with NIST SP 800-73-5 Part 2.
   */
  @Test
  void contactlessReadOfAlwaysObjectStillSucceeds() {
    createObject(ACCESS_MODE_ALWAYS);

    try (MockedStatic<APDU> mockedApdu = Mockito.mockStatic(APDU.class)) {
      mockedApdu
          .when(APDU::getProtocol)
          .thenReturn((byte) (APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A | APDU.PROTOCOL_T1));
      assertSw(0x9000, selectApplet(), "SELECT over contactless");
      ResponseAPDU response = transmit(0x00, 0xCB, 0x3F, 0xFF, TEST_TAG_LIST, 0);
      assertSw(
          0x9000,
          response,
          "An ALWAYS object remains contactless-readable (no VCI bit, unaffected)");
    }
  }
}
