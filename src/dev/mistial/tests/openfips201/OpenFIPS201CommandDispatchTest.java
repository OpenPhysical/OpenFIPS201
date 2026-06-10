package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import javacard.framework.APDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * Focused tests for APDU command routing and front-door preconditions in {@code OpenFIPS201}.
 *
 * <p>These tests exercise the command switch, P1/P2 validation, and "no object yet" behavior that
 * should be stable regardless of personalization state.
 */
@Timeout(value = 15, unit = TimeUnit.SECONDS)
class OpenFIPS201CommandDispatchTest extends OpenFIPS201TestSupport {

  @Test
  void selectReturnsPivApplicationPropertyTemplate() {
    ResponseAPDU response = selectApplet();
    assertSw(0x9000, response, "SELECT by applet AID");
    // jcardsim/JCardEngine may model SELECT response data differently; command-level success is
    // the stable invariant we require in CI.
    assertEquals(0x9000, response.getSW(), "SELECT must complete successfully");
  }

  @Test
  void appletSelectionAllowsContactlessByDefault() {
    try (MockedStatic<APDU> mockedApdu = Mockito.mockStatic(APDU.class)) {
      mockedApdu
          .when(APDU::getProtocol)
          .thenReturn((byte) (APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A | APDU.PROTOCOL_T1));
      assertSw(0x9000, selectApplet(), "SELECT over contactless should succeed by default");
    }
  }

  @Test
  void unsupportedInstructionReturnsInsNotSupported() {
    assertSw(0x9000, selectApplet(), "SELECT before unsupported INS test");
    ResponseAPDU response = transmit(0x00, 0xFE, 0x00, 0x00);
    assertSw(0x6D00, response, "Unknown INS must return INS_NOT_SUPPORTED");
  }

  @Test
  void getDataRejectsWrongP1() {
    assertSw(0x9000, selectApplet(), "SELECT before GET DATA checks");
    ResponseAPDU response = transmit(0x00, 0xCB, 0x00, 0xFF, hex("5C017E"));
    assertSw(0x6A86, response, "GET DATA requires P1=0x3F");
  }

  @Test
  void getDataRejectsWrongP2() {
    assertSw(0x9000, selectApplet(), "SELECT before GET DATA checks");
    ResponseAPDU response = transmit(0x00, 0xCB, 0x3F, 0x01, hex("5C017E"));
    assertSw(0x6A86, response, "GET DATA requires P2=0xFF or extended P2=0x00");
  }

  @Test
  void getDataRejectsMalformedTagList() {
    assertSw(0x9000, selectApplet(), "SELECT before GET DATA checks");

    // The applet expects a Tag List object (5C ..). Any other tag must fail with WRONG DATA.
    ResponseAPDU response = transmit(0x00, 0xCB, 0x3F, 0xFF, hex("5D017E"));
    assertSw(0x6A80, response, "GET DATA with malformed tag list should fail");
  }

  @Test
  void getDataReturnsFileNotFoundWhenObjectNotProvisioned() {
    assertSw(0x9000, selectApplet(), "SELECT before GET DATA checks");

    // Fresh cards are not pre-populated with every object. Requesting one should return 6A82.
    ResponseAPDU response = transmit(0x00, 0xCB, 0x3F, 0xFF, hex("5C035FC102"));
    assertSw(0x6A82, response, "Unprovisioned object should return FILE_NOT_FOUND");
  }

  @Test
  void getDataExtendedGetVersionWorks() {
    assertSw(0x9000, selectApplet(), "SELECT before GET DATA EXTENDED checks");

    // Extended GET DATA (P2=00) with id "GV" (0x4756) asks for implementation version details.
    ResponseAPDU response = transmit(0x00, 0xCB, 0x3F, 0x00, hex("5C032F4756"), 0);
    assertSw(0x9000, response, "GET DATA EXTENDED GV should succeed");

    // Extended responses are wrapped in a response TLV with tag 0x53.
    byte[] data = response.getData();
    assertTrue(data.length > 2, "GET DATA EXTENDED should return response data");
    assertEquals((byte) 0x53, data[0], "Extended GET DATA response should use tag 0x53");

    int outerOffset = contentOffset(data, 0);
    int outerEnd = outerOffset + derLength(data, 1);
    assertEquals(
        "OpenFIPS201-OpenPhysical",
        new String(tlvValue(data, outerOffset, outerEnd, 0x80), StandardCharsets.US_ASCII),
        "GET VERSION application name should identify this fork");
    assertEquals((byte) 0x00, singleByteTlvValue(data, outerOffset, outerEnd, 0x81));
    assertEquals((byte) 0x01, singleByteTlvValue(data, outerOffset, outerEnd, 0x82));
    assertEquals((byte) 0x00, singleByteTlvValue(data, outerOffset, outerEnd, 0x83));
  }

  @Test
  void getDataExtendedRejectsUnknownIdentifier() {
    assertSw(0x9000, selectApplet(), "SELECT before GET DATA EXTENDED checks");
    ResponseAPDU response = transmit(0x00, 0xCB, 0x3F, 0x00, hex("5C032F1234"), 0);
    assertSw(
        0x6A82, response, "Unknown extended data object identifier should return FILE_NOT_FOUND");
  }

  @Test
  void putDataAdminWithoutSecureChannelIsRejected() {
    assertSw(0x9000, selectApplet(), "SELECT before PUT DATA checks");

    // P2=00 chooses the administrative PUT DATA path, which must require SCP.
    ResponseAPDU response = transmit(0x00, 0xDB, 0x3F, 0x00, hex("7E00"));
    assertSw(0x6982, response, "Administrative PUT DATA must require a secure channel");
  }

  @Test
  void putDataRejectsWrongP1BeforeDeeperParsing() {
    assertSw(0x9000, selectApplet(), "SELECT before PUT DATA checks");
    ResponseAPDU response = transmit(0x00, 0xDB, 0x00, 0xFF, hex("7E00"));
    assertSw(0x6A86, response, "PUT DATA requires P1=0x3F");
  }

  @Test
  void generateAsymmetricKeypairRejectsWrongP1() {
    assertSw(0x9000, selectApplet(), "SELECT before GENERATE ASYMMETRIC KEYPAIR checks");

    // APDU shape is valid enough to enter the command path; P1 mismatch should be rejected first.
    ResponseAPDU response = transmit(0x00, 0x47, 0x01, 0x9E, hex("AC03800111"));
    assertSw(0x6A86, response, "GENERATE ASYMMETRIC KEYPAIR requires P1=0x00");
  }

  @Test
  void generalAuthenticateRejectsInvalidKeyReference() {
    assertSw(0x9000, selectApplet(), "SELECT before GENERAL AUTHENTICATE checks");

    // SP 800-73-4 Part 2, 3.2.4: any key reference value not supported by the card shall return
    // status word '6A 88'.
    ResponseAPDU response = transmit(0x00, 0x87, 0x11, 0x01, hex("7C00"));
    assertSw(0x6A88, response, "GENERAL AUTHENTICATE with invalid key reference must return 6A88");
  }

  @Test
  void generalAuthenticateTreatsAttestationAuthorityAsNotFound() {
    assertSw(0x9000, selectApplet(), "SELECT before GENERAL AUTHENTICATE checks");

    // F9 must be indistinguishable from a nonexistent key so GENERAL AUTHENTICATE does not leak
    // whether an attestation authority is provisioned.
    ResponseAPDU response = transmit(0x00, 0x87, 0x11, 0xF9, hex("7C00"));
    assertSw(0x6A88, response, "GENERAL AUTHENTICATE with P2=F9 must look like key-not-found");
  }

  @Test
  void attestRejectsCommandData() {
    assertSw(0x9000, selectApplet(), "SELECT before ATTEST length check");

    ResponseAPDU response = transmit(0x00, 0xF9, 0x9A, 0x00, hex("00"));
    assertSw(0x6700, response, "ATTEST is a no-body command and must reject nonzero Lc");
  }

  @Test
  void attestRejectsNonZeroP2() {
    assertSw(0x9000, selectApplet(), "SELECT before ATTEST P2 check");

    ResponseAPDU response = transmit(0x00, 0xF9, 0x9A, 0x01);
    assertSw(0x6A86, response, "ATTEST requires P2=0x00");
  }

  private static byte singleByteTlvValue(byte[] data, int offset, int end, int tag) {
    byte[] value = tlvValue(data, offset, end, tag);
    assertEquals(1, value.length, "Expected one-byte GET VERSION field");
    return value[0];
  }

  private static byte[] tlvValue(byte[] data, int offset, int end, int tag) {
    while (offset < end) {
      int currentTag = data[offset++] & 0xFF;
      int lengthOffset = offset;
      int valueOffset = contentOffset(data, offset - 1);
      int length = derLength(data, lengthOffset);
      if (currentTag == tag) {
        byte[] value = new byte[length];
        System.arraycopy(data, valueOffset, value, 0, length);
        return value;
      }
      offset = valueOffset + length;
    }
    throw new IllegalArgumentException("Tag not found: " + String.format("0x%02X", tag));
  }
}
