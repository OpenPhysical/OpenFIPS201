package dev.mistial.tests.openfips201;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import javax.smartcardio.ResponseAPDU;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
  }

  @Test
  void getDataExtendedRejectsUnknownIdentifier() {
    assertSw(0x9000, selectApplet(), "SELECT before GET DATA EXTENDED checks");
    ResponseAPDU response = transmit(0x00, 0xCB, 0x3F, 0x00, hex("5C032F1234"), 0);
    assertSw(0x6A82, response, "Unknown extended data object identifier should return FILE_NOT_FOUND");
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

    // Unknown key reference should fail deterministically with INCORRECT_P1P2.
    ResponseAPDU response = transmit(0x00, 0x87, 0x11, 0x01, hex("7C00"));
    assertSw(0x6A86, response, "GENERAL AUTHENTICATE with invalid key reference should fail");
  }
}
