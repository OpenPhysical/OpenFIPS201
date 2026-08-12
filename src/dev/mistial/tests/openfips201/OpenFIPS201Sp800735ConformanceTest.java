package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.util.concurrent.TimeUnit;
import javacard.framework.APDU;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * SP 800-73-5 conformance assertions.
 *
 * <p>These tests encode normative requirements from SP 800-73-5 and are intended to fail when the
 * implementation violates them.
 */
@Timeout(value = 15, unit = TimeUnit.SECONDS)
class OpenFIPS201Sp800735ConformanceTest extends OpenFIPS201TestSupport {

  private static final boolean FIPS_MODE = Boolean.getBoolean("fips.mode");
  private static final byte SC_MASK =
      (byte) (SecureChannel.AUTHENTICATED | SecureChannel.C_DECRYPTION | SecureChannel.C_MAC);

  @Test
  void verifyMalformedPinMayReturn6A80Or63Cx() {
    assertSw(0x9000, selectApplet(), "SELECT before VERIFY conformance test");

    ResponseAPDU response = transmit(0x00, 0x20, 0x00, 0x80, hex("31323334353647FF"));
    int sw = response.getSW();
    assertTrue(
        sw == 0x6A80 || (sw & 0xFFF0) == 0x63C0,
        "SP 800-73-5 allows 6A80 or 63Cx for malformed authentication data, but got "
            + swHex(response));
  }

  @Test
  void resetRetryCounterCombinedInvalidCaseMayReturn6A80Or63Cx() {
    assertSw(0x9000, selectApplet(), "SELECT before RESET RETRY COUNTER conformance test");

    // PUK is wrong and new PIN is malformed. SP 800-73-5 explicitly allows either 6A80 or 63Cx.
    ResponseAPDU response =
        transmit(0x00, 0x2C, 0x00, 0x80, hex("303132333435363731323334353647FF"));
    int sw = response.getSW();
    assertTrue(
        sw == 0x6A80 || (sw & 0xFFF0) == 0x63C0,
        "SP 800-73-5 allows 6A80 or 63Cx for combined-invalid RESET RETRY COUNTER case, but got "
            + swHex(response));
  }

  @Test
  void pinRetryCounterMustNotBeConfigurableAboveTen() {
    assertSw(0x9000, selectApplet(), "SELECT before retry-limit conformance test");

    // SP 800-73-5 (Part 2, VERIFY/CHANGE REFERENCE DATA behavior) caps retry counters at 10.
    // This APDU attempts to configure contact and contactless PIN retries to 11.
    ResponseAPDU response = updateConfigOverMockedScp(hex("68 08 A0 06 86 01 0B 87 01 0B"));
    assertSw(0x6984, response, "Configuring PIN retry limits above 10 must be rejected");
  }

  @Test
  void pukRetryCounterMustNotBeConfigurableAboveTen() {
    assertSw(0x9000, selectApplet(), "SELECT before retry-limit conformance test");

    // Same conformance requirement as PIN retries; attempts to set PUK retries to 11.
    ResponseAPDU response = updateConfigOverMockedScp(hex("68 08 A1 06 83 01 0B 84 01 0B"));
    assertSw(0x6984, response, "Configuring PUK retry limits above 10 must be rejected");
  }

  @Test
  void pinMinimumLengthMustNotBeConfigurableBelowSix() {
    assertSw(0x9000, selectApplet(), "SELECT before PIN length conformance test");

    // SP 800-73-5 PIN encoding rules require at least six significant PIN bytes.
    ResponseAPDU response = updateConfigOverMockedScp(hex("68 08 A0 06 84 01 05 85 01 08"));
    assertSw(0x6984, response, "Configuring PIN minimum length below 6 must be rejected");
  }

  @Test
  void pinMaximumLengthMustNotBeConfigurableAboveEight() {
    assertSw(0x9000, selectApplet(), "SELECT before PIN length conformance test");

    // SP 800-73-5 PIN presentation is 8 bytes with 0xFF padding, so max significant length is 8.
    ResponseAPDU response = updateConfigOverMockedScp(hex("68 08 A0 06 84 01 06 85 01 09"));
    assertSw(0x6984, response, "Configuring PIN maximum length above 8 must be rejected");
  }

  @Test
  void resetRetryCounterWireLengthDoesNotFollowConfiguredPinLimit() {
    assertSw(0x9000, selectApplet(), "SELECT before RESET RETRY COUNTER length test");
    assertSw(
        0x9000,
        updateConfigOverMockedScp(hex("68 08 A0 06 84 01 06 85 01 07")),
        "Configure a seven-byte significant PIN limit");

    ResponseAPDU response =
        transmit(0x00, 0x2C, 0x00, 0x80, hex("3031323334353637393837363534FFFF"));
    assertSw(0x63C9, response, "RESET RETRY COUNTER must still consume two eight-byte fields");
  }

  @Test
  void changeReferenceDataWireLengthDoesNotFollowConfiguredPinLimit() {
    assertSw(0x9000, selectApplet(), "SELECT before CHANGE REFERENCE DATA length test");
    assertSw(
        0x9000,
        updateConfigOverMockedScp(hex("68 08 A0 06 84 01 06 85 01 06")),
        "Configure a six-byte significant PIN limit");

    ResponseAPDU response =
        transmit(0x00, 0x24, 0x00, 0x80, hex("313233343536FFFF363534333231FFFF"));
    assertSw(0x9000, response, "CHANGE REFERENCE DATA must consume two eight-byte fields");
  }

  @Test
  void contactlessChangeReferenceDataRequiresVciEvenWhenContactlessPinChangeIsEnabled() {
    assertSw(0x9000, selectApplet(), "SELECT before contactless PIN change config");
    assertSw(
        0x9000,
        updateConfigOverMockedScp(hex("68 05 A0 03 83 01 FF")),
        "Enable contactless PIN change");

    try (MockedStatic<APDU> mockedApdu = Mockito.mockStatic(APDU.class)) {
      mockedApdu
          .when(APDU::getProtocol)
          .thenReturn((byte) (APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A | APDU.PROTOCOL_T1));
      assertSw(0x9000, selectApplet(), "SELECT over contactless");

      ResponseAPDU response =
          transmit(0x00, 0x24, 0x00, 0x80, hex("313233343536FFFFFF363534333231FFFFFF"));
      assertSw(
          0x6982,
          response,
          "Contactless CHANGE REFERENCE DATA for key ref 80 requires VCI, not plaintext");
    }
  }

  @Test
  void contactlessVerifyStatusAndResetRequireVci() {
    assertSw(0x9000, selectApplet(), "SELECT before contactless VERIFY policy test");
    assertSw(
        0x9000,
        updateConfigOverMockedScp(hex("68 05 A0 03 83 01 FF")),
        "Enable contactless PIN use");

    try (MockedStatic<APDU> mockedApdu = Mockito.mockStatic(APDU.class)) {
      mockedApdu
          .when(APDU::getProtocol)
          .thenReturn((byte) (APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A | APDU.PROTOCOL_T1));
      assertSw(0x9000, selectApplet(), "SELECT over contactless");
      assertSw(
          0x6982,
          transmit(0x00, 0x20, 0x00, 0x80),
          "Contactless VERIFY status must require VCI");
      assertSw(
          0x6982,
          transmit(0x00, 0x20, 0xFF, 0x80),
          "Contactless VERIFY reset must require VCI");
    }
  }

  @Test
  void globalPinStatusAndResetRequireDiscoveryAdvertisement() {
    assertSw(0x9000, selectApplet(), "SELECT before Global PIN policy test");
    assertSw(
        0x9000,
        updateConfigOverMockedScp(hex("68 05 A0 03 81 01 FF")),
        "Enable Global PIN without provisioning Discovery");

    assertSw(
        0x6A88,
        transmit(0x00, 0x20, 0x00, 0x00),
        "Global PIN status must require Discovery advertisement");
    assertSw(
        0x6A88,
        transmit(0x00, 0x20, 0xFF, 0x00),
        "Global PIN reset must require Discovery advertisement");
  }

  @Test
  void strictContactlessPutDataAndGenerateKeyAreUnsupported() {
    assumeTrue(FIPS_MODE, "Strict command availability is enforced by the FIPS profile");
    try (MockedStatic<APDU> mockedApdu = Mockito.mockStatic(APDU.class)) {
      mockedApdu
          .when(APDU::getProtocol)
          .thenReturn((byte) (APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A | APDU.PROTOCOL_T1));
      assertSw(0x9000, selectApplet(), "SELECT over contactless");
      assertSw(
          0x6A81,
          transmit(0x00, 0xDB, 0x3F, 0xFF, hex("5C035FC1025300")),
          "Strict contactless PUT DATA must be unsupported");
      assertSw(
          0x6A81,
          transmit(0x00, 0x47, 0x00, 0x9A, hex("AC03800111")),
          "Strict contactless GENERATE KEY must be unsupported");
    }
  }

  @Test
  void strictProfileRejectsContactlessPukChangeAsUnsupported() {
    assertSw(0x9000, selectApplet(), "SELECT before contactless PUK policy test");
    assertSw(
        0x9000,
        updateConfigOverMockedScp(hex("68 05 A1 03 81 01 FF")),
        "Enable the relaxed-profile contactless PUK extension");

    try (MockedStatic<APDU> mockedApdu = Mockito.mockStatic(APDU.class)) {
      mockedApdu
          .when(APDU::getProtocol)
          .thenReturn((byte) (APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A | APDU.PROTOCOL_T1));
      assertSw(0x9000, selectApplet(), "SELECT over contactless");
      assertSw(
          FIPS_MODE ? 0x6A81 : 0x9000,
          transmit(
              0x00,
              0x24,
              0x00,
              0x81,
              hex("31323334353637383837363534333231")),
          "Strict mode must not expose contactless PUK change");
    }
  }

  @Test
  void strictProfileRejectsContactlessResetRetryCounterAsUnsupported() {
    assertSw(0x9000, selectApplet(), "SELECT before contactless retry-reset policy test");
    assertSw(
        0x9000,
        updateConfigOverMockedScp(hex("680AA0038301FFA1038101FF")),
        "Enable the relaxed-profile contactless PIN and PUK extensions");

    try (MockedStatic<APDU> mockedApdu = Mockito.mockStatic(APDU.class)) {
      mockedApdu
          .when(APDU::getProtocol)
          .thenReturn((byte) (APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A | APDU.PROTOCOL_T1));
      assertSw(0x9000, selectApplet(), "SELECT over contactless");
      assertSw(
          FIPS_MODE ? 0x6A81 : 0x9000,
          transmit(
              0x00,
              0x2C,
              0x00,
              0x80,
              hex("3132333435363738363534333231FFFF")),
          "Strict mode must not expose contactless retry reset");
    }
  }

  private ResponseAPDU updateConfigOverMockedScp(byte[] payload) {
    try (MockedStatic<GPSystem> mocked = Mockito.mockStatic(GPSystem.class)) {
      Mockito.when(GPSystem.getCardContentState()).thenReturn(GPSystem.APPLICATION_SELECTABLE);
      SecureChannel secureChannel = Mockito.mock(SecureChannel.class);

      Mockito.when(GPSystem.getSecureChannel()).thenReturn(secureChannel);
      Mockito.when(secureChannel.getSecurityLevel()).thenReturn(SC_MASK);
      Mockito.when(
              secureChannel.unwrap(
                  Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyShort()))
          .thenAnswer(invocation -> (short) invocation.getArgument(2));

      byte[] apdu = new byte[5 + payload.length];
      apdu[0] = (byte) 0x84; // GlobalPlatform secure-messaging CLA
      apdu[1] = (byte) 0xDB; // PUT DATA
      apdu[2] = (byte) 0x3F; // P1
      apdu[3] = (byte) 0x00; // P2 admin path
      apdu[4] = (byte) payload.length;
      System.arraycopy(payload, 0, apdu, 5, payload.length);

      return transmit(new CommandAPDU(apdu));
    }
  }
}
