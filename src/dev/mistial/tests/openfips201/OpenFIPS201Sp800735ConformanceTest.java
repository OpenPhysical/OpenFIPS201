package dev.mistial.tests.openfips201;

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * SP 800-73-5 conformance assertions.
 *
 * <p>These tests encode normative requirements from SP 800-73-5 and are intended to fail when the
 * implementation violates them.
 */
@Timeout(value = 15, unit = TimeUnit.SECONDS)
class OpenFIPS201Sp800735ConformanceTest extends OpenFIPS201TestSupport {

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
    assertTrue(
        response.getSW() != 0x9000,
        "Configuring PIN retry limits above 10 should be rejected as non-conformant");
  }

  @Test
  void pukRetryCounterMustNotBeConfigurableAboveTen() {
    assertSw(0x9000, selectApplet(), "SELECT before retry-limit conformance test");

    // Same conformance requirement as PIN retries; attempts to set PUK retries to 11.
    ResponseAPDU response = updateConfigOverMockedScp(hex("68 08 A1 06 83 01 0B 84 01 0B"));
    assertTrue(
        response.getSW() != 0x9000,
        "Configuring PUK retry limits above 10 should be rejected as non-conformant");
  }

  @Test
  void pinMinimumLengthMustNotBeConfigurableBelowSix() {
    assertSw(0x9000, selectApplet(), "SELECT before PIN length conformance test");

    // SP 800-73-5 PIN encoding rules require at least six significant PIN bytes.
    ResponseAPDU response = updateConfigOverMockedScp(hex("68 08 A0 06 84 01 05 85 01 08"));
    assertTrue(
        response.getSW() != 0x9000,
        "Configuring PIN minimum length below 6 should be rejected as non-conformant");
  }

  @Test
  void pinMaximumLengthMustNotBeConfigurableAboveEight() {
    assertSw(0x9000, selectApplet(), "SELECT before PIN length conformance test");

    // SP 800-73-5 PIN presentation is 8 bytes with 0xFF padding, so max significant length is 8.
    ResponseAPDU response = updateConfigOverMockedScp(hex("68 08 A0 06 84 01 06 85 01 09"));
    assertTrue(
        response.getSW() != 0x9000,
        "Configuring PIN maximum length above 8 should be rejected as non-conformant");
  }

  private ResponseAPDU updateConfigOverMockedScp(byte[] payload) {
    try (MockedStatic<GPSystem> mocked = Mockito.mockStatic(GPSystem.class)) {
      SecureChannel secureChannel = Mockito.mock(SecureChannel.class);

      Mockito.when(GPSystem.getSecureChannel()).thenReturn(secureChannel);
      Mockito.when(secureChannel.getSecurityLevel()).thenReturn(SC_MASK);
      Mockito.when(secureChannel.unwrap(Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyShort()))
          .thenAnswer(invocation -> (short) invocation.getArgument(2));

      byte[] apdu = new byte[5 + payload.length];
      apdu[0] = (byte) 0x04; // Secure messaging CLA, no command chaining bit
      apdu[1] = (byte) 0xDB; // PUT DATA
      apdu[2] = (byte) 0x3F; // P1
      apdu[3] = (byte) 0x00; // P2 admin path
      apdu[4] = (byte) payload.length;
      System.arraycopy(payload, 0, apdu, 5, payload.length);

      return transmit(new CommandAPDU(apdu));
    }
  }
}
