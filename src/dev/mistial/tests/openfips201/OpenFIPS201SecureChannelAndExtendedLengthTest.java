package dev.mistial.tests.openfips201;

import javacard.framework.ISO7816;
import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * Regression tests for security-channel unwrap length handling and extended APDU receive logic.
 */
@Timeout(value = 15, unit = TimeUnit.SECONDS)
class OpenFIPS201SecureChannelAndExtendedLengthTest extends OpenFIPS201TestSupport {

  @Test
  void secureChannelHandlersUseUnwrappedPayloadLength() {
    // This guards the regression where command handlers used APDU.getIncomingLength() after unwrap,
    // which reflects wrapped length on some runtimes.
    try (MockedStatic<GPSystem> mocked = Mockito.mockStatic(GPSystem.class)) {
      SecureChannel secureChannel = Mockito.mock(SecureChannel.class);

      Mockito.when(secureChannel.getSecurityLevel())
          .thenReturn((byte) (SecureChannel.AUTHENTICATED | SecureChannel.C_DECRYPTION | SecureChannel.C_MAC));
      Mockito.when(GPSystem.getSecureChannel()).thenReturn(secureChannel);

      // Simulate SCP metadata removal reducing plaintext length by four bytes.
      Mockito.when(secureChannel.unwrap(Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyShort()))
          .thenAnswer(invocation -> (short) (((short) invocation.getArgument(2)) - 4));

      assertSw(0x9000, selectApplet(), "SELECT before SCP length regression test");

      // Wrapped length is 20 bytes. Plaintext length seen by handlers should become 16.
      byte[] resetRetryWrapped =
          hex(
              "E4 2C 00 80 14 "
                  + "31 32 33 34 35 36 37 38 " // wrong PUK guess
                  + "39 38 37 36 35 34 FF FF " // new PIN in valid format
                  + "AA BB CC DD"); // synthetic SCP wrapper overhead

      ResponseAPDU response = transmit(new CommandAPDU(resetRetryWrapped));

      // If wrapped length leaks into handler logic, this tends to fail as WRONG_DATA (6A80).
      // Correct logic should proceed into the command and return a business status.
      assertNotEquals(ISO7816.SW_WRONG_DATA, response.getSW(), "Handler must use unwrapped Lc");
      Mockito.verify(secureChannel, Mockito.atLeastOnce())
          .unwrap(Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyShort());
    }
  }

  @Test
  void extendedLengthOverApduBufferIsRejectedWithWrongLength() {
    assertSw(0x9000, selectApplet(), "SELECT before extended-length test");

    byte[] oversizedPayload = new byte[300];
    for (int i = 0; i < oversizedPayload.length; i++) {
      oversizedPayload[i] = (byte) i;
    }

    // Any command with Nc beyond what can be assembled contiguously in the APDU buffer should be
    // rejected early by receiveAllIncomingData().
    CommandAPDU oversized = new CommandAPDU(0x00, 0x2C, 0x00, 0x80, oversizedPayload, 0);
    ResponseAPDU response = transmit(oversized);
    assertEquals(ISO7816.SW_WRONG_LENGTH, response.getSW(), "Oversized Nc should return WRONG_LENGTH");
  }

  @Test
  void initializeUpdateAndExternalAuthenticateDispatchToGpSecureChannel() {
    try (MockedStatic<GPSystem> mocked = Mockito.mockStatic(GPSystem.class)) {
      SecureChannel secureChannel = Mockito.mock(SecureChannel.class);
      Mockito.when(GPSystem.getSecureChannel()).thenReturn(secureChannel);
      Mockito.when(secureChannel.processSecurity(Mockito.any())).thenReturn((short) 0);

      assertSw(0x9000, selectApplet(), "SELECT before GP SCP command dispatch test");

      ResponseAPDU initUpdate = transmit(new CommandAPDU(0x80, 0x50, 0x00, 0x00, hex("0102030405060708")));
      assertSw(0x9000, initUpdate, "INITIALIZE UPDATE should route to SecureChannel.processSecurity");
      Mockito.verify(secureChannel).resetSecurity();

      ResponseAPDU extAuth = transmit(new CommandAPDU(0x84, 0x82, 0x00, 0x00, hex("0000000000000000")));
      assertSw(0x9000, extAuth, "EXTERNAL AUTHENTICATE should route to SecureChannel.processSecurity");
      Mockito.verify(secureChannel, Mockito.times(2)).processSecurity(Mockito.any());
    }
  }
}
