package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;

import javacard.framework.ISO7816;
import javax.smartcardio.ResponseAPDU;
import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class OpenFIPS201AsymmetricKeyTest extends OpenFIPS201TestSupport {
  private static final int KEY_REFERENCE = 0x9A;

  @Test
  void generatesRsa1024KeyPairAndReturnsModulusAndExponent() {
    withMockedScp(
        () -> {
          createKey(0x06, 0x04);
          ResponseAPDU response =
              transmit(0x84, 0x47, 0x00, KEY_REFERENCE, hex("AC03800106"), 0);
          assertSw(0x9000, response, "RSA key generation");
          byte[] data = response.getData();
          assertEquals((byte) 0x7F, data[0]);
          assertEquals((byte) 0x49, data[1]);
        });
  }

  @Test
  void generatesP256KeyPairAndReturnsUncompressedPoint() {
    withMockedScp(
        () -> {
          createKey(0x11, 0x04);
          ResponseAPDU response =
              transmit(0x84, 0x47, 0x00, KEY_REFERENCE, hex("AC03800111"), 0);
          assertSw(0x9000, response, "P-256 key generation");
          byte[] data = response.getData();
          assertEquals((byte) 0x7F, data[0]);
          assertEquals((byte) 0x49, data[1]);
          assertEquals((byte) 0x86, data[3]);
          assertEquals((byte) 0x04, data[5]);
        });
  }

  @Test
  void rejectsConflictingAsymmetricRolesDuringProvisioning() {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before conflicting-role test");
          assertSw(
              ISO7816.SW_WRONG_DATA,
              transmit(0x84, 0xDB, 0x3F, 0x00, createKeyRequest(0x11, 0x06)),
              "SIGN and KEY_ESTABLISH roles must be mutually exclusive");
        });
  }

  @Test
  void rejectsOffCurvePointThroughGeneralAuthenticate() {
    withMockedScp(
        () -> {
          createKey(0x11, 0x02);
          assertSw(
              0x9000,
              transmit(0x84, 0x47, 0x00, KEY_REFERENCE, hex("AC03800111"), 0),
              "P-256 key generation");

          byte[] point = new byte[65];
          point[0] = 0x04;
          byte[] request = new byte[69];
          request[0] = 0x7C;
          request[1] = 0x43;
          request[2] = (byte) 0x85;
          request[3] = 0x41;
          System.arraycopy(point, 0, request, 4, point.length);

          assertSw(
              ISO7816.SW_WRONG_DATA,
              transmit(0x00, 0x87, 0x11, KEY_REFERENCE, request, 0),
              "GENERAL AUTHENTICATE must reject an off-curve ECDH point");
        });
  }

  @Test
  void signsP256DigestThroughGeneralAuthenticate() {
    withMockedScp(
        () -> {
          createKey(0x11, 0x04);
          assertSw(
              0x9000,
              transmit(0x84, 0x47, 0x00, KEY_REFERENCE, hex("AC03800111"), 0),
              "P-256 key generation");

          byte[] request = new byte[38];
          request[0] = 0x7C;
          request[1] = 0x24;
          request[2] = (byte) 0x81;
          request[3] = 0x20;
          for (int i = 0; i < 32; i++) request[4 + i] = (byte) (i + 1);
          request[36] = (byte) 0x82;
          request[37] = 0x00;

          ResponseAPDU response = transmit(0x00, 0x87, 0x11, KEY_REFERENCE, request, 0);
          assertSw(0x9000, response, "P-256 GENERAL AUTHENTICATE signature");
          assertEquals(0x7C, response.getData()[0] & 0xFF);
        });
  }

  private void createKey(int mechanism, int role) {
    assertSw(0x9000, selectApplet(), "SELECT before asymmetric provisioning");
    assertSw(
        0x9000,
        transmit(0x84, 0xDB, 0x3F, 0x00, createKeyRequest(mechanism, role)),
        "Create asymmetric key object");
  }

  private static byte[] createKeyRequest(int mechanism, int role) {
    return new byte[] {
      0x66, 0x12,
      (byte) 0x8B, 0x01, (byte) KEY_REFERENCE,
      (byte) 0x8C, 0x01, 0x7F,
      (byte) 0x8D, 0x01, 0x00,
      (byte) 0x8E, 0x01, (byte) mechanism,
      (byte) 0x8F, 0x01, (byte) role,
      (byte) 0x90, 0x01, 0x00
    };
  }

  protected void withMockedScp(Runnable action) {
    try (MockedStatic<GPSystem> mocked = Mockito.mockStatic(GPSystem.class)) {
      SecureChannel secureChannel = Mockito.mock(SecureChannel.class);
      Mockito.when(secureChannel.getSecurityLevel())
          .thenReturn(
              (byte)
                  (SecureChannel.AUTHENTICATED | SecureChannel.C_DECRYPTION | SecureChannel.C_MAC));
      Mockito.when(
              secureChannel.unwrap(
                  Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyShort()))
          .thenAnswer(invocation -> (short) invocation.getArgument(2));
      Mockito.when(GPSystem.getSecureChannel()).thenReturn(secureChannel);
      action.run();
    }
  }
}
