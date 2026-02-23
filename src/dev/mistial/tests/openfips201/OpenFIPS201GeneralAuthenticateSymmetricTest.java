package dev.mistial.tests.openfips201;

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import javax.smartcardio.ResponseAPDU;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Regression coverage for symmetric GENERAL AUTHENTICATE behavior.
 */
@Timeout(value = 15, unit = TimeUnit.SECONDS)
class OpenFIPS201GeneralAuthenticateSymmetricTest extends OpenFIPS201TestSupport {

  private static final byte ALG_3DES = (byte) 0x03;
  private static final byte KEY_REF_CARD_MANAGEMENT = (byte) 0x9B;

  @Test
  void externalAuthenticateChallengeSucceedsForProvisioned3desManagementKey() {
    provisionManagementKeyOverScp(keyMaterial3des((byte) 0x41));

    assertSw(0x9000, selectApplet(), "SELECT before 3DES GENERAL AUTHENTICATE");

    // Case 2: external authenticate challenge request (7C {81 00})
    ResponseAPDU response = transmit(0x00, 0x87, ALG_3DES & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, hex("7C028100"));
    assertSw(0x9000, response, "GENERAL AUTHENTICATE challenge request should succeed");

    byte[] data = response.getData();
    assertEquals(12, data.length, "3DES challenge response should be 7C/81 wrapper plus 8-byte challenge");
    assertEquals((byte) 0x7C, data[0], "Response should use dynamic authentication template");
    assertEquals((byte) 0x81, data[2], "Response should contain challenge tag 0x81");
    assertEquals((byte) 0x08, data[3], "3DES challenge length should be 8 bytes");
  }

  private void provisionManagementKeyOverScp(byte[] keyBytes) {
    try (MockedStatic<GPSystem> mockedGp = Mockito.mockStatic(GPSystem.class)) {
      SecureChannel secureChannel = Mockito.mock(SecureChannel.class);
      Mockito.when(secureChannel.getSecurityLevel())
          .thenReturn((byte) (SecureChannel.AUTHENTICATED | SecureChannel.C_DECRYPTION | SecureChannel.C_MAC));
      Mockito.when(secureChannel.unwrap(Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyShort()))
          .thenAnswer(invocation -> (short) invocation.getArgument(2));
      Mockito.when(GPSystem.getSecureChannel()).thenReturn(secureChannel);

      assertSw(0x9000, selectApplet(), "SELECT before SCP provisioning flow");

      // 66 { 8B=id, 8C=mode contact, 8D=mode contactless, 8E=mechanism, 8F=role, 90=attrs }
      byte[] createManagementKeyObject =
          new byte[] {
            (byte) 0x66, (byte) 0x12,
            (byte) 0x8B, (byte) 0x01, KEY_REF_CARD_MANAGEMENT,
            (byte) 0x8C, (byte) 0x01, (byte) 0x7F,
            (byte) 0x8D, (byte) 0x01, (byte) 0x00,
            (byte) 0x8E, (byte) 0x01, ALG_3DES,
            (byte) 0x8F, (byte) 0x01, (byte) 0x01,
            (byte) 0x90, (byte) 0x01, (byte) 0x11
          };

      assertSw(
          0x9000,
          transmit(0x84, 0xDB, 0x3F, 0x00, createManagementKeyObject),
          "SCP create-key operation for 9B should succeed");
      assertSw(
          0x9000,
          transmit(0x84, 0x24, ALG_3DES & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, keyUpdateData(keyBytes)),
          "SCP initial key import for 9B should succeed");
    }
  }

  private static byte[] keyUpdateData(byte[] keyBytes) {
    return concat(new byte[] {(byte) 0x30, (byte) (keyBytes.length + 2), (byte) 0x80, (byte) keyBytes.length}, keyBytes);
  }

  private static byte[] keyMaterial3des(byte seed) {
    byte[] key = new byte[24];
    for (int i = 0; i < key.length; i++) {
      key[i] = toOddParity((byte) (seed + i));
    }
    return key;
  }

  private static byte[] concat(byte[] prefix, byte[] suffix) {
    byte[] output = new byte[prefix.length + suffix.length];
    System.arraycopy(prefix, 0, output, 0, prefix.length);
    System.arraycopy(suffix, 0, output, prefix.length, suffix.length);
    return output;
  }

  private static byte toOddParity(byte value) {
    int upperSevenBits = value & 0xFE;
    int ones = Integer.bitCount(upperSevenBits);
    return (byte) ((ones & 1) == 0 ? (upperSevenBits | 0x01) : upperSevenBits);
  }
}
