package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.concurrent.TimeUnit;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** Regression coverage for symmetric GENERAL AUTHENTICATE behavior. */
@Timeout(value = 15, unit = TimeUnit.SECONDS)
class OpenFIPS201GeneralAuthenticateSymmetricTest extends OpenFIPS201TestSupport {

  private static final byte ALG_3DES = (byte) 0x03;
  private static final byte KEY_REF_CARD_MANAGEMENT = (byte) 0x9B;

  /** Provisions its own 3DES 9B key, so the standard (AES-128) test card is not applied. */
  @Override
  protected boolean provisionsStandardCard() {
    return false;
  }

  @Test
  void externalAuthenticateChallengeSucceedsForProvisioned3desManagementKey() {
    provisionManagementKeyOverScp(ALG_3DES, keyMaterial3des((byte) 0x41));

    assertSw(0x9000, selectApplet(), "SELECT before 3DES GENERAL AUTHENTICATE");

    // Case 2: external authenticate challenge request (7C {81 00})
    ResponseAPDU response =
        transmit(0x00, 0x87, ALG_3DES & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, hex("7C028100"));
    assertSw(0x9000, response, "GENERAL AUTHENTICATE challenge request should succeed");

    byte[] data = response.getData();
    assertEquals(
        12, data.length, "3DES challenge response should be 7C/81 wrapper plus 8-byte challenge");
    assertEquals((byte) 0x7C, data[0], "Response should use dynamic authentication template");
    assertEquals((byte) 0x81, data[2], "Response should contain challenge tag 0x81");
    assertEquals((byte) 0x08, data[3], "3DES challenge length should be 8 bytes");
  }

  private static byte[] keyMaterial3des(byte seed) {
    byte[] key = new byte[24];
    for (int i = 0; i < key.length; i++) {
      key[i] = toOddParity((byte) (seed + i));
    }
    return key;
  }

  private static byte toOddParity(byte value) {
    int upperSevenBits = value & 0xFE;
    int ones = Integer.bitCount(upperSevenBits);
    return (byte) ((ones & 1) == 0 ? (upperSevenBits | 0x01) : upperSevenBits);
  }
}
