package dev.mistial.tests.openfips201;

import javacard.framework.ISO7816;
import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * TDD coverage for management key (9B) updates using INS=0x24 (CHANGE REFERENCE DATA).
 *
 * <p>Design intent exercised here:
 *
 * <ul>
 *   <li>Use PIV algorithm identifiers in P1 for key mechanisms (03/08/0A/0C).
 *   <li>Permit management key update outside SCP when administrative authentication is satisfied.
 *   <li>Keep key injection payload shape aligned with existing admin key-import semantics:
 *       SEQUENCE(0x30) + key element (0x80).
 * </ul>
 */
@Timeout(value = 20, unit = TimeUnit.SECONDS)
class OpenFIPS201ManagementKeyChangeReferenceDataTest extends OpenFIPS201TestSupport {

  // PIV algorithm identifiers (SP 800-73/78 aligned)
  private static final byte ALG_3DES = (byte) 0x03;
  private static final byte ALG_AES_128 = (byte) 0x08;
  private static final byte ALG_AES_192 = (byte) 0x0A;
  private static final byte ALG_AES_256 = (byte) 0x0C;

  private static final byte KEY_REF_CARD_MANAGEMENT = (byte) 0x9B;

  @Test
  void managementKeyChangeRequiresAuthenticatedAdminOutsideSecureChannel() {
    byte[] initialKey = keyMaterial(ALG_AES_128, (byte) 0x11);
    byte[] rotatedKey = keyMaterial(ALG_AES_128, (byte) 0x31);

    provisionManagementKeyOverScp(ALG_AES_128, initialKey);
    assertSw(0x9000, selectApplet(), "SELECT before unauthenticated management key change");

    ResponseAPDU response = transmit(0x00, 0x24, ALG_AES_128 & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, keyUpdateData(rotatedKey));
    assertSw(
        ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
        response,
        "Changing 9B outside SCP must require prior admin authentication");
  }

  @Test
  void managementKeyChangeSucceedsAfterGeneralAuthenticateOutsideSecureChannel() {
    byte[] initialKey = keyMaterial(ALG_AES_128, (byte) 0x21);
    byte[] rotatedKey = keyMaterial(ALG_AES_128, (byte) 0x41);

    provisionManagementKeyOverScp(ALG_AES_128, initialKey);
    authenticateManagementKey(ALG_AES_128, initialKey);

    ResponseAPDU response = transmit(0x00, 0x24, ALG_AES_128 & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, keyUpdateData(rotatedKey));
    assertSw(0x9000, response, "Authenticated admin session should permit 9B rotation without SCP");
  }

  @Test
  void managementKeyRotationInvalidatesOldValueAndAcceptsNewValue() {
    byte[] initialKey = keyMaterial(ALG_AES_128, (byte) 0x51);
    byte[] rotatedKey = keyMaterial(ALG_AES_128, (byte) 0x61);

    provisionManagementKeyOverScp(ALG_AES_128, initialKey);
    authenticateManagementKey(ALG_AES_128, initialKey);
    assertSw(
        0x9000,
        transmit(0x00, 0x24, ALG_AES_128 & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, keyUpdateData(rotatedKey)),
        "9B rotation should succeed before post-rotation verification");

    reconnectAndSelect();

    int oldKeyAuthSw = authenticateManagementKeyAndReturnSw(ALG_AES_128, initialKey);
    assertNotEquals(0x9000, oldKeyAuthSw, "Old management key must fail after rotation");

    int newKeyAuthSw = authenticateManagementKeyAndReturnSw(ALG_AES_128, rotatedKey);
    assertEquals(0x9000, newKeyAuthSw, "New management key must authenticate after rotation");
  }

  @Test
  void managementKeyChangeRejectsWrongKeyLengthForAlgorithm() {
    byte[] initialKey = keyMaterial(ALG_AES_128, (byte) 0x71);
    byte[] wrongSizedKeyForAes128 = keyMaterial(ALG_AES_192, (byte) 0x72); // 24 bytes, should fail for 0x08

    provisionManagementKeyOverScp(ALG_AES_128, initialKey);
    authenticateManagementKey(ALG_AES_128, initialKey);

    ResponseAPDU response =
        transmit(0x00, 0x24, ALG_AES_128 & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, keyUpdateData(wrongSizedKeyForAes128));
    assertSw(
        ISO7816.SW_WRONG_LENGTH,
        response,
        "9B update payload length must match key size for the algorithm in P1");
  }

  @Test
  void managementKeyChangeCannotSwitchToDifferentAlgorithmType() {
    byte[] initialAes256Key = keyMaterial(ALG_AES_256, (byte) 0x75);
    byte[] candidateAes128Key = keyMaterial(ALG_AES_128, (byte) 0x76);

    provisionManagementKeyOverScp(ALG_AES_256, initialAes256Key);
    authenticateManagementKey(ALG_AES_256, initialAes256Key);

    // A different (but still valid PIV) algorithm ID must not retarget the existing key object.
    // Type migration requires a management-domain delete/recreate flow, not CHANGE REFERENCE DATA.
    ResponseAPDU response =
        transmit(0x00, 0x24, ALG_AES_128 & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, keyUpdateData(candidateAes128Key));
    assertSw(
        0x6A88,
        response,
        "9B key mechanism is immutable for CHANGE REFERENCE DATA");
  }

  @Test
  void managementKeyChangeRejectsNonPivAlgorithmIdentifier() {
    byte[] initialKey = keyMaterial(ALG_AES_128, (byte) 0x73);
    byte[] rotatedKey = keyMaterial(ALG_AES_128, (byte) 0x74);

    provisionManagementKeyOverScp(ALG_AES_128, initialKey);
    authenticateManagementKey(ALG_AES_128, initialKey);

    ResponseAPDU response = transmit(0x00, 0x24, 0x09, KEY_REF_CARD_MANAGEMENT & 0xFF, keyUpdateData(rotatedKey));
    assertSw(
        ISO7816.SW_INCORRECT_P1P2,
        response,
        "Management key updates must use PIV algorithm identifiers in P1");
  }

  @Test
  void pivAlgorithmIdentifier03WorksForManagementKeyChange() {
    assertManagementKeyRotationWorksWithoutScp(ALG_3DES);
  }

  @Test
  void pivAlgorithmIdentifier08WorksForManagementKeyChange() {
    assertManagementKeyRotationWorksWithoutScp(ALG_AES_128);
  }

  @Test
  void pivAlgorithmIdentifier0aWorksForManagementKeyChange() {
    assertManagementKeyRotationWorksWithoutScp(ALG_AES_192);
  }

  @Test
  void pivAlgorithmIdentifier0cWorksForManagementKeyChange() {
    assertManagementKeyRotationWorksWithoutScp(ALG_AES_256);
  }

  /**
   * Provisions a symmetric management key object and value under mocked SCP.
   *
   * <p>This mirrors OpenFIPS201's documented profile flow: create key object with PUT DATA admin,
   * then inject key value with CHANGE REFERENCE DATA admin.
   */
  private void provisionManagementKeyOverScp(byte algorithm, byte[] keyBytes) {
    try (MockedStatic<GPSystem> mockedGp = Mockito.mockStatic(GPSystem.class)) {
      SecureChannel secureChannel = Mockito.mock(SecureChannel.class);
      Mockito.when(secureChannel.getSecurityLevel())
          .thenReturn((byte) (SecureChannel.AUTHENTICATED | SecureChannel.C_DECRYPTION | SecureChannel.C_MAC));
      Mockito.when(secureChannel.unwrap(Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyShort()))
          .thenAnswer(invocation -> (short) invocation.getArgument(2));
      Mockito.when(GPSystem.getSecureChannel()).thenReturn(secureChannel);

      assertSw(0x9000, selectApplet(), "SELECT before SCP provisioning flow");

      // 66 { 8B=id, 8C=mode contact, 8D=mode contactless, 8E=mechanism, 8F=role, 90=attrs }
      // Access mode and key attributes align with the NIST-compliant profile scripts.
      byte[] createManagementKeyObject =
          new byte[] {
            (byte) 0x66, (byte) 0x12,
            (byte) 0x8B, (byte) 0x01, KEY_REF_CARD_MANAGEMENT,
            (byte) 0x8C, (byte) 0x01, (byte) 0x7F,
            (byte) 0x8D, (byte) 0x01, (byte) 0x00,
            (byte) 0x8E, (byte) 0x01, algorithm,
            (byte) 0x8F, (byte) 0x01, (byte) 0x01,
            (byte) 0x90, (byte) 0x01, (byte) 0x11
          };

      ResponseAPDU createResponse = transmit(0x84, 0xDB, 0x3F, 0x00, createManagementKeyObject);
      assertSw(0x9000, createResponse, "SCP create-key operation for 9B should succeed");

      ResponseAPDU importResponse =
          transmit(0x84, 0x24, algorithm & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, keyUpdateData(keyBytes));
      assertSw(0x9000, importResponse, "SCP initial key import for 9B should succeed");
    }
  }

  private void assertManagementKeyRotationWorksWithoutScp(byte algorithm) {
    byte[] initialKey = keyMaterial(algorithm, (byte) (0x30 + (algorithm & 0x0F)));
    byte[] rotatedKey = keyMaterial(algorithm, (byte) (0x50 + (algorithm & 0x0F)));

    provisionManagementKeyOverScp(algorithm, initialKey);
    authenticateManagementKey(algorithm, initialKey);
    assertSw(
        0x9000,
        transmit(0x00, 0x24, algorithm & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, keyUpdateData(rotatedKey)),
        "PIV algorithm ID " + String.format("0x%02X", algorithm) + " should support 9B update");
  }

  private void authenticateManagementKey(byte algorithm, byte[] keyBytes) {
    int sw = authenticateManagementKeyAndReturnSw(algorithm, keyBytes);
    assertEquals(0x9000, sw, "GENERAL AUTHENTICATE should succeed for current 9B value");
  }

  private int authenticateManagementKeyAndReturnSw(byte algorithm, byte[] keyBytes) {
    assertSw(0x9000, selectApplet(), "SELECT before GENERAL AUTHENTICATE");

    // External authenticate request: ask the card for a plaintext challenge.
    byte[] externalAuthRequest = hex("7C028100");
    ResponseAPDU challengeResponse =
        transmit(0x00, 0x87, algorithm & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, externalAuthRequest);
    assertSw(0x9000, challengeResponse, "GENERAL AUTHENTICATE challenge request should succeed");

    byte[] expectedChallenge = extractChallenge(challengeResponse.getData(), challengeLengthForAlgorithm(algorithm));
    byte[] encryptedChallenge = encryptChallengeWithManagementKey(algorithm, keyBytes, expectedChallenge);

    // External authenticate response: send encrypted challenge response in tag 0x82.
    byte[] externalAuthResponse =
        concat(
            new byte[] {(byte) 0x7C, (byte) (encryptedChallenge.length + 2), (byte) 0x82, (byte) encryptedChallenge.length},
            encryptedChallenge);
    ResponseAPDU verificationResponse =
        transmit(0x00, 0x87, algorithm & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, externalAuthResponse);
    return verificationResponse.getSW();
  }

  private void reconnectAndSelect() {
    if (session != null && !session.isClosed()) {
      session.close();
    }
    session = engine.connect();
    assertSw(0x9000, selectApplet(), "SELECT after reconnect");
  }

  private void changeManagementKeyOverScp(byte algorithm, byte[] keyBytes) {
    try (MockedStatic<GPSystem> mockedGp = Mockito.mockStatic(GPSystem.class)) {
      SecureChannel secureChannel = Mockito.mock(SecureChannel.class);
      Mockito.when(secureChannel.getSecurityLevel())
          .thenReturn((byte) (SecureChannel.AUTHENTICATED | SecureChannel.C_DECRYPTION | SecureChannel.C_MAC));
      Mockito.when(secureChannel.unwrap(Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyShort()))
          .thenAnswer(invocation -> (short) invocation.getArgument(2));
      Mockito.when(GPSystem.getSecureChannel()).thenReturn(secureChannel);

      assertSw(0x9000, selectApplet(), "SELECT before SCP management key update");
      ResponseAPDU updateResponse =
          transmit(0x84, 0x24, algorithm & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, keyUpdateData(keyBytes));
      assertSw(0x9000, updateResponse, "SCP 9B update should succeed for PIV algorithm identifier");
    }
  }

  private static byte[] keyUpdateData(byte[] keyBytes) {
    return concat(new byte[] {(byte) 0x30, (byte) (keyBytes.length + 2), (byte) 0x80, (byte) keyBytes.length}, keyBytes);
  }

  private static byte[] extractChallenge(byte[] responseData, int expectedLength) {
    assertEquals(4 + expectedLength, responseData.length, "Unexpected external authenticate response length");
    assertEquals((byte) 0x7C, responseData[0], "Response must be wrapped in Dynamic Authentication Template (0x7C)");
    assertEquals((byte) (responseData.length - 2), responseData[1], "Outer template length must match payload");
    assertEquals((byte) 0x81, responseData[2], "External authenticate challenge response must include tag 0x81");
    assertEquals((byte) expectedLength, responseData[3], "Challenge size must match algorithm block size");

    byte[] challenge = new byte[expectedLength];
    System.arraycopy(responseData, 4, challenge, 0, expectedLength);
    return challenge;
  }

  private static byte[] encryptChallengeWithManagementKey(byte algorithm, byte[] keyBytes, byte[] challenge) {
    try {
      if (algorithm == ALG_3DES) {
        Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "DESede"));
        return cipher.doFinal(challenge);
      }

      Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"));
      return cipher.doFinal(challenge);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to encrypt GENERAL AUTHENTICATE challenge", e);
    }
  }

  private static int challengeLengthForAlgorithm(byte algorithm) {
    return (algorithm == ALG_3DES) ? 8 : 16;
  }

  private static byte[] keyMaterial(byte algorithm, byte seed) {
    int len;
    switch (algorithm) {
      case ALG_3DES:
        len = 24;
        break;
      case ALG_AES_128:
        len = 16;
        break;
      case ALG_AES_192:
        len = 24;
        break;
      case ALG_AES_256:
        len = 32;
        break;
      default:
        throw new IllegalArgumentException("Unsupported management key algorithm: " + String.format("0x%02X", algorithm));
    }

    byte[] key = new byte[len];
    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) (seed + i);
    }
    if (algorithm == ALG_3DES) {
      for (int i = 0; i < key.length; i++) {
        key[i] = toOddParity(key[i]);
      }
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
