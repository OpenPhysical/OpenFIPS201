package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.concurrent.TimeUnit;
import javacard.framework.ISO7816;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

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

    ResponseAPDU response = transmitKeyUpdate(ALG_AES_128, keyUpdateData(rotatedKey));
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
    authenticateCardManagementKey(ALG_AES_128, initialKey);

    ResponseAPDU response = transmitKeyUpdate(ALG_AES_128, keyUpdateData(rotatedKey));
    assertSw(0x9000, response, "Authenticated admin session should permit 9B rotation without SCP");
  }

  @Test
  void localPinAdministrativeChangeSucceedsAfter9bAuthentication() {
    byte[] managementKey = keyMaterial(ALG_AES_128, (byte) 0x45);
    provisionManagementKeyOverScp(ALG_AES_128, managementKey);
    authenticateCardManagementKey(ALG_AES_128, managementKey);

    ResponseAPDU response = transmitPinAdminUpdate(0x80, hex("393837363534FFFF"));
    assertSw(0x9000, response, "Authenticated 9B must authorize administrative PIN changes");
  }

  @Test
  void localPinAdministrativeChangeSucceedsOverScp() {
    ResponseAPDU response = transmitPinAdminUpdateOverScp(0x80, hex("393837363534FFFF"));
    assertSw(0x9000, response, "SCP must authorize administrative PIN changes");
  }

  @Test
  void pukAdministrativeChangeSucceedsAfter9bAuthentication() {
    byte[] managementKey = keyMaterial(ALG_AES_128, (byte) 0x46);
    provisionManagementKeyOverScp(ALG_AES_128, managementKey);
    authenticateCardManagementKey(ALG_AES_128, managementKey);

    ResponseAPDU response = transmitPinAdminUpdate(0x81, hex("3132333435363738"));
    assertSw(0x9000, response, "Authenticated 9B must authorize administrative PUK changes");
  }

  @Test
  void pukAdministrativeChangeSucceedsOverScp() {
    ResponseAPDU response = transmitPinAdminUpdateOverScp(0x81, hex("3132333435363738"));
    assertSw(0x9000, response, "SCP must authorize administrative PUK changes");
  }

  @Test
  void managementKeyRotationInvalidatesOldValueAndAcceptsNewValue() {
    byte[] initialKey = keyMaterial(ALG_AES_128, (byte) 0x51);
    byte[] rotatedKey = keyMaterial(ALG_AES_128, (byte) 0x61);

    provisionManagementKeyOverScp(ALG_AES_128, initialKey);
    authenticateCardManagementKey(ALG_AES_128, initialKey);
    assertSw(
        0x9000,
        transmitKeyUpdate(ALG_AES_128, keyUpdateData(rotatedKey)),
        "9B rotation should succeed before post-rotation verification");

    reconnectAndSelect();

    int oldKeyAuthSw = authenticateCardManagementKeyResponse(ALG_AES_128, initialKey).getSW();
    assertEquals(0x6982, oldKeyAuthSw, "Old management key must fail after rotation");

    int newKeyAuthSw = authenticateCardManagementKeyResponse(ALG_AES_128, rotatedKey).getSW();
    assertEquals(0x9000, newKeyAuthSw, "New management key must authenticate after rotation");
  }

  @Test
  void managementKeyChangeRejectsWrongKeyLengthForAlgorithm() {
    byte[] initialKey = keyMaterial(ALG_AES_128, (byte) 0x71);
    byte[] wrongSizedKeyForAes128 =
        keyMaterial(ALG_AES_192, (byte) 0x72); // 24 bytes, should fail for 0x08

    provisionManagementKeyOverScp(ALG_AES_128, initialKey);
    authenticateCardManagementKey(ALG_AES_128, initialKey);

    ResponseAPDU response = transmitKeyUpdate(ALG_AES_128, keyUpdateData(wrongSizedKeyForAes128));
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
    authenticateCardManagementKey(ALG_AES_256, initialAes256Key);

    // A different (but still valid PIV) algorithm ID must not retarget the existing key object.
    // Type migration requires a management-domain delete/recreate flow, not CHANGE REFERENCE DATA.
    ResponseAPDU response = transmitKeyUpdate(ALG_AES_128, keyUpdateData(candidateAes128Key));
    assertSw(0x6A88, response, "9B key mechanism is immutable for CHANGE REFERENCE DATA");
  }

  @Test
  void managementKeyChangeRejectsNonPivAlgorithmIdentifier() {
    byte[] initialKey = keyMaterial(ALG_AES_128, (byte) 0x73);
    byte[] rotatedKey = keyMaterial(ALG_AES_128, (byte) 0x74);

    provisionManagementKeyOverScp(ALG_AES_128, initialKey);
    authenticateCardManagementKey(ALG_AES_128, initialKey);

    ResponseAPDU response = transmitKeyUpdate((byte) 0x09, keyUpdateData(rotatedKey));
    assertSw(
        ISO7816.SW_INCORRECT_P1P2,
        response,
        "Management key updates must use PIV algorithm identifiers in P1");
  }

  @Test
  void managementKeyChangeRejectsMalformedSequenceWithoutMutatingKey() {
    byte[] initialKey = keyMaterial(ALG_AES_128, (byte) 0x12);
    byte[] candidateKey = keyMaterial(ALG_AES_128, (byte) 0x22);

    provisionManagementKeyOverScp(ALG_AES_128, initialKey);
    authenticateCardManagementKey(ALG_AES_128, initialKey);

    // Payload must be SEQUENCE(0x30) wrapping one key element.
    ResponseAPDU malformed = transmitKeyUpdate(ALG_AES_128, candidateKey);
    assertSw(ISO7816.SW_WRONG_DATA, malformed, "Non-SEQUENCE payload must be rejected");

    reconnectAndSelect();
    assertEquals(
        0x9000,
        authenticateCardManagementKeyResponse(ALG_AES_128, initialKey).getSW(),
        "Malformed update must not change the management key");
    assertEquals(
        0x6982,
        authenticateCardManagementKeyResponse(ALG_AES_128, candidateKey).getSW(),
        "Candidate key must not be accepted when update was rejected");
  }

  @Test
  void managementKeyChangeRejectsMultiElementPayloadWithoutMutatingKey() {
    byte[] initialKey = keyMaterial(ALG_AES_128, (byte) 0x13);
    byte[] candidateKey = keyMaterial(ALG_AES_128, (byte) 0x23);

    provisionManagementKeyOverScp(ALG_AES_128, initialKey);
    authenticateCardManagementKey(ALG_AES_128, initialKey);

    // Only one key element is valid in CHANGE REFERENCE DATA for a key object.
    byte[] malformedMultiElement =
        concat(keyUpdateData(candidateKey), new byte[] {(byte) 0x81, (byte) 0x00});
    byte[] wrapped =
        concat(
            new byte[] {(byte) 0x30, (byte) malformedMultiElement.length}, malformedMultiElement);
    ResponseAPDU response = transmitKeyUpdate(ALG_AES_128, wrapped);
    assertSw(ISO7816.SW_WRONG_DATA, response, "Extra elements must be rejected");

    reconnectAndSelect();
    assertEquals(
        0x9000,
        authenticateCardManagementKeyResponse(ALG_AES_128, initialKey).getSW(),
        "Rejected multi-element payload must not update key material");
    assertEquals(
        0x6982,
        authenticateCardManagementKeyResponse(ALG_AES_128, candidateKey).getSW(),
        "Candidate key must not authenticate when payload was rejected");
  }

  @Test
  void managementKeyChangeClearsAuthenticatedSessionAfterSuccessfulRotation() {
    byte[] initialKey = keyMaterial(ALG_AES_128, (byte) 0x14);
    byte[] rotatedKey = keyMaterial(ALG_AES_128, (byte) 0x24);
    byte[] rotatedAgainKey = keyMaterial(ALG_AES_128, (byte) 0x34);

    provisionManagementKeyOverScp(ALG_AES_128, initialKey);
    authenticateCardManagementKey(ALG_AES_128, initialKey);
    assertSw(
        0x9000,
        transmitKeyUpdate(ALG_AES_128, keyUpdateData(rotatedKey)),
        "Initial authenticated rotation should succeed");

    // Rotation must clear key-authenticated state. A second rotation requires re-authentication.
    ResponseAPDU secondRotationWithoutAuth =
        transmitKeyUpdate(ALG_AES_128, keyUpdateData(rotatedAgainKey));
    assertSw(
        ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
        secondRotationWithoutAuth,
        "Authenticated key session must be cleared after successful key change");
  }

  @Test
  void failedExternalAuthenticateResponseCannotAuthorizeManagementKeyChange() {
    byte[] initialKey = keyMaterial(ALG_AES_128, (byte) 0x15);
    byte[] rotatedKey = keyMaterial(ALG_AES_128, (byte) 0x25);

    provisionManagementKeyOverScp(ALG_AES_128, initialKey);
    assertSw(0x9000, selectApplet(), "SELECT before failed external authenticate flow");

    ResponseAPDU challenge =
        transmit(0x00, 0x87, ALG_AES_128 & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, hex("7C028100"));
    assertSw(0x9000, challenge, "Challenge request should succeed");

    byte[] plaintextChallenge =
        extractChallenge(challenge.getData(), challengeLengthForAlgorithm(ALG_AES_128));
    byte[] encryptedChallenge =
        encryptManagementChallenge(ALG_AES_128, initialKey, plaintextChallenge);
    encryptedChallenge[0] ^= (byte) 0x01; // Deliberately corrupt one byte.

    byte[] badResponse =
        concat(
            new byte[] {
              (byte) 0x7C,
              (byte) (encryptedChallenge.length + 2),
              (byte) 0x82,
              (byte) encryptedChallenge.length
            },
            encryptedChallenge);
    ResponseAPDU authResponse =
        transmit(0x00, 0x87, ALG_AES_128 & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, badResponse);
    assertSw(
        ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
        authResponse,
        "Mismatched challenge response must not authenticate the management key");

    ResponseAPDU rotation = transmitKeyUpdate(ALG_AES_128, keyUpdateData(rotatedKey));
    assertSw(
        ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
        rotation,
        "Failed external authenticate must not grant authorization for management key update");
  }

  @Test
  void interveningCommandAbandonsExternalAuthenticateChallenge() {
    byte[] managementKey = keyMaterial(ALG_AES_128, (byte) 0x29);
    setLocalPinOverScp(hex("313233343536FFFF"));
    provisionManagementKeyOverScp(ALG_AES_128, managementKey);
    assertSw(0x9000, selectApplet(), "SELECT before interrupted authentication flow");

    ResponseAPDU challenge =
        transmit(0x00, 0x87, ALG_AES_128 & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, hex("7C028100"));
    assertSw(0x9000, challenge, "Challenge request should succeed");
    byte[] encryptedChallenge =
        encryptManagementChallenge(
            ALG_AES_128,
            managementKey,
            extractChallenge(challenge.getData(), challengeLengthForAlgorithm(ALG_AES_128)));

    assertSw(
        0x9000,
        transmit(0x00, 0x20, 0x00, 0x80, hex("313233343536FFFF")),
        "Intervening VERIFY should execute");

    byte[] response =
        concat(
            new byte[] {
              (byte) 0x7C,
              (byte) (encryptedChallenge.length + 2),
              (byte) 0x82,
              (byte) encryptedChallenge.length
            },
            encryptedChallenge);
    assertSw(
        ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
        transmit(0x00, 0x87, ALG_AES_128 & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, response),
        "The challenge must not survive an intervening command");
  }

  @ParameterizedTest(name = "PIV algorithm 0x{0} supports plaintext-authorized 9B rotation")
  @ValueSource(bytes = {0x03, 0x08, 0x0A, 0x0C})
  void pivAlgorithmIdentifierWorksForManagementKeyChange(byte algorithm) {
    if (algorithm == ALG_3DES) {
      Assumptions.assumeFalse(Boolean.getBoolean("fips.mode"), "TDEA is excluded from FIPS mode");
    }
    assertManagementKeyRotationWorksWithoutScp(algorithm);
  }

  /** Creates and rotates its own 9B key per algorithm, so the standard test card is not applied. */
  @Override
  protected boolean provisionsStandardCard() {
    return false;
  }

  private void assertManagementKeyRotationWorksWithoutScp(byte algorithm) {
    byte[] initialKey = keyMaterial(algorithm, (byte) (0x30 + (algorithm & 0x0F)));
    byte[] rotatedKey = keyMaterial(algorithm, (byte) (0x50 + (algorithm & 0x0F)));

    provisionManagementKeyOverScp(algorithm, initialKey);
    authenticateCardManagementKey(algorithm, initialKey);
    assertSw(
        0x9000,
        transmitKeyUpdate(algorithm, keyUpdateData(rotatedKey)),
        "PIV algorithm ID " + String.format("0x%02X", algorithm) + " should support 9B update");
  }

  private void reconnectAndSelect() {
    if (session != null) {
      session.close();
    }
    session = engine.connect();
    assertSw(0x9000, selectApplet(), "SELECT after reconnect");
  }

  private ResponseAPDU transmitPinAdminUpdateOverScp(int id, byte[] data) {
    return withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before SCP management key update");
          return transmit(0x84, 0x24, 0x01, id, data);
        });
  }

  private ResponseAPDU transmitPinAdminUpdate(int id, byte[] data) {
    return transmit(0x80, 0x24, 0x01, id, data);
  }

  private ResponseAPDU transmitKeyUpdate(byte algorithm, byte[] data) {
    return transmit(
        0x80, 0x25, 0x01, KEY_REF_CARD_MANAGEMENT & 0xFF, keyUpdateCommand(algorithm, data));
  }

  private static byte[] keyUpdateCommand(byte algorithm, byte[] data) {
    return concat(new byte[] {(byte) 0x80, (byte) 0x01, algorithm}, data);
  }

  protected static byte[] keyUpdateData(byte[] keyBytes) {
    return concat(
        new byte[] {(byte) 0x30, (byte) (keyBytes.length + 2), (byte) 0x80, (byte) keyBytes.length},
        keyBytes);
  }

  private static byte[] extractChallenge(byte[] responseData, int expectedLength) {
    assertEquals(
        4 + expectedLength,
        responseData.length,
        "Unexpected external authenticate response length");
    assertEquals(
        (byte) 0x7C,
        responseData[0],
        "Response must be wrapped in Dynamic Authentication Template (0x7C)");
    assertEquals(
        (byte) (responseData.length - 2),
        responseData[1],
        "Outer template length must match payload");
    assertEquals(
        (byte) 0x81,
        responseData[2],
        "External authenticate challenge response must include tag 0x81");
    assertEquals(
        (byte) expectedLength, responseData[3], "Challenge size must match algorithm block size");

    byte[] challenge = new byte[expectedLength];
    System.arraycopy(responseData, 4, challenge, 0, expectedLength);
    return challenge;
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
        throw new IllegalArgumentException(
            "Unsupported management key algorithm: " + String.format("0x%02X", algorithm));
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

  private static byte toOddParity(byte value) {
    int upperSevenBits = value & 0xFE;
    int ones = Integer.bitCount(upperSevenBits);
    return (byte) ((ones & 1) == 0 ? (upperSevenBits | 0x01) : upperSevenBits);
  }
}
