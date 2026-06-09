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
import javax.smartcardio.ResponseAPDU;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * SP 800-73-5 style coverage for PUT DATA operations that are unlocked by management-key
 * authentication (key reference 0x9B).
 *
 * <p>Scope of this suite:
 *
 * <ul>
 *   <li>Happy path for all supported PUT DATA object-reference forms (normal, biometric, discovery).
 *   <li>Happy path for object clear semantics (zero-length DATA element).
 *   <li>Negative path for each parser/access gate exercised by {@code PIV.putData()}.
 *   <li>Boundary check that administrative PUT DATA (P2=00) remains SCP-only.
 * </ul>
 */
@Timeout(value = 25, unit = TimeUnit.SECONDS)
class OpenFIPS201PutDataManagementKeyConformanceTest extends OpenFIPS201TestSupport {

  private static final byte ALG_AES_128 = (byte) 0x08;
  private static final byte KEY_REF_CARD_MANAGEMENT = (byte) 0x9B;

  private static final byte DATA_ID_NORMAL = (byte) 0x5A;
  private static final byte DATA_ID_BIOMETRIC_GROUP = (byte) 0x61;
  private static final byte DATA_ID_DISCOVERY = (byte) 0x7E;

  @Test
  void putDataNormalObjectUpdateSucceedsAfterManagementAuthentication() {
    byte[] managementKey = keyMaterialAes128((byte) 0x11);

    provisionManagementKeyOverScp(managementKey);
    createDataObjectOverScp(DATA_ID_NORMAL, KEY_REF_CARD_MANAGEMENT);
    authenticateManagementKey(managementKey);

    // PUT DATA for a standard object:
    // 5C 03 5F C1 <id>   (tag list)
    // 53 <len> <value>   (data object)
    byte[] objectBody = hex("5303A1A2A3");
    assertSw(
        0x9000,
        transmit(0x00, 0xDB, 0x3F, 0xFF, concat(normalTagList(DATA_ID_NORMAL), objectBody)),
        "9B-authenticated session should permit normal-object PUT DATA update");

    ResponseAPDU readBack = getDataNormal(DATA_ID_NORMAL);
    assertSw(0x9000, readBack, "GET DATA should succeed after successful PUT DATA update");
    assertArrayEquals(objectBody, readBack.getData(), "Object content should match replaced TLV payload");
  }

  @Test
  void putDataBiometricObjectUpdateSucceedsAfterManagementAuthentication() {
    byte[] managementKey = keyMaterialAes128((byte) 0x21);

    provisionManagementKeyOverScp(managementKey);
    createDataObjectOverScp(DATA_ID_BIOMETRIC_GROUP, KEY_REF_CARD_MANAGEMENT);
    authenticateManagementKey(managementKey);

    // Biometric group form is referenced by top-level tag 7F61.
    byte[] newBiometricGroupValue = hex("7F6103010203");
    assertSw(
        0x9000,
        transmit(0x00, 0xDB, 0x3F, 0xFF, newBiometricGroupValue),
        "9B-authenticated session should permit biometric-group PUT DATA update");

    ResponseAPDU readBack = getDataBiometricGroup();
    assertSw(0x9000, readBack, "GET DATA for biometric group should succeed after update");
    assertArrayEquals(
        newBiometricGroupValue, readBack.getData(), "Biometric-group object content should match replaced value");
  }

  @Test
  void putDataDiscoveryObjectUpdateSucceedsAfterManagementAuthentication() {
    byte[] managementKey = keyMaterialAes128((byte) 0x31);

    provisionManagementKeyOverScp(managementKey);
    createDataObjectOverScp(DATA_ID_DISCOVERY, KEY_REF_CARD_MANAGEMENT);
    authenticateManagementKey(managementKey);

    // Discovery object can be addressed directly as tag 7E for PUT DATA.
    assertSw(
        0x9000,
        transmit(0x00, 0xDB, 0x3F, 0xFF, hex("7E03010203")),
        "9B-authenticated session should permit discovery-object PUT DATA update");

    // Discovery reads are generated dynamically; we only assert command success and expected wrapper.
    ResponseAPDU discovery = getDataDiscovery();
    assertSw(0x9000, discovery, "GET DATA discovery should still succeed after PUT DATA");
    assertEquals((byte) 0x7E, discovery.getData()[0], "Discovery response should begin with discovery tag");
  }

  @Test
  void putDataClearObjectSucceedsAfterManagementAuthentication() {
    byte[] managementKey = keyMaterialAes128((byte) 0x41);

    provisionManagementKeyOverScp(managementKey);
    createDataObjectOverScp(DATA_ID_NORMAL, KEY_REF_CARD_MANAGEMENT);
    authenticateManagementKey(managementKey);

    // First write a value.
    assertSw(
        0x9000,
        transmit(0x00, 0xDB, 0x3F, 0xFF, hex("5C035FC15A5303010203")),
        "Initial PUT DATA update should succeed before clear test");
    assertSw(0x9000, getDataNormal(DATA_ID_NORMAL), "Object should be readable before clear");

    // Then clear by supplying zero-length 53 value.
    assertSw(
        0x9000,
        transmit(0x00, 0xDB, 0x3F, 0xFF, hex("5C035FC15A5300")),
        "PUT DATA with zero-length object should clear object content");

    // For an uninitialized object, this implementation returns FILE_NOT_FOUND by default.
    assertSw(ISO7816.SW_FILE_NOT_FOUND, getDataNormal(DATA_ID_NORMAL), "Cleared object should become uninitialized");
  }

  @Test
  void putDataIsRejectedWithoutManagementAuthentication() {
    byte[] managementKey = keyMaterialAes128((byte) 0x51);

    provisionManagementKeyOverScp(managementKey);
    createDataObjectOverScp(DATA_ID_NORMAL, KEY_REF_CARD_MANAGEMENT);
    assertSw(0x9000, selectApplet(), "SELECT before unauthenticated PUT DATA");

    ResponseAPDU response = transmit(0x00, 0xDB, 0x3F, 0xFF, hex("5C035FC15A530101"));
    assertSw(
        ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
        response,
        "PUT DATA should fail without SCP and without prior 9B authentication");
  }

  @Test
  void putDataIsRejectedWhenObjectUsesDifferentAdminKey() {
    byte[] managementKey = keyMaterialAes128((byte) 0x61);
    byte differentAdminKeyRef = (byte) 0x9A;

    provisionManagementKeyOverScp(managementKey);
    createDataObjectOverScp(DATA_ID_NORMAL, differentAdminKeyRef);
    authenticateManagementKey(managementKey);

    ResponseAPDU response = transmit(0x00, 0xDB, 0x3F, 0xFF, hex("5C035FC15A530101"));
    assertSw(
        ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
        response,
        "9B authentication must not satisfy PUT DATA for objects bound to a different admin key");
  }

  @Test
  void putDataRejectsUnknownNormalObjectReference() {
    byte[] managementKey = keyMaterialAes128((byte) 0x71);

    provisionManagementKeyOverScp(managementKey);
    authenticateManagementKey(managementKey);

    // Object 0x5B was not created in this test instance.
    ResponseAPDU response = transmit(0x00, 0xDB, 0x3F, 0xFF, hex("5C035FC15B530101"));
    assertSw(ISO7816.SW_FILE_NOT_FOUND, response, "PUT DATA should reject unknown normal object identifier");
  }

  @Test
  void putDataRejectsUnknownDiscoveryObjectReference() {
    byte[] managementKey = keyMaterialAes128((byte) 0x72);

    provisionManagementKeyOverScp(managementKey);
    authenticateManagementKey(managementKey);

    ResponseAPDU response = transmit(0x00, 0xDB, 0x3F, 0xFF, hex("7E0101"));
    assertSw(ISO7816.SW_FILE_NOT_FOUND, response, "PUT DATA should reject discovery write when object does not exist");
  }

  @Test
  void putDataRejectsMalformedTopLevelTagForTagListForm() {
    byte[] managementKey = keyMaterialAes128((byte) 0x73);

    provisionManagementKeyOverScp(managementKey);
    createDataObjectOverScp(DATA_ID_NORMAL, KEY_REF_CARD_MANAGEMENT);
    authenticateManagementKey(managementKey);

    ResponseAPDU response = transmit(0x00, 0xDB, 0x3F, 0xFF, hex("5D035FC15A530101"));
    assertSw(ISO7816.SW_WRONG_DATA, response, "PUT DATA should reject unknown top-level tag");
  }

  @Test
  void putDataRejectsMalformedNormalTagListLength() {
    byte[] managementKey = keyMaterialAes128((byte) 0x74);

    provisionManagementKeyOverScp(managementKey);
    createDataObjectOverScp(DATA_ID_NORMAL, KEY_REF_CARD_MANAGEMENT);
    authenticateManagementKey(managementKey);

    ResponseAPDU response = transmit(0x00, 0xDB, 0x3F, 0xFF, hex("5C025FC1"));
    assertSw(PIV_SW_REFERENCE_NOT_FOUND, response, "Normal-object PUT DATA requires 5C length=3");
  }

  @Test
  void putDataRejectsMalformedNormalTagListPrefixByteOne() {
    byte[] managementKey = keyMaterialAes128((byte) 0x75);

    provisionManagementKeyOverScp(managementKey);
    createDataObjectOverScp(DATA_ID_NORMAL, KEY_REF_CARD_MANAGEMENT);
    authenticateManagementKey(managementKey);

    ResponseAPDU response = transmit(0x00, 0xDB, 0x3F, 0xFF, hex("5C0300C15A530101"));
    assertSw(ISO7816.SW_FILE_NOT_FOUND, response, "Normal-object PUT DATA requires tag prefix byte 0x5F");
  }

  @Test
  void putDataRejectsMalformedNormalTagListPrefixByteTwo() {
    byte[] managementKey = keyMaterialAes128((byte) 0x76);

    provisionManagementKeyOverScp(managementKey);
    createDataObjectOverScp(DATA_ID_NORMAL, KEY_REF_CARD_MANAGEMENT);
    authenticateManagementKey(managementKey);

    ResponseAPDU response = transmit(0x00, 0xDB, 0x3F, 0xFF, hex("5C035F005A530101"));
    assertSw(ISO7816.SW_FILE_NOT_FOUND, response, "Normal-object PUT DATA requires tag prefix byte 0xC1");
  }

  @Test
  void putDataRejectsMissingDataTagForNormalObject() {
    byte[] managementKey = keyMaterialAes128((byte) 0x77);

    provisionManagementKeyOverScp(managementKey);
    createDataObjectOverScp(DATA_ID_NORMAL, KEY_REF_CARD_MANAGEMENT);
    authenticateManagementKey(managementKey);

    ResponseAPDU response = transmit(0x00, 0xDB, 0x3F, 0xFF, hex("5C035FC15A520101"));
    assertSw(ISO7816.SW_WRONG_DATA, response, "Normal-object PUT DATA requires DATA tag 0x53");
  }

  @Test
  void putDataRejectsMalformedBiometricReference() {
    byte[] managementKey = keyMaterialAes128((byte) 0x78);

    provisionManagementKeyOverScp(managementKey);
    authenticateManagementKey(managementKey);

    // For biometric addressing, tag 0x7F must be followed by 0x61.
    ResponseAPDU response = transmit(0x00, 0xDB, 0x3F, 0xFF, hex("7F620101"));
    assertSw(PIV_SW_REFERENCE_NOT_FOUND, response, "Biometric PUT DATA requires reference 7F61");
  }

  @Test
  void putDataRejectsWrongP1() {
    assertSw(0x9000, selectApplet(), "SELECT before PUT DATA P1 validation");
    ResponseAPDU response = transmit(0x00, 0xDB, 0x00, 0xFF, hex("5C035FC15A530101"));
    assertSw(ISO7816.SW_INCORRECT_P1P2, response, "PUT DATA requires P1=0x3F");
  }

  @Test
  void putDataRejectsWrongP2() {
    assertSw(0x9000, selectApplet(), "SELECT before PUT DATA P2 validation");
    ResponseAPDU response = transmit(0x00, 0xDB, 0x3F, 0xFE, hex("5C035FC15A530101"));
    assertSw(ISO7816.SW_INCORRECT_P1P2, response, "PUT DATA requires P2=0xFF (or 0x00 for admin path)");
  }

  @Test
  void putDataAdminPathStillRequiresSecureChannelAfterManagementAuthentication() {
    byte[] managementKey = keyMaterialAes128((byte) 0x79);
    provisionManagementKeyOverScp(managementKey);
    authenticateManagementKey(managementKey);

    // Even with 9B authenticated, P2=00 routes to administrative PUT DATA and must stay SCP-only.
    byte[] createObjectRequest =
        new byte[] {
          (byte) 0x64, (byte) 0x0C,
          (byte) 0x8B, (byte) 0x01, (byte) 0x5A,
          (byte) 0x8C, (byte) 0x01, (byte) 0x7F,
          (byte) 0x8D, (byte) 0x01, (byte) 0x7F,
          (byte) 0x91, (byte) 0x01, (byte) 0x9B
        };
    ResponseAPDU response = transmit(0x00, 0xDB, 0x3F, 0x00, createObjectRequest);
    assertSw(
        ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
        response,
        "Administrative PUT DATA remains SCP-gated");
  }

  @Test
  void putDataOverSecureChannelSucceedsWithoutManagementAuthentication() {
    byte[] managementKey = keyMaterialAes128((byte) 0x7A);

    provisionManagementKeyOverScp(managementKey);
    createDataObjectOverScp(DATA_ID_NORMAL, KEY_REF_CARD_MANAGEMENT);

    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before SCP PUT DATA");
            ResponseAPDU response =
                transmit(0x84, 0xDB, 0x3F, 0xFF, hex("5C035FC15A53030A0B0C"));
            assertSw(0x9000, response, "SCP should authorize PUT DATA without prior 9B authentication");
          }
        });
  }

  @Test
  void putDataSecureChannelAuthorizationIsNotStickyAcrossCommands() {
    byte[] managementKey = keyMaterialAes128((byte) 0x7B);

    provisionManagementKeyOverScp(managementKey);
    createDataObjectOverScp(DATA_ID_NORMAL, KEY_REF_CARD_MANAGEMENT);

    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before SCP PUT DATA");
            assertSw(
                0x9000,
                transmit(0x84, 0xDB, 0x3F, 0xFF, hex("5C035FC15A5303010203")),
                "SCP PUT DATA should succeed");
          }
        });

    // A subsequent plain command must not inherit SCP authorization.
    ResponseAPDU withoutScp = transmit(0x00, 0xDB, 0x3F, 0xFF, hex("5C035FC15A53030D0E0F"));
    assertSw(
        ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
        withoutScp,
        "Secure-channel administrative authorization must be command-scoped");
  }

  @Test
  void putDataRemainsBlockedAfterFailedGeneralAuthenticateResponse() {
    byte[] managementKey = keyMaterialAes128((byte) 0x7C);

    provisionManagementKeyOverScp(managementKey);
    createDataObjectOverScp(DATA_ID_NORMAL, KEY_REF_CARD_MANAGEMENT);
    assertSw(0x9000, selectApplet(), "SELECT before failed GENERAL AUTHENTICATE flow");

    ResponseAPDU challengeResponse =
        transmit(0x00, 0x87, ALG_AES_128 & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, hex("7C028100"));
    assertSw(0x9000, challengeResponse, "GENERAL AUTHENTICATE challenge request should succeed");

    byte[] challenge = extractChallenge(challengeResponse.getData(), 16);
    byte[] encryptedChallenge = encryptAesEcbNoPadding(managementKey, challenge);
    encryptedChallenge[0] ^= (byte) 0x01; // Corrupt response to force authentication failure.
    byte[] responseData =
        concat(
            new byte[] {(byte) 0x7C, (byte) (encryptedChallenge.length + 2), (byte) 0x82, (byte) encryptedChallenge.length},
            encryptedChallenge);
    ResponseAPDU verificationResponse =
        transmit(0x00, 0x87, ALG_AES_128 & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, responseData);
    assertSw(
        ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
        verificationResponse,
        "GENERAL AUTHENTICATE must fail for incorrect challenge response");

    ResponseAPDU putData = transmit(0x00, 0xDB, 0x3F, 0xFF, hex("5C035FC15A530101"));
    assertSw(
        ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
        putData,
        "Failed authentication must not grant PUT DATA authorization");
  }

  @Test
  void putDataAuthorizationIsClearedWhenExternalAuthenticateRestarts() {
    byte[] managementKey = keyMaterialAes128((byte) 0x7D);

    provisionManagementKeyOverScp(managementKey);
    createDataObjectOverScp(DATA_ID_NORMAL, KEY_REF_CARD_MANAGEMENT);
    authenticateManagementKey(managementKey);

    assertSw(
        0x9000,
        transmit(0x00, 0xDB, 0x3F, 0xFF, hex("5C035FC15A5303010203")),
        "PUT DATA should succeed while management key is authenticated");

    // Starting a new external-auth challenge resets the prior authenticated-key state.
    ResponseAPDU restart =
        transmit(0x00, 0x87, ALG_AES_128 & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, hex("7C028100"));
    assertSw(0x9000, restart, "Fresh challenge request should succeed");

    ResponseAPDU putDataAfterRestart = transmit(0x00, 0xDB, 0x3F, 0xFF, hex("5C035FC15A5303040506"));
    assertSw(
        ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
        putDataAfterRestart,
        "A restarted challenge flow must clear prior key-authenticated admin state");
  }

  private void provisionManagementKeyOverScp(byte[] keyBytes) {
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before SCP management-key provisioning");

            // 66 { 8B=id, 8C=mode contact, 8D=mode contactless, 8E=mechanism, 8F=role, 90=attrs }
            byte[] createManagementKeyObject =
                new byte[] {
                  (byte) 0x66, (byte) 0x12,
                  (byte) 0x8B, (byte) 0x01, KEY_REF_CARD_MANAGEMENT,
                  (byte) 0x8C, (byte) 0x01, (byte) 0x7F,
                  (byte) 0x8D, (byte) 0x01, (byte) 0x00,
                  (byte) 0x8E, (byte) 0x01, ALG_AES_128,
                  (byte) 0x8F, (byte) 0x01, (byte) 0x01,
                  (byte) 0x90, (byte) 0x01, (byte) 0x11
                };
            assertSw(
                0x9000,
                transmit(0x84, 0xDB, 0x3F, 0x00, createManagementKeyObject),
                "SCP create-key operation for 9B should succeed");

            // Inject initial key value under administrative CHANGE REFERENCE DATA.
            assertSw(
                0x9000,
                transmit(0x84, 0x24, ALG_AES_128 & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, keyUpdateData(keyBytes)),
                "SCP initial key import for 9B should succeed");
          }
        });
  }

  private void createDataObjectOverScp(final byte id, final byte adminKey) {
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before SCP data-object create");
            byte[] createObjectRequest =
                new byte[] {
                  (byte) 0x64, (byte) 0x0C,
                  (byte) 0x8B, (byte) 0x01, id,
                  (byte) 0x8C, (byte) 0x01, (byte) 0x7F,
                  (byte) 0x8D, (byte) 0x01, (byte) 0x7F,
                  (byte) 0x91, (byte) 0x01, adminKey
                };
            assertSw(
                0x9000,
                transmit(0x84, 0xDB, 0x3F, 0x00, createObjectRequest),
                "SCP create-object operation should succeed");
          }
        });
  }

  private void authenticateManagementKey(byte[] keyBytes) {
    assertSw(0x9000, selectApplet(), "SELECT before management-key GENERAL AUTHENTICATE");

    // Case 2 request for challenge (tag 0x81 with zero-length payload).
    ResponseAPDU challengeResponse =
        transmit(0x00, 0x87, ALG_AES_128 & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, hex("7C028100"));
    assertSw(0x9000, challengeResponse, "GENERAL AUTHENTICATE challenge request should succeed");

    byte[] challenge = extractChallenge(challengeResponse.getData(), 16);
    byte[] encryptedChallenge = encryptAesEcbNoPadding(keyBytes, challenge);

    byte[] responseData =
        concat(
            new byte[] {(byte) 0x7C, (byte) (encryptedChallenge.length + 2), (byte) 0x82, (byte) encryptedChallenge.length},
            encryptedChallenge);
    ResponseAPDU verificationResponse =
        transmit(0x00, 0x87, ALG_AES_128 & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, responseData);
    assertSw(0x9000, verificationResponse, "GENERAL AUTHENTICATE verification should succeed");
  }

  private ResponseAPDU getDataNormal(byte id) {
    return transmit(0x00, 0xCB, 0x3F, 0xFF, normalTagList(id));
  }

  private ResponseAPDU getDataBiometricGroup() {
    return transmit(0x00, 0xCB, 0x3F, 0xFF, hex("5C027F61"));
  }

  private ResponseAPDU getDataDiscovery() {
    return transmit(0x00, 0xCB, 0x3F, 0xFF, hex("5C017E"));
  }

  private static byte[] normalTagList(byte id) {
    return new byte[] {(byte) 0x5C, (byte) 0x03, (byte) 0x5F, (byte) 0xC1, id};
  }

  private static byte[] keyUpdateData(byte[] keyBytes) {
    return concat(new byte[] {(byte) 0x30, (byte) (keyBytes.length + 2), (byte) 0x80, (byte) keyBytes.length}, keyBytes);
  }

  private static byte[] keyMaterialAes128(byte seed) {
    byte[] key = new byte[16];
    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) (seed + i);
    }
    return key;
  }

  private static byte[] extractChallenge(byte[] responseData, int expectedLength) {
    assertEquals(4 + expectedLength, responseData.length, "Unexpected challenge response length");
    assertEquals((byte) 0x7C, responseData[0], "Response should be wrapped in 0x7C template");
    assertEquals((byte) 0x81, responseData[2], "Challenge response should contain tag 0x81");
    assertEquals((byte) expectedLength, responseData[3], "Challenge length should match algorithm block size");

    byte[] challenge = new byte[expectedLength];
    System.arraycopy(responseData, 4, challenge, 0, expectedLength);
    return challenge;
  }

  private static byte[] encryptAesEcbNoPadding(byte[] keyBytes, byte[] challenge) {
    try {
      Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"));
      return cipher.doFinal(challenge);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to encrypt challenge", e);
    }
  }

  private void withMockedScp(Runnable action) {
    try (MockedStatic<GPSystem> mockedGp = Mockito.mockStatic(GPSystem.class)) {
      SecureChannel secureChannel = Mockito.mock(SecureChannel.class);
      Mockito.when(secureChannel.getSecurityLevel())
          .thenReturn((byte) (SecureChannel.AUTHENTICATED | SecureChannel.C_DECRYPTION | SecureChannel.C_MAC));
      Mockito.when(secureChannel.unwrap(Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyShort()))
          .thenAnswer(invocation -> (short) invocation.getArgument(2));
      Mockito.when(GPSystem.getSecureChannel()).thenReturn(secureChannel);
      action.run();
    }
  }

  private static byte[] concat(byte[] prefix, byte[] suffix) {
    byte[] output = new byte[prefix.length + suffix.length];
    System.arraycopy(prefix, 0, output, 0, prefix.length);
    System.arraycopy(suffix, 0, output, prefix.length, suffix.length);
    return output;
  }

  // Local copy of PIV.SW_REFERENCE_NOT_FOUND (package-private in production code).
  private static final int PIV_SW_REFERENCE_NOT_FOUND = 0x6A88;
}
