package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.ResponseAPDU;
import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/** Regression coverage for symmetric GENERAL AUTHENTICATE behavior. */
@Timeout(value = 15, unit = TimeUnit.SECONDS)
class OpenFIPS201GeneralAuthenticateSymmetricTest extends OpenFIPS201TestSupport {

  private static final byte ALG_3DES = (byte) 0x03;
  private static final byte ALG_AES_128 = (byte) 0x08;
  private static final boolean FIPS_MODE = Boolean.getBoolean("fips.mode");
  private static final byte TEST_ALGORITHM = FIPS_MODE ? ALG_AES_128 : ALG_3DES;
  private static final byte KEY_REF_CARD_MANAGEMENT = (byte) 0x9B;
  private static final byte KEY_REF_SECURE_MESSAGING = (byte) 0x04;
  private static final byte ACTIVE_SM_ALGORITHM =
      (byte) ("CS7".equalsIgnoreCase(System.getProperty("vci.suite", "CS2")) ? 0x2E : 0x27);

  /** Provisions its own 3DES 9B key, so the standard (AES-128) test card is not applied. */
  @Override
  protected boolean provisionsStandardCard() {
    return false;
  }

  @Test
  void externalAuthenticateChallengeSucceedsForProvisioned3desManagementKey() {
    provisionManagementKeyOverScp(keyMaterial((byte) 0x41), (byte) 0x14);

    assertSw(0x9000, selectApplet(), "SELECT before 3DES GENERAL AUTHENTICATE");

    // Case 2: external authenticate challenge request (7C {81 00})
    ResponseAPDU response =
        transmit(
            0x00, 0x87, TEST_ALGORITHM & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, hex("7C028100"));
    assertSw(0x9000, response, "GENERAL AUTHENTICATE challenge request should succeed");

    byte[] data = response.getData();
    assertEquals(
        (FIPS_MODE ? 20 : 12), data.length, "Challenge response must contain one cipher block");
    assertEquals((byte) 0x7C, data[0], "Response should use dynamic authentication template");
    assertEquals((byte) 0x81, data[2], "Response should contain challenge tag 0x81");
    assertEquals((byte) (FIPS_MODE ? 16 : 8), data[3], "Challenge length must match the cipher");
  }

  @Test
  void externalAuthenticateRequiresPermitAttribute() {
    provisionManagementKeyOverScp(keyMaterial((byte) 0x41), (byte) 0x10);

    assertSw(0x9000, selectApplet(), "SELECT before denied GENERAL AUTHENTICATE");
    assertSw(
        0x6982,
        transmit(
            0x00, 0x87, TEST_ALGORITHM & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, hex("7C028100")),
        "GENERAL AUTHENTICATE must require ATTR_PERMIT_EXTERNAL");
  }

  @Test
  void mutualAuthenticateCompletesWitnessAndChallengeExchange() throws Exception {
    // SP 800-73-5 Part 2, Section 3.2.4 and Appendix A.2 define the
    // two-command witness/challenge exchange exercised here.
    byte[] key = keyMaterial((byte) 0x61);
    provisionManagementKeyOverScp(key, (byte) 0x18);
    assertSw(0x9000, selectApplet(), "SELECT before mutual authentication");

    ResponseAPDU witnessResponse =
        transmit(
            0x00, 0x87, TEST_ALGORITHM & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, hex("7C028000"));
    assertSw(0x9000, witnessResponse, "Mutual authentication witness request");

    byte[] encodedWitness = witnessResponse.getData();
    int blockLength = FIPS_MODE ? 16 : 8;
    byte[] encryptedWitness = Arrays.copyOfRange(encodedWitness, 4, 4 + blockLength);
    byte[] witness = crypt(Cipher.DECRYPT_MODE, key, encryptedWitness);
    byte[] hostChallenge = new byte[blockLength];
    Arrays.fill(hostChallenge, (byte) 0x5A);

    ResponseAPDU challengeResponse =
        transmit(
            0x00,
            0x87,
            TEST_ALGORITHM & 0xFF,
            KEY_REF_CARD_MANAGEMENT & 0xFF,
            concat(
                new byte[] {
                  (byte) 0x7C, (byte) (4 + 2 * blockLength), (byte) 0x80, (byte) blockLength
                },
                witness,
                new byte[] {(byte) 0x81, (byte) blockLength},
                hostChallenge));
    assertSw(0x9000, challengeResponse, "Mutual authentication challenge response");

    byte[] encodedChallenge = challengeResponse.getData();
    byte[] encryptedChallenge = Arrays.copyOfRange(encodedChallenge, 4, 4 + blockLength);
    assertArrayEquals(
        hostChallenge,
        crypt(Cipher.DECRYPT_MODE, key, encryptedChallenge),
        "Card response must encrypt the host challenge with the authenticated key");
  }

  @Test
  void emptyWitnessTakesPrecedenceWhenChallengeIsAlsoEmpty() {
    provisionManagementKeyOverScp(keyMaterial((byte) 0x61), (byte) 0x1C);
    assertSw(0x9000, selectApplet(), "SELECT before mutual-authentication routing test");

    ResponseAPDU response =
        transmit(
            0x00, 0x87, TEST_ALGORITHM & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, hex("7C0480008100"));

    assertSw(0x9000, response, "An empty Witness selects SP 800-73-5 Part 2 Case 4");
    assertEquals((byte) 0x80, response.getData()[2], "Mutual authentication returns a Witness");
  }

  @Test
  void missingDynamicAuthenticationTemplateReturns6A80() {
    provisionManagementKeyOverScp(keyMaterial((byte) 0x41), (byte) 0x14);

    assertSw(0x9000, selectApplet(), "SELECT before malformed GENERAL AUTHENTICATE");
    assertSw(
        0x6A80,
        transmit(0x00, 0x87, TEST_ALGORITHM & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, hex("5300")),
        "GENERAL AUTHENTICATE requires the dynamic authentication template");
  }

  /** SP 800-73-5 Part 2 Section 3.2.4 binds algorithm 27/2E exclusively to key reference 04. */
  @Test
  void secureMessagingAlgorithmAndKeyReferenceMustBeUsedTogether() {
    assertSw(0x9000, selectApplet(), "SELECT before SM key-reference validation");

    assertSw(
        0x6A86,
        transmit(
            0x00, 0x87, TEST_ALGORITHM & 0xFF, KEY_REF_SECURE_MESSAGING & 0xFF, hex("7C028100")),
        "Key reference 04 must reject a non-SM mechanism");
    assertSw(
        0x6A86,
        transmit(
            0x00,
            0x87,
            ACTIVE_SM_ALGORITHM & 0xFF,
            KEY_REF_CARD_MANAGEMENT & 0xFF,
            hex("7C028100")),
        "An SM mechanism must reject a non-04 key reference");
  }

  /** SP 800-73-5 Part 2 Section 3.2.4 requires 6A86 for an unsupported key reference. */
  @Test
  void unsupportedKeyReferenceReturns6A86() {
    assertSw(0x9000, selectApplet(), "SELECT before unsupported-key validation");
    assertSw(
        0x6A86,
        transmit(0x00, 0x87, TEST_ALGORITHM & 0xFF, 0x01, hex("7C028100")),
        "GENERAL AUTHENTICATE must reject an unsupported P2 with 6A86");
  }

  /**
   * SP 800-73-5 Part 2 Section 3.2.4 permits GENERAL AUTHENTICATE only with available reference
   * data. A declared key object without imported key material is not operational.
   */
  @Test
  void uninitialisedKeyReturnsIncorrectP1P2() {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before creating an empty key object");
          assertSw(
              0x9000,
              transmit(0x84, 0xDB, 0xFF, 0xFF, managementKeyDefinition((byte) 0x14)),
              "Create management key without importing its value");
        });

    assertSw(0x9000, selectApplet(), "SELECT before using an empty key object");
    assertSw(
        0x6A86,
        transmit(
            0x00, 0x87, TEST_ALGORITHM & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, hex("7C028100")),
        "An uninitialised key must not enter an authentication exchange");
  }

  /** SP 800-73-5 Part 2 Section 3.2.4 requires a recognized authentication-template case. */
  @Test
  void emptyOrUnrecognizedAuthenticationTemplateReturns6A80() {
    provisionManagementKeyOverScp(keyMaterial((byte) 0x41), (byte) 0x14);
    assertSw(0x9000, selectApplet(), "SELECT before invalid-template cases");

    assertSw(
        0x6A80,
        transmit(0x00, 0x87, TEST_ALGORITHM & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, hex("7C00")),
        "An empty Dynamic Authentication Template selects no valid operation");
    assertSw(
        0x6A80,
        transmit(
            0x00, 0x87, TEST_ALGORITHM & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, hex("7C028500")),
        "An unknown element alone selects no valid operation");
  }

  /**
   * SP 800-73-5 Part 2 Section 3.2.4 and Appendix A.2 require the external-authentication response
   * to immediately follow its challenge request and occupy exactly one cipher block.
   */
  @Test
  void externalAuthenticateResponseRequiresStateAndExactBlockLength() {
    provisionManagementKeyOverScp(keyMaterial((byte) 0x41), (byte) 0x14);
    assertSw(0x9000, selectApplet(), "SELECT before external-authentication negative cases");

    assertSw(
        0x6982,
        transmit(
            0x00,
            0x87,
            TEST_ALGORITHM & 0xFF,
            KEY_REF_CARD_MANAGEMENT & 0xFF,
            tlv((byte) 0x7C, tlv((byte) 0x82, new byte[FIPS_MODE ? 16 : 8]))),
        "A response without a preceding challenge request must fail");

    assertSw(
        0x9000,
        transmit(
            0x00, 0x87, TEST_ALGORITHM & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, hex("7C028100")),
        "External-authentication challenge request");
    assertSw(
        0x6A80,
        transmit(
            0x00,
            0x87,
            TEST_ALGORITHM & 0xFF,
            KEY_REF_CARD_MANAGEMENT & 0xFF,
            tlv((byte) 0x7C, tlv((byte) 0x82, new byte[(FIPS_MODE ? 16 : 8) - 1]))),
        "External-authentication response must occupy exactly one cipher block");
  }

  /** SP 800-73-5 Part 2 Section 3.2.4 requires explicit authorization for mutual authentication. */
  @Test
  void mutualAuthenticateRequiresPermitAttribute() {
    provisionManagementKeyOverScp(keyMaterial((byte) 0x41), (byte) 0x14);
    assertSw(0x9000, selectApplet(), "SELECT before denied mutual authentication");
    assertSw(
        0x6982,
        transmit(
            0x00, 0x87, TEST_ALGORITHM & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, hex("7C028000")),
        "GENERAL AUTHENTICATE must require ATTR_PERMIT_MUTUAL");
  }

  /**
   * SP 800-73-5 Part 2 Section 3.2.4 and Appendix A.2 require an immediately preceding witness
   * request, equal one-block witness and challenge values, and an exact witness match.
   */
  @Test
  void mutualAuthenticateResponseRejectsInvalidStateLengthsAndWitness() {
    int blockLength = FIPS_MODE ? 16 : 8;
    byte[] block = new byte[blockLength];
    provisionManagementKeyOverScp(keyMaterial((byte) 0x61), (byte) 0x18);
    assertSw(0x9000, selectApplet(), "SELECT before mutual-authentication negative cases");

    assertSw(
        0x6982,
        transmit(
            0x00,
            0x87,
            TEST_ALGORITHM & 0xFF,
            KEY_REF_CARD_MANAGEMENT & 0xFF,
            mutualResponse(block, block)),
        "A mutual response without a preceding witness request must fail");

    requestWitness();
    assertSw(
        0x6A80,
        transmit(
            0x00,
            0x87,
            TEST_ALGORITHM & 0xFF,
            KEY_REF_CARD_MANAGEMENT & 0xFF,
            mutualResponse(new byte[blockLength - 1], new byte[blockLength - 1])),
        "Witness must occupy exactly one cipher block");

    requestWitness();
    assertSw(
        0x6A80,
        transmit(
            0x00,
            0x87,
            TEST_ALGORITHM & 0xFF,
            KEY_REF_CARD_MANAGEMENT & 0xFF,
            mutualResponse(block, new byte[blockLength - 1])),
        "Challenge length must equal witness length");

    requestWitness();
    assertSw(
        0x6982,
        transmit(
            0x00,
            0x87,
            TEST_ALGORITHM & 0xFF,
            KEY_REF_CARD_MANAGEMENT & 0xFF,
            mutualResponse(block, block)),
        "A witness that does not match the card challenge must fail");
  }

  @Test
  void unrelatedCommandAbortsIncompleteGeneralAuthenticateChain() {
    setLocalPinOverScp(hex("313233343536FFFF"));
    provisionManagementKeyOverScp(keyMaterial((byte) 0x51), (byte) 0x14);
    assertSw(0x9000, selectApplet(), "SELECT before chained GENERAL AUTHENTICATE");

    assertSw(
        0x9000,
        transmit(0x10, 0x87, TEST_ALGORITHM & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, hex("7C02")),
        "First GENERAL AUTHENTICATE chain segment");
    assertSw(
        0x9000,
        transmit(0x00, 0x20, 0x00, 0x80, hex("313233343536FFFF")),
        "VERIFY must execute after abandoning the authentication chain");

    assertSw(
        0x6A80,
        transmit(0x00, 0x87, TEST_ALGORITHM & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, hex("8100")),
        "The abandoned authentication fragment must not survive");

    assertSw(
        0x9000,
        transmit(
            0x00, 0x87, TEST_ALGORITHM & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, hex("7C028100")),
        "The applet must accept a fresh authentication command");
  }

  private void provisionManagementKeyOverScp(byte[] keyBytes, byte attributes) {
    try (MockedStatic<GPSystem> mockedGp = Mockito.mockStatic(GPSystem.class)) {
      Mockito.when(GPSystem.getCardContentState()).thenReturn(GPSystem.APPLICATION_SELECTABLE);
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

      assertSw(0x9000, selectApplet(), "SELECT before SCP provisioning flow");

      // 66 { 8B=id, 8C=mode contact, 8D=mode contactless, 8E=mechanism, 8F=role, 90=attrs }
      byte[] createManagementKeyObject = managementKeyDefinition(attributes);

      assertSw(
          0x9000,
          transmit(0x84, 0xDB, 0xFF, 0xFF, createManagementKeyObject),
          "SCP create-key operation for 9B should succeed");
      assertSw(
          0x9000,
          transmit(
              0x84,
              0x25,
              0x01,
              KEY_REF_CARD_MANAGEMENT & 0xFF,
              concat(
                  new byte[] {(byte) 0x80, (byte) 0x01, TEST_ALGORITHM}, keyUpdateData(keyBytes))),
          "SCP initial key import for 9B should succeed");
    }
  }

  private ResponseAPDU requestWitness() {
    ResponseAPDU response =
        transmit(
            0x00, 0x87, TEST_ALGORITHM & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, hex("7C028000"));
    assertSw(0x9000, response, "Mutual-authentication witness request");
    return response;
  }

  private static byte[] mutualResponse(byte[] witness, byte[] challenge) {
    return tlv((byte) 0x7C, concat(tlv((byte) 0x80, witness), tlv((byte) 0x81, challenge)));
  }

  private static byte[] managementKeyDefinition(byte attributes) {
    return new byte[] {
      (byte) 0x66,
      (byte) 0x12,
      (byte) 0x8B,
      (byte) 0x01,
      KEY_REF_CARD_MANAGEMENT,
      (byte) 0x8C,
      (byte) 0x01,
      (byte) 0x7F,
      (byte) 0x8D,
      (byte) 0x01,
      (byte) 0x00,
      (byte) 0x8E,
      (byte) 0x01,
      TEST_ALGORITHM,
      (byte) 0x8F,
      (byte) 0x01,
      (byte) 0x01,
      (byte) 0x90,
      (byte) 0x01,
      attributes
    };
  }

  protected static byte[] keyUpdateData(byte[] keyBytes) {
    return concat(
        new byte[] {(byte) 0x30, (byte) (keyBytes.length + 2), (byte) 0x80, (byte) keyBytes.length},
        keyBytes);
  }

  private static byte[] keyMaterial3des(byte seed) {
    byte[] key = new byte[24];
    for (int i = 0; i < key.length; i++) {
      key[i] = toOddParity((byte) (seed + i));
    }
    return key;
  }

  private static byte[] keyMaterial(byte seed) {
    if (!FIPS_MODE) return keyMaterial3des(seed);
    byte[] key = new byte[16];
    for (int i = 0; i < key.length; i++) key[i] = (byte) (seed + i);
    return key;
  }

  private static byte[] crypt(int mode, byte[] key, byte[] input) throws Exception {
    String algorithm = FIPS_MODE ? "AES" : "DESede";
    Cipher cipher = Cipher.getInstance(algorithm + "/ECB/NoPadding");
    cipher.init(mode, new SecretKeySpec(key, algorithm));
    return cipher.doFinal(input);
  }

  private static byte toOddParity(byte value) {
    int upperSevenBits = value & 0xFE;
    int ones = Integer.bitCount(upperSevenBits);
    return (byte) ((ones & 1) == 0 ? (upperSevenBits | 0x01) : upperSevenBits);
  }
}
