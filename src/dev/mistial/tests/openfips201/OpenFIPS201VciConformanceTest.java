package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Test;

/**
 * Conformance tests for Virtual Contact Interface (VCI) behavior.
 *
 * <p>NIST SP 800-73-5 Part 1 Section 5.5 defines VCI, Section 3.3.2 defines Discovery Object policy
 * bits, and Appendix C.3 defines APT secure-messaging algorithm advertisement.
 */
class OpenFIPS201VciConformanceTest extends OpenFIPS201TestSupport {
  private static final byte ACCESS_MODE_NEVER = (byte) 0x00;
  private static final byte ACCESS_MODE_PIN = (byte) 0x01;
  private static final byte ACCESS_MODE_OCC = (byte) 0x04;
  private static final byte ACCESS_MODE_VCI = (byte) 0x08;
  private static final byte ACCESS_MODE_ALWAYS = (byte) 0x7F;
  private static final byte KEY_REF_SECURE_MESSAGING = (byte) 0x04;
  private static final byte ALG_CS2 = (byte) 0x27;
  private static final byte ALG_CS7 = (byte) 0x2E;
  private static final byte ROLE_KEY_ESTABLISH = (byte) 0x02;
  private static final byte ATTR_NONE = (byte) 0x00;
  private static final byte ATTR_IMPORTABLE = (byte) 0x10;

  /** Verifies that invalid VCI modes are rejected. */
  @Test
  void invalidVciModeIsRejectedByConfiguration() {
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before VCI config update");
            ResponseAPDU response = transmit(0x84, 0xDB, 0xFF, 0xFF, hex("68 05 A2 03 80 01 03"));
            assertSw(0x6A80, response, "VCI mode must be disabled, enabled, or pairing-code");
          }
        });
  }

  @Test
  void occConfigurationAndAccessRulesAreRejectedUntilOccIsImplemented() {
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before OCC config update");
            ResponseAPDU config = transmit(0x84, 0xDB, 0xFF, 0xFF, hex("68 05 A3 03 80 01 01"));
            assertSw(0x6A81, config, "OCC configuration must remain unsupported");

            byte[] objectWithOcc =
                tlv(
                    (byte) 0x64,
                    new byte[] {
                      (byte) 0x8B,
                      (byte) 0x01,
                      (byte) 0x5A,
                      (byte) 0x8C,
                      (byte) 0x01,
                      ACCESS_MODE_PIN,
                      (byte) 0x8D,
                      (byte) 0x01,
                      ACCESS_MODE_OCC,
                      (byte) 0x91,
                      (byte) 0x01,
                      (byte) 0x9B,
                      (byte) 0x92,
                      (byte) 0x02,
                      (byte) 0x00,
                      (byte) 0x0E
                    });
            ResponseAPDU object = transmit(0x84, 0xDB, 0xFF, 0xFF, objectWithOcc);
            assertSw(0x6A81, object, "OCC-bearing ACLs are unsupported until OCC CVM exists");
          }
        });
  }

  /**
   * Verifies that the Discovery Object correctly advertises VCI capability and its pairing policy.
   *
   * <p>NIST SP 800-73-5 Part 1 Section 3.3.2/Table 1: PIN Usage Policy bit 4 indicates VCI support;
   * bit 3 selects pairing-required (0) or no-pairing (1) VCI.
   */
  @Test
  void discoveryObjectRequiresIssuerPolicyBeforeAdvertisingVci() {
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before VCI pairing-required config");
            assertSw(
                0x9000,
                transmit(0x84, 0xDB, 0xFF, 0xFF, hex("68 05 A2 03 80 01 02")),
                "Enable VCI with pairing code");
            createDiscoveryObject();
          }
        });

    ResponseAPDU pairingRequired = transmit(0x00, 0xCB, 0x3F, 0xFF, hex("5C017E"));
    assertSw(0x9000, pairingRequired, "Read Discovery Object with VCI pairing-required");
    byte[] pairingPolicy = policyBytes(pairingRequired.getData());
    assertFalse(
        (pairingPolicy[0] & 0x08) != 0,
        "Discovery Object must not advertise VCI before SM key/CVC and pairing data are ready");

    createOperationalVciKey();

    pairingRequired = transmit(0x00, 0xCB, 0x3F, 0xFF, hex("5C017E"));
    assertSw(0x9000, pairingRequired, "Read Discovery Object after SM key provisioning");
    pairingPolicy = policyBytes(pairingRequired.getData());
    assertFalse(
        (pairingPolicy[0] & 0x08) != 0,
        "Pairing-required VCI must not advertise before pairing reference data exists");

    createPairingCodeReferenceData();

    pairingRequired = transmit(0x00, 0xCB, 0x3F, 0xFF, hex("5C017E"));
    assertSw(0x9000, pairingRequired, "Read unstored Discovery fallback after VCI setup");
    pairingPolicy = policyBytes(pairingRequired.getData());
    assertFalse(
        (pairingPolicy[0] & 0x08) != 0,
        "Unstored Discovery must not advertise an issuer policy protected by the Security Object");

    withMockedScp(
        () ->
            assertSw(
                0x9000,
                transmit(0x84, 0xDB, 0x3F, 0xFF, hex("7E124F0BA0000003080000100001005F2F024800")),
                "Store pairing-required Discovery policy"));

    pairingRequired = transmit(0x00, 0xCB, 0x3F, 0xFF, hex("5C017E"));
    pairingPolicy = policyBytes(pairingRequired.getData());
    assertTrue((pairingPolicy[0] & 0x08) != 0, "Stored Discovery must set VCI implemented bit");
    assertFalse((pairingPolicy[0] & 0x04) != 0, "Pairing-required VCI must clear no-pairing bit");

    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(
                0x9000,
                transmit(0x84, 0xDB, 0xFF, 0xFF, hex("68 05 A2 03 80 01 01")),
                "Enable VCI without pairing code");
            assertSw(
                0x9000,
                transmit(0x84, 0xDB, 0x3F, 0xFF, hex("7E124F0BA0000003080000100001005F2F024C00")),
                "Store no-pairing Discovery policy");
          }
        });

    ResponseAPDU noPairing = transmit(0x00, 0xCB, 0x3F, 0xFF, hex("5C017E"));
    assertSw(0x9000, noPairing, "Read Discovery Object with VCI no-pairing");
    byte[] noPairingPolicy = policyBytes(noPairing.getData());
    assertTrue((noPairingPolicy[0] & 0x08) != 0, "Discovery Object must keep VCI implemented bit");
    assertTrue((noPairingPolicy[0] & 0x04) != 0, "No-pairing VCI must set no-pairing bit");
  }

  /**
   * Verifies that the Application Property Template (APT) advertises CS2 only after key material
   * and CVC are loaded.
   *
   * <p>NIST SP 800-73-5 Part 1 Appendix C.3: APT tag 'AC' advertises secure messaging algorithm
   * identifiers; '27' means CS2 is supported and the card has the matching PIV Secure Messaging
   * key.
   */
  @Test
  void applicationPropertyTemplateAdvertisesConfiguredSuiteOnlyAfterKeyMaterialAndCvc() {
    byte[] advertisement = new byte[] {(byte) 0x80, (byte) 0x01, activeAlgorithm()};
    assertSw(0x9000, selectApplet(), "Initial SELECT");
    assertFalse(
        contains(selectAppletWithData().getData(), advertisement),
        "APT must not advertise secure messaging by default");

    configureVciMode((byte) 0x02);
    createVciKeyOverScp(ATTR_NONE);
    generateVciKeyOverScp();
    assertFalse(
        contains(selectAppletWithData().getData(), advertisement),
        "APT requires CVC as well as key material");

    loadVciCvcOverScp(hex("7F2181100102030405060708090A0B0C0D0E0F10"));
    assertTrue(
        contains(selectAppletWithData().getData(), advertisement),
        "APT must advertise the configured suite after key and CVC");
  }

  /**
   * SP 800-73-5 Part 2 Section 3.1.1: "Tag 0xAC SHALL be present and indicate algorithm identifier
   * 0x27 or 0x2E (but not both) when the PIV Card Application supports secure messaging." Key 04
   * with its CVC establishes secure messaging whether or not VCI is configured, so the APT
   * advertises the suite in both configurations.
   */
  @Test
  void applicationPropertyTemplateAdvertisesSecureMessagingWithoutVci() {
    byte[] advertisement = new byte[] {(byte) 0x80, (byte) 0x01, activeAlgorithm()};
    createVciKeyOverScp(ATTR_NONE);
    generateVciKeyOverScp();
    loadVciCvcOverScp(hex("7F210401020304"));

    assertTrue(
        contains(selectAppletWithData().getData(), advertisement),
        "APT must advertise the suite whenever secure messaging is available");
  }

  /**
   * Verifies that a non-importable VCI key accepts CVC loading but rejects private key import.
   *
   * <p>Aligned with NIST SP 800-73-5 Part 2, Section 3.2.1 Table 2 & Section 4.1.8. Administrative
   * key references check access modes, allowing post-generation CVC loading to the VCI key slot.
   */
  @Test
  void nonImportableVciKeyAcceptsCvcButRejectsPrivateKeyImport() {
    configureVciMode((byte) 0x02);
    createVciKeyOverScp(ATTR_NONE);

    loadVciCvcOverScp(hex("7F210401020304"));
    ResponseAPDU privateImport =
        changeVciReferenceDataOverScp(
            tlv((byte) 0x30, tlv((byte) 0x87, fixed((byte) 0x44, activeScalarOne().length))));
    assertSw(0x6982, privateImport, "Generated non-importable VCI key must reject private import");
  }

  /**
   * Verifies that an imported VCI key requires its CVC to be loaded before APT advertisement.
   *
   * <p>NIST SP 800-73-5 Part 1 Appendix C.3 requires a PIV Secure Messaging key before APT
   * secure-messaging algorithm advertisement.
   */
  @Test
  void importableVciKeyDefinitionIsRejected() {
    configureVciMode((byte) 0x01);
    assertSw(
        0x6A80,
        createVciKeyOverScpForResponse(ATTR_IMPORTABLE, activeAlgorithm()),
        "SP 800-73-5 Part 1 Section 5.1.2 requires key 04 generation on-card");
  }

  @Test
  void configuredBuildRejectsOtherSecureMessagingKeyDefinition() {
    configureVciMode((byte) 0x02);
    ResponseAPDU response = createVciKeyOverScpForResponse(ATTR_NONE, inactiveAlgorithm());
    assertEquals(0x6A81, response.getSW(), "Build must reject the other SM suite definition");
    assertFalse(
        contains(
            selectAppletWithData().getData(),
            new byte[] {(byte) 0x80, (byte) 0x01, inactiveAlgorithm()}),
        "APT must not advertise the other suite");
  }

  @Test
  void configuredBuildDoesNotAllowBothSecureMessagingSuites() {
    configureVciMode((byte) 0x02);
    createVciKeyOverScp(ATTR_NONE, activeAlgorithm());

    ResponseAPDU secondSuite = createVciKeyOverScpForResponse(ATTR_NONE, inactiveAlgorithm());
    assertEquals(0x6A81, secondSuite.getSW(), "Card must not accept both SM suites");
  }

  /**
   * SP 800-73-5 Part 2 Section 4.1 reserves key 04 for OPACITY establishment. Tag 85 is the generic
   * key-management ECDH form and must never expose key 04's shared secret.
   */
  @Test
  void secureMessagingKeyRejectsGenericEcdh() {
    configureVciMode((byte) 0x02);
    createOperationalVciKey();

    ResponseAPDU response =
        transmit(
            0x00,
            0x87,
            activeAlgorithm() & 0xFF,
            KEY_REF_SECURE_MESSAGING & 0xFF,
            tlv((byte) 0x7C, tlv((byte) 0x85, activeBasePoint())));

    assertSw(0x6A86, response, "Key 04 must reject generic ECDH exponentiation");
  }

  /**
   * SP 800-73-5 Part 2 Table 16: C2 "CB_ICC = CB_H & 'F0'" and C3 "Return an error ('6A 80') if
   * CB_ICC is not 0x00". Section 4.1.6 carries the received CB_H in OtherInfo ("0x01 || CB_H") and
   * CB_ICC at its end. The card's cryptogram is recomputed host-side from independent ECDH, KDF and
   * CMAC so a CB_H that does not reach the KDF fails the comparison. Step C11 response lengths use
   * the shortest BER-TLV form (ISO/IEC 7816-4 Section 6.3).
   */
  @Test
  void opacityMasksHostControlByteAndBindsItIntoTheKdf() throws Exception {
    configureVciMode((byte) 0x02);
    createVciKeyOverScp(ATTR_NONE);
    byte[] cardPoint = generateVciKeyOverScpReturningPoint();
    byte[] cvc = hex("7F210401020304");
    loadVciCvcOverScp(cvc);

    for (byte hostControlByte : new byte[] {0x00, 0x01, 0x0F}) {
      java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("EC");
      generator.initialize(
          new java.security.spec.ECGenParameterSpec(isCs2Build() ? "secp256r1" : "secp384r1"));
      java.security.KeyPair host = generator.generateKeyPair();
      byte[] hostPoint = uncompressedPoint((java.security.interfaces.ECPublicKey) host.getPublic());
      byte[] hostId = hex("0102030405060708");

      byte[] data =
          collectResponse(
              transmit(
                  0x00,
                  0x87,
                  activeAlgorithm() & 0xFF,
                  KEY_REF_SECURE_MESSAGING & 0xFF,
                  tlv(
                      (byte) 0x7C,
                      concat(
                          tlv((byte) 0x81, concat(new byte[] {hostControlByte}, hostId, hostPoint)),
                          hex("8200"))),
                  256),
              "OPACITY with CB_H " + hostControlByte);

      int fieldLength = isCs2Build() ? 32 : 48;
      int nonceLength = fieldLength / 2;
      int responseLength = 1 + nonceLength + 16 + cvc.length;
      assertArrayEquals(
          concat(
              new byte[] {(byte) 0x7C, (byte) (responseLength + 2)},
              new byte[] {(byte) 0x82, (byte) responseLength}),
          java.util.Arrays.copyOf(data, 4),
          "OPACITY response lengths must use the shortest encoding");
      byte[] value = tlvValue(data, (byte) 0x82);
      assertEquals(0x00, value[0], "CB_ICC = CB_H & 'F0' = 0x00");
      byte[] nonce = java.util.Arrays.copyOfRange(value, 1, 1 + nonceLength);
      byte[] cryptogram = java.util.Arrays.copyOfRange(value, 1 + nonceLength, 17 + nonceLength);
      assertArrayEquals(
          cvc, java.util.Arrays.copyOfRange(value, 17 + nonceLength, value.length), "C_ICC");

      javax.crypto.KeyAgreement agreement = javax.crypto.KeyAgreement.getInstance("ECDH");
      agreement.init(host.getPrivate());
      agreement.doPhase(cardPublicKey(cardPoint, host.getPublic()), true);
      byte[] z = agreement.generateSecret();
      byte[] cardId =
          java.util.Arrays.copyOf(
              java.security.MessageDigest.getInstance("SHA-256").digest(cvc), 8);
      int keyLength = isCs2Build() ? 16 : 32;
      byte[] otherInfo =
          concat(
              new byte[] {0x04},
              fixed(activeKdfAlgorithmId(), 4),
              new byte[] {0x08},
              hostId,
              new byte[] {0x01, hostControlByte, 0x10},
              java.util.Arrays.copyOfRange(hostPoint, 1, 17),
              new byte[] {0x08},
              cardId,
              new byte[] {(byte) nonceLength},
              nonce,
              new byte[] {0x01, 0x00});
      byte[] confirmationKey = java.util.Arrays.copyOf(kdf(z, otherInfo, 4 * keyLength), keyLength);
      byte[] expected =
          aesCmac(
              confirmationKey,
              concat(
                  "KC_1_V".getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                  cardId,
                  hostId,
                  java.util.Arrays.copyOfRange(hostPoint, 1, hostPoint.length)));
      assertArrayEquals(
          expected, cryptogram, "AuthCryptogram_ICC over keys derived with the received CB_H");
    }

    byte[] point = activeBasePoint();
    assertSw(
        0x6A80,
        transmit(
            0x00,
            0x87,
            activeAlgorithm() & 0xFF,
            KEY_REF_SECURE_MESSAGING & 0xFF,
            tlv(
                (byte) 0x7C,
                concat(
                    tlv((byte) 0x81, concat(new byte[] {0x10}, hex("0102030405060708"), point)),
                    hex("8200")))),
        "C3: CB_H & 'F0' other than 0x00 is rejected");
  }

  /**
   * Step C11 response lengths take the shortest BER-TLV form (ISO/IEC 7816-4 Section 6.3) on both
   * sides of the one-octet and '81' boundaries. The CVC length sets the Response '82' length to 7E
   * (template 80), 80, F7 (the template size of a typical CS2 CVC, answered as '7C 81 FA') and FF.
   */
  @Test
  void opacityResponseLengthsUseShortestFormAcrossBoundaries() {
    configureVciMode((byte) 0x02);
    createVciKeyOverScp(ATTR_NONE);
    generateVciKeyOverScpReturningPoint();
    int nonceLength = (isCs2Build() ? 32 : 48) / 2;
    int fixedLength = 1 + nonceLength + 16;
    byte[] hostPoint = activeBasePoint();

    for (int responseLength : new int[] {0x7E, 0x80, 0xF7, 0xFF}) {
      byte[] cvc = new byte[responseLength - fixedLength];
      for (int i = 0; i < cvc.length; i++) cvc[i] = (byte) (i + 1);
      loadVciCvcOverScp(cvc);

      byte[] data =
          collectResponse(
              transmit(
                  0x00,
                  0x87,
                  activeAlgorithm() & 0xFF,
                  KEY_REF_SECURE_MESSAGING & 0xFF,
                  tlv(
                      (byte) 0x7C,
                      concat(
                          tlv(
                              (byte) 0x81,
                              concat(new byte[] {0x00}, hex("0102030405060708"), hostPoint)),
                          hex("8200"))),
                  256),
              "OPACITY with response length " + responseLength);

      byte[] responseHeader = concat(new byte[] {(byte) 0x82}, derLength(responseLength));
      int templateLength = responseHeader.length + responseLength;
      byte[] expectedHeader =
          concat(new byte[] {(byte) 0x7C}, derLength(templateLength), responseHeader);
      assertArrayEquals(
          expectedHeader,
          java.util.Arrays.copyOf(data, expectedHeader.length),
          "Shortest lengths for response length " + responseLength);
      assertEquals(
          expectedHeader.length + responseLength,
          data.length,
          "Template size for response length " + responseLength);
      assertArrayEquals(
          cvc,
          java.util.Arrays.copyOfRange(data, data.length - cvc.length, data.length),
          "C_ICC ends the response");
    }
  }

  private byte[] generateVciKeyOverScpReturningPoint() {
    return withMockedScp(
        () -> {
          ResponseAPDU response =
              transmit(
                  0x84,
                  0x47,
                  0x00,
                  KEY_REF_SECURE_MESSAGING & 0xFF,
                  tlv((byte) 0xAC, tlv((byte) 0x80, new byte[] {activeAlgorithm()})),
                  256);
          return tlvValue(collectResponse(response, "Generate VCI key on-card"), (byte) 0x86);
        });
  }

  private static byte activeKdfAlgorithmId() {
    return isCs2Build() ? (byte) 0x09 : (byte) 0x0D;
  }

  /** SP 800-56A Section 5.8.1 one-step KDF with the suite hash of SP 800-73-5 Table 18. */
  private static byte[] kdf(byte[] z, byte[] otherInfo, int length) throws Exception {
    java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
    for (int counter = 1; output.size() < length; counter++) {
      java.security.MessageDigest digest =
          java.security.MessageDigest.getInstance(isCs2Build() ? "SHA-256" : "SHA-384");
      digest.update(new byte[] {0, 0, 0, (byte) counter});
      digest.update(z);
      digest.update(otherInfo);
      output.write(digest.digest());
    }
    return java.util.Arrays.copyOf(output.toByteArray(), length);
  }

  private static byte[] aesCmac(byte[] key, byte[] input) {
    org.bouncycastle.crypto.macs.CMac cmac =
        new org.bouncycastle.crypto.macs.CMac(
            org.bouncycastle.crypto.engines.AESEngine.newInstance());
    cmac.init(new org.bouncycastle.crypto.params.KeyParameter(key));
    cmac.update(input, 0, input.length);
    byte[] mac = new byte[16];
    cmac.doFinal(mac, 0);
    return mac;
  }

  private static byte[] uncompressedPoint(java.security.interfaces.ECPublicKey key) {
    int fieldLength = (key.getParams().getCurve().getField().getFieldSize() + 7) / 8;
    return concat(
        new byte[] {0x04},
        unsigned(key.getW().getAffineX(), fieldLength),
        unsigned(key.getW().getAffineY(), fieldLength));
  }

  private static byte[] unsigned(java.math.BigInteger value, int length) {
    byte[] encoded = value.toByteArray();
    byte[] out = new byte[length];
    int copy = Math.min(encoded.length, length);
    System.arraycopy(encoded, encoded.length - copy, out, length - copy, copy);
    return out;
  }

  private static java.security.PublicKey cardPublicKey(byte[] point, java.security.PublicKey like)
      throws Exception {
    int fieldLength = (point.length - 1) / 2;
    java.security.spec.ECPoint w =
        new java.security.spec.ECPoint(
            new java.math.BigInteger(1, java.util.Arrays.copyOfRange(point, 1, 1 + fieldLength)),
            new java.math.BigInteger(
                1, java.util.Arrays.copyOfRange(point, 1 + fieldLength, point.length)));
    return java.security.KeyFactory.getInstance("EC")
        .generatePublic(
            new java.security.spec.ECPublicKeySpec(
                w, ((java.security.interfaces.ECPublicKey) like).getParams()));
  }

  @Test
  void pairingCodeRequiresDiscoveryAndAllowsPlaintextContactVerify() {
    configureVciMode((byte) 0x02);
    createPairingCodeReferenceData();

    assertSw(
        0x6A88,
        transmit(0x00, 0x20, 0x00, 0x98, hex("3132333435363738")),
        "Pairing reference must not exist without stored Discovery VCI policy");

    withMockedScp(
        () -> {
          createDiscoveryObject();
          assertSw(0x9000, selectApplet(), "SELECT before stored Discovery policy");
          assertSw(
              0x9000,
              transmit(0x84, 0xDB, 0x3F, 0xFF, hex("7E124F0BA0000003080000100001005F2F024800")),
              "Store pairing-required Discovery policy");
        });

    assertSw(
        0x9000,
        transmit(0x00, 0x20, 0x00, 0x98, hex("3132333435363738")),
        "Part 2 Table 2 permits plaintext pairing-code VERIFY on contact");
  }

  @Test
  void malformedPairingCodeReferenceMakesKeyReference98Unverifiable() {
    configureVciMode((byte) 0x02);
    // Table 44 requires the pairing code under tag 99; tag 98 leaves the container unusable.
    createPairingCodeReferenceData((byte) 0x98);
    withMockedScp(
        () -> {
          createDiscoveryObject();
          assertSw(0x9000, selectApplet(), "SELECT before stored Discovery policy");
          assertSw(
              0x9000,
              transmit(0x84, 0xDB, 0x3F, 0xFF, hex("7E124F0BA0000003080000100001005F2F024800")),
              "Store pairing-required Discovery policy");
        });

    assertSw(
        0x6A88,
        transmit(0x00, 0x20, 0x00, 0x98, hex("3132333435363738")),
        "SP 800-73-5 Part 2 Section 3.2.1: an unverifiable key reference returns 6A88");
  }

  private void configureVciMode(final byte mode) {
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before VCI config");
            assertSw(
                0x9000,
                transmit(
                    0x84,
                    0xDB,
                    0xFF,
                    0xFF,
                    hex("68 05 A2 03 80 01 " + String.format("%02X", mode))),
                "Update VCI mode");
          }
        });
  }

  private void createVciKeyOverScp(final byte attributes) {
    createVciKeyOverScp(attributes, activeAlgorithm());
  }

  private void createVciKeyOverScp(final byte attributes, final byte mechanism) {
    assertSw(0x9000, createVciKeyOverScpForResponse(attributes, mechanism), "Create VCI key");
  }

  private ResponseAPDU createVciKeyOverScpForResponse(final byte attributes, final byte mechanism) {
    final ResponseAPDU[] response = new ResponseAPDU[1];
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before VCI key create");
            byte[] request =
                tlv(
                    (byte) 0x66,
                    concat(
                        new byte[] {
                          (byte) 0x8B, (byte) 0x01, KEY_REF_SECURE_MESSAGING,
                          (byte) 0x8C, (byte) 0x01, ACCESS_MODE_ALWAYS,
                          (byte) 0x8D, (byte) 0x01, ACCESS_MODE_ALWAYS,
                          (byte) 0x91, (byte) 0x01, (byte) 0x9B,
                          (byte) 0x8E, (byte) 0x01, mechanism,
                          (byte) 0x8F, (byte) 0x01, ROLE_KEY_ESTABLISH,
                          (byte) 0x90, (byte) 0x01, attributes
                        }));
            response[0] = transmit(0x84, 0xDB, 0xFF, 0xFF, request);
          }
        });
    return response[0];
  }

  private void createDiscoveryObject() {
    byte[] request =
        tlv(
            (byte) 0x64,
            new byte[] {
              (byte) 0x8B,
              (byte) 0x01,
              (byte) 0x7E,
              (byte) 0x8C,
              (byte) 0x01,
              ACCESS_MODE_ALWAYS,
              (byte) 0x8D,
              (byte) 0x01,
              ACCESS_MODE_ALWAYS,
              (byte) 0x91,
              (byte) 0x01,
              (byte) 0x9B,
              (byte) 0x92,
              (byte) 0x02,
              (byte) 0x00,
              (byte) 0x20
            });
    assertSw(0x9000, transmit(0x84, 0xDB, 0xFF, 0xFF, request), "Create Discovery Object");
  }

  private void createOperationalVciKey() {
    createVciKeyOverScp(ATTR_NONE);
    generateVciKeyOverScp();
    loadVciCvcOverScp(hex("7F210401020304"));
  }

  private void generateVciKeyOverScp() {
    withMockedScp(
        () ->
            assertSw(
                0x9000,
                transmit(
                    0x84,
                    0x47,
                    0x00,
                    KEY_REF_SECURE_MESSAGING & 0xFF,
                    tlv((byte) 0xAC, tlv((byte) 0x80, new byte[] {activeAlgorithm()}))),
                "Generate VCI key on-card"));
  }

  private void createPairingCodeReferenceData() {
    createPairingCodeReferenceData((byte) 0x99);
  }

  private void createPairingCodeReferenceData(final byte pairingCodeTag) {
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            byte[] createObject =
                tlv(
                    (byte) 0x64,
                    new byte[] {
                      (byte) 0x8B,
                      (byte) 0x03,
                      (byte) 0x5F,
                      (byte) 0xC1,
                      (byte) 0x23,
                      (byte) 0x8C,
                      (byte) 0x01,
                      ACCESS_MODE_PIN,
                      (byte) 0x8D,
                      (byte) 0x01,
                      (byte) (ACCESS_MODE_VCI | ACCESS_MODE_PIN),
                      (byte) 0x91,
                      (byte) 0x01,
                      (byte) 0x9B,
                      (byte) 0x92,
                      (byte) 0x02,
                      (byte) 0x00,
                      (byte) 0x0E
                    });
            assertSw(
                0x9000,
                transmit(0x84, 0xDB, 0xFF, 0xFF, createObject),
                "Create Pairing Code Reference Data object");

            byte[] content =
                concat(
                    hex("5C035FC123"),
                    tlv(
                        (byte) 0x53,
                        concat(tlv(pairingCodeTag, hex("3132333435363738")), hex("FE00"))));
            assertSw(
                0x9000,
                transmit(0x84, 0xDB, 0x3F, 0xFF, content),
                "Load Pairing Code Reference Data object");
          }
        });
  }

  private void importVciPrivateKeyOverScp(byte[] privateScalar) {
    importVciPrivateKeyOverScp(privateScalar, activeAlgorithm());
  }

  private void importVciPrivateKeyOverScp(byte[] privateScalar, byte mechanism) {
    ResponseAPDU response =
        changeVciReferenceDataOverScp(tlv((byte) 0x30, tlv((byte) 0x87, privateScalar)), mechanism);
    assertSw(0x9000, response, "Import VCI private key");
  }

  private void importVciPublicKeyOverScp(byte[] publicPoint) {
    importVciPublicKeyOverScp(publicPoint, activeAlgorithm());
  }

  private void importVciPublicKeyOverScp(byte[] publicPoint, byte mechanism) {
    ResponseAPDU response =
        changeVciReferenceDataOverScp(tlv((byte) 0x30, tlv((byte) 0x86, publicPoint)), mechanism);
    assertSw(0x9000, response, "Import VCI public key");
  }

  private void loadVciCvcOverScp(byte[] cvc) {
    loadVciCvcOverScp(cvc, activeAlgorithm());
  }

  private void loadVciCvcOverScp(byte[] cvc, byte mechanism) {
    ResponseAPDU response =
        changeVciReferenceDataOverScp(tlv((byte) 0x30, tlv((byte) 0x8A, cvc)), mechanism);
    assertSw(0x9000, response, "Load VCI CVC");
  }

  private ResponseAPDU changeVciReferenceDataOverScp(final byte[] data) {
    return changeVciReferenceDataOverScp(data, activeAlgorithm());
  }

  private ResponseAPDU changeVciReferenceDataOverScp(final byte[] data, final byte mechanism) {
    final ResponseAPDU[] response = new ResponseAPDU[1];
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            response[0] =
                transmit(0x84, 0x24, mechanism & 0xFF, KEY_REF_SECURE_MESSAGING & 0xFF, data);
          }
        });
    return response[0];
  }

  private static boolean contains(byte[] haystack, byte[] needle) {
    outer:
    for (int i = 0; i <= haystack.length - needle.length; i++) {
      for (int j = 0; j < needle.length; j++) {
        if (haystack[i + j] != needle[j]) continue outer;
      }
      return true;
    }
    return false;
  }

  private ResponseAPDU selectAppletWithData() {
    return transmit(
        new javax.smartcardio.CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 256));
  }

  private static byte[] fixed(byte value, int length) {
    byte[] out = new byte[length];
    for (int i = 0; i < out.length; i++) out[i] = value;
    return out;
  }

  private static byte[] policyBytes(byte[] discovery) {
    for (int i = 0; i <= discovery.length - 5; i++) {
      if (discovery[i] == (byte) 0x5F && discovery[i + 1] == (byte) 0x2F && discovery[i + 2] == 2) {
        return new byte[] {discovery[i + 3], discovery[i + 4]};
      }
    }
    throw new IllegalArgumentException("Discovery Object missing 5F2F policy bytes");
  }

  private static byte[] p256ScalarOne() {
    byte[] scalar = new byte[32];
    scalar[31] = 1;
    return scalar;
  }

  private static byte[] p256BasePoint() {
    return hex(
        "04"
            + "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
            + "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
  }

  private static byte[] p384ScalarOne() {
    byte[] scalar = new byte[48];
    scalar[47] = 1;
    return scalar;
  }

  private static byte[] p384BasePoint() {
    // secp384r1 generator (uncompressed).
    return hex(
        "04AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"
            + "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F");
  }

  private static boolean isCs2Build() {
    return !"CS7".equalsIgnoreCase(System.getProperty("vci.suite", "CS2"));
  }

  private static byte activeAlgorithm() {
    return isCs2Build() ? ALG_CS2 : ALG_CS7;
  }

  private static byte inactiveAlgorithm() {
    return isCs2Build() ? ALG_CS7 : ALG_CS2;
  }

  private static byte[] activeBasePoint() {
    return isCs2Build() ? p256BasePoint() : p384BasePoint();
  }

  private static byte[] activeScalarOne() {
    return isCs2Build() ? p256ScalarOne() : p384ScalarOne();
  }

  private static byte[] activeAdvertisement() {
    return new byte[] {(byte) 0x80, (byte) 0x01, activeAlgorithm()};
  }
}
