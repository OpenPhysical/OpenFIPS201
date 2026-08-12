package dev.mistial.tests.openfips201;

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
            ResponseAPDU response = transmit(0x84, 0xDB, 0x3F, 0x00, hex("68 05 A2 03 80 01 03"));
            assertSw(0x6984, response, "VCI mode must be disabled, enabled, or pairing-code");
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
            ResponseAPDU config = transmit(0x84, 0xDB, 0x3F, 0x00, hex("68 05 A3 03 80 01 01"));
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
                      (byte) 0x0C
                    });
            ResponseAPDU object = transmit(0x84, 0xDB, 0x3F, 0x00, objectWithOcc);
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
  void discoveryObjectAdvertisesVciAndPairingPolicy() {
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before VCI pairing-required config");
            assertSw(
                0x9000,
                transmit(0x84, 0xDB, 0x3F, 0x00, hex("68 05 A2 03 80 01 02")),
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
    assertSw(0x9000, pairingRequired, "Read Discovery Object with VCI pairing-required ready");
    pairingPolicy = policyBytes(pairingRequired.getData());
    assertTrue((pairingPolicy[0] & 0x08) != 0, "Discovery Object must set VCI implemented bit");
    assertFalse((pairingPolicy[0] & 0x04) != 0, "Pairing-required VCI must clear no-pairing bit");

    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(
                0x9000,
                transmit(0x84, 0xDB, 0x3F, 0x00, hex("68 05 A2 03 80 01 01")),
                "Enable VCI without pairing code");
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

    ResponseAPDU secondSuite =
        createVciKeyOverScpForResponse(ATTR_NONE, inactiveAlgorithm());
    assertEquals(0x6A81, secondSuite.getSW(), "Card must not accept both SM suites");
  }

  /**
   * SP 800-73-5 Part 2 Section 4.1 reserves key 04 for OPACITY establishment. Tag 85 is the
   * generic key-management ECDH form and must never expose key 04's shared secret.
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
              transmit(
                  0x84,
                  0xDB,
                  0x3F,
                  0xFF,
                  hex("7E124F0BA0000003080000100001005F2F024800")),
              "Store pairing-required Discovery policy");
        });

    assertSw(
        0x9000,
        transmit(0x00, 0x20, 0x00, 0x98, hex("3132333435363738")),
        "Part 2 Table 2 permits plaintext pairing-code VERIFY on contact");
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
                    0x3F,
                    0x00,
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
            response[0] = transmit(0x84, 0xDB, 0x3F, 0x00, request);
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
    assertSw(0x9000, transmit(0x84, 0xDB, 0x3F, 0x00, request), "Create Discovery Object");
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
                      (byte) 0x0C
                    });
            assertSw(
                0x9000,
                transmit(0x84, 0xDB, 0x3F, 0x00, createObject),
                "Create Pairing Code Reference Data object");

            byte[] content =
                concat(
                    hex("5C035FC123"), tlv((byte) 0x53, tlv((byte) 0x99, hex("3132333435363738"))));
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
