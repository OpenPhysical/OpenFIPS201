package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.concurrent.TimeUnit;
import javacard.framework.ISO7816;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.globalplatform.GPSystem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.Mockito;

/**
 * The FIPS profile's readiness gate on the irreversible PERSONALIZE transition (administrative PUT
 * DATA {@code 69}, which moves the GlobalPlatform application lifecycle to PERSONALIZED '0F').
 *
 * <p>Each refusal is '6985' (conditions of use not satisfied), leaves the lifecycle unchanged, and
 * is shown to be caused by the one missing condition: repairing it lets the same card personalize.
 *
 * <ul>
 *   <li>SP 800-73-5 Part 1 Section 3.3.2: a stored Discovery Object advertises only features the
 *       card implements.
 *   <li>SP 800-73-5 Part 1 Section 3.3.3: "The Key History object SHALL be present in the PIV Card
 *       Application if the PIV Card Application contains any retired key management private keys".
 *   <li>SP 800-73-5 Part 1 Section 3.3.8 and Table 44: with pairing-code VCI the Pairing Code
 *       Reference Data Container is exactly {@code 99 08 <8 digits> FE 00}.
 * </ul>
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class OpenFIPS201FipsPersonalizationReadinessTest extends OpenFIPS201TestSupport {
  private static final byte LIFECYCLE_PERSONALIZED = (byte) 0x0F;
  private static final byte ALG_ECC_P256 = (byte) 0x11;
  private static final byte KEY_SECURE_MESSAGING = (byte) 0x04;
  private static final byte KEY_ATTESTATION = (byte) 0xF9;
  private static final X500Name AUTHORITY_TEMPLATE =
      new X500Name("C=US,O=OpenPhysical Test,CN=PIV Attestation Authority");
  private static final byte[] DISCOVERY_PIN_ONLY = discovery("4000");
  private static final byte[] PAIRING_CODE = "12345678".getBytes(StandardCharsets.US_ASCII);

  /** F9 activation wipes other key material, so the standard card is applied after it. */
  @Override
  protected boolean provisionsStandardCard() {
    return false;
  }

  @BeforeEach
  void provisionFipsReadyCard() throws Exception {
    assumeTrue(Boolean.getBoolean("fips.mode"), "The readiness gate applies to the FIPS profile");
    if (isAttestationEnabledBuild()) {
      activateAttestationAuthority();
    }
    provisionStandardTestCard();
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before card provisioning");
          // SP 800-73-5 Part 1 Table 5 access rules for the PIV Authentication and Card
          // Authentication keys; both are generated on the card.
          generateKey("66128B019A8C01018D01098E01118F0104900100", 0x9A);
          generateKey("66128B019E8C017F8D017F8E01118F0104900100", 0x9E);
          // SP 800-73-5 Part 1 Table 1 mandatory objects, with the Table 3 access rules and the
          // Table 8 minimum capacities the FIPS profile enforces at creation.
          putObject("5FC107", 0x7F, 0x08, 170, hex("F00100F10121FE00"));
          putObject(
              "5FC102",
              0x7F,
              0x7F,
              2881,
              concat(
                  tlv((byte) 0x34, new byte[16]),
                  tlv((byte) 0x35, "20301231".getBytes(StandardCharsets.US_ASCII)),
                  hex("3E00FE00")));
          putObject("5FC105", 0x7F, 0x08, 1857, hex("700530030201007101" + "00FE00"));
          putObject("5FC101", 0x7F, 0x7F, 1857, hex("700530030201007101" + "00FE00"));
          putObject("5FC103", 0x01, 0x09, 4006, hex("BC0100FE00"));
          putObject("5FC108", 0x01, 0x09, 12710, hex("BC0100FE00"));
          putObject("5FC106", 0x7F, 0x08, 1336, hex("BA03010203BB0100FE00"));
        });
  }

  /** The first complete FIPS card: every readiness condition holds, and PERSONALIZE succeeds. */
  @Test
  void completeProfilePersonalizes() {
    assertPersonalizes("A complete FIPS card profile");
  }

  @Test
  void discoveryAdvertisingAnUnimplementedFeatureBlocksPersonalization() {
    withMockedScp(
        () -> {
          createObject("7E", 0x7F, 0x7F, 0x20);
          // PIN Usage Policy '48 00': PIV PIN and VCI, on a card that does not configure VCI.
          assertSw(0x9000, transmit(0x84, 0xDB, 0x3F, 0xFF, discovery("4800")), "Store Discovery");
        });
    assertRefused("A Discovery Object advertising VCI without VCI");

    withMockedScp(
        () ->
            assertSw(
                0x9000, transmit(0x84, 0xDB, 0x3F, 0xFF, DISCOVERY_PIN_ONLY), "Store Discovery"));
    assertPersonalizes("A Discovery Object advertising only the PIV PIN");
  }

  @Test
  void retiredKeyWithoutKeyHistoryBlocksPersonalization() {
    withMockedScp(() -> generateKey("66128B01828C01018D01098E01118F0102900100", 0x82));
    assertRefused("A retired key-management key without Key History");

    withMockedScp(() -> putObject("5FC10C", 0x7F, 0x08, 128, hex("C10101C20100FE00")));
    assertPersonalizes("A retired key-management key with Key History");
  }

  @Test
  void malformedPairingCodeReferenceBlocksPersonalization() {
    withMockedScp(
        () -> {
          // VCI with pairing code (SP 800-73-5 Part 1 Section 5.5) and its prerequisites: the
          // secure-messaging key with its CVC, the signer container 5FC122 and a Discovery Object
          // advertising pairing-required VCI.
          assertSw(
              0x9000, transmit(0x84, 0xDB, 0xFF, 0xFF, hex("68 05 A2 03 80 01 02")), "VCI mode");
          byte suite = activeSuite();
          assertSw(
              0x9000,
              transmit(
                  0x84,
                  0xDB,
                  0xFF,
                  0xFF,
                  concat(
                      hex("6612 8B0104 8C017F 8D017F 8E01"),
                      new byte[] {suite},
                      hex("8F0102 900100"))),
              "Define the secure-messaging key");
          collectResponse(
              transmit(
                  0x84,
                  0x47,
                  0x00,
                  KEY_SECURE_MESSAGING,
                  tlv((byte) 0xAC, tlv((byte) 0x80, new byte[] {suite})),
                  256),
              "Generate the secure-messaging key");
          assertSw(
              0x9000,
              transmit(
                  0x84,
                  0x24,
                  suite & 0xFF,
                  KEY_SECURE_MESSAGING,
                  tlv((byte) 0x30, tlv((byte) 0x8A, hex("7F210401020304")))),
              "Load the secure-messaging CVC");
          putObject("5FC122", 0x7F, 0x7F, 2471, hex("700530030201007101" + "00FE00"));
          createObject("7E", 0x7F, 0x7F, 0x20);
          assertSw(
              0x9000,
              transmit(0x84, 0xDB, 0x3F, 0xFF, discovery("4800")),
              "Store a pairing-required VCI Discovery Object");
          // Pairing Code '98' instead of '99'.
          putObject("5FC123", 0x01, 0x09, 14, concat(tlv((byte) 0x98, PAIRING_CODE), hex("FE00")));
        });
    assertRefused("A malformed Pairing Code Reference Data Container");

    withMockedScp(
        () ->
            assertSw(
                0x9000,
                transmit(
                    0x84,
                    0xDB,
                    0x3F,
                    0xFF,
                    concat(
                        hex("5C035FC123"),
                        tlv((byte) 0x53, concat(tlv((byte) 0x99, PAIRING_CODE), hex("FE00"))))),
                "Repair the Pairing Code Reference Data Container"));
    assertPersonalizes("A well-formed Pairing Code Reference Data Container");
  }

  private void assertRefused(String context) {
    assertEquals(
        GPSystem.APPLICATION_SELECTABLE,
        personalize(ISO7816.SW_CONDITIONS_NOT_SATISFIED, context + " blocks PERSONALIZE"),
        context + " must leave the lifecycle unchanged");
  }

  private void assertPersonalizes(String context) {
    assertEquals(
        LIFECYCLE_PERSONALIZED,
        personalize(ISO7816.SW_NO_ERROR, context + " personalizes"),
        context + " must reach the PERSONALIZED lifecycle");
  }

  /** Sends PERSONALIZE and returns the lifecycle state GlobalPlatform holds afterwards. */
  private byte personalize(final int expectedSw, final String context) {
    final byte[] state = {GPSystem.APPLICATION_SELECTABLE};
    withMockedScp(
        () -> {
          Mockito.when(GPSystem.getCardContentState()).thenAnswer(invocation -> state[0]);
          Mockito.when(GPSystem.setCardContentState(LIFECYCLE_PERSONALIZED))
              .thenAnswer(
                  invocation -> {
                    state[0] = LIFECYCLE_PERSONALIZED;
                    return true;
                  });
          assertSw(0x9000, selectApplet(), "SELECT before PERSONALIZE");
          assertSw(expectedSw, transmit(0x84, 0xDB, 0xFF, 0xFF, hex("6900")), context);
        });
    return state[0];
  }

  /**
   * Defines F9, generates it, proves possession and loads an issuer-signed certificate, so the
   * authority is ACTIVE. Activation wipes all other keys and data objects.
   */
  private void activateAttestationAuthority() throws Exception {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    final OpenFIPS201AttestationTest.TestIssuer issuer =
        OpenFIPS201AttestationTest.TestIssuer.create();
    final byte[][] point = new byte[1][];
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before F9 provisioning");
          assertSw(
              0x9000,
              transmit(0x84, 0xDB, 0xFF, 0xFF, hex("66128B01F98C01008D01008E01118F0104900100")),
              "Define F9");
          point[0] =
              tlvValue(
                  collectResponse(
                      transmit(0x84, 0x47, 0x00, KEY_ATTESTATION & 0xFF, hex("AC03800111"), 256),
                      "Generate F9"),
                  (byte) 0x86);
          collectResponse(
              transmit(0x84, 0xF9, 0xF9, 0x01, new byte[32], 256), "Prove possession of F9");
        });
    final byte[] certificate =
        issuer.sign(
            issuer.profile(point[0], OpenFIPS201AttestationTest.opid(), AUTHORITY_TEMPLATE));
    withMockedScp(
        () ->
            assertSw(
                0x9000,
                transmitChained(
                    0x84,
                    0x24,
                    ALG_ECC_P256,
                    KEY_ATTESTATION & 0xFF,
                    tlv((byte) 0x30, tlv((byte) 0x70, certificate))),
                "Load the F9 certificate"));
  }

  private void generateKey(String definition, int id) {
    assertSw(0x9000, transmit(0x84, 0xDB, 0xFF, 0xFF, hex(definition)), "Define key " + id);
    collectResponse(
        transmit(
            0x84, 0x47, 0x00, id, new byte[] {(byte) 0xAC, 0x03, (byte) 0x80, 0x01, 0x11}, 256),
        String.format("Generate key %02X", id));
  }

  private void createObject(String id, int contact, int contactless, int capacity) {
    byte[] request =
        tlv(
            (byte) 0x64,
            concat(
                tlv((byte) 0x8B, hex(id)),
                new byte[] {
                  (byte) 0x8C,
                  0x01,
                  (byte) contact,
                  (byte) 0x8D,
                  0x01,
                  (byte) contactless,
                  (byte) 0x91,
                  0x01,
                  (byte) 0x9B,
                  (byte) 0x92,
                  0x02,
                  (byte) (capacity >> 8),
                  (byte) capacity
                }));
    assertSw(0x9000, transmit(0x84, 0xDB, 0xFF, 0xFF, request), "Create object " + id);
  }

  private void putObject(String id, int contact, int contactless, int capacity, byte[] value) {
    createObject(id, contact, contactless, capacity);
    assertSw(
        0x9000,
        transmitChained(
            0x84, 0xDB, 0x3F, 0xFF, concat(tlv((byte) 0x5C, hex(id)), tlv((byte) 0x53, value))),
        "PUT DATA " + id);
  }

  /** SP 800-73-5 Part 1 Section 3.3.2: {@code 7E { 4F <PIV AID> 5F2F <PIN Usage Policy> }}. */
  private static byte[] discovery(String policy) {
    return tlv(
        (byte) 0x7E, concat(tlv((byte) 0x4F, OPENFIPS201_AID_BYTES), hex("5F2F02"), hex(policy)));
  }

  private static byte activeSuite() {
    return (byte) ("CS7".equalsIgnoreCase(System.getProperty("vci.suite", "CS2")) ? 0x2E : 0x27);
  }
}
