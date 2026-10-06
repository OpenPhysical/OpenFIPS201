package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javax.crypto.KeyAgreement;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * Asymmetric key import through CHANGE REFERENCE DATA (INS 24) under the admin key.
 *
 * <p>JC 3.0.5 API Util.arrayCopyNonAtomic "does not use the transaction facility during the copy
 * operation even if a transaction is in progress", and key-component setters have no specified
 * transaction behaviour. A pair-wise consistency failure must therefore leave one coherent state:
 * the whole import is cleared, and a fresh import of every component is required.
 *
 * <p>An imported public point passes the same SP 800-56A Section 5.6.2.3.3 partial public-key
 * validation as a peer point in key agreement. A point outside the field or off the curve is
 * incorrect command data ('6A80') and clears the import. Key 9D is importable in every build
 * profile, including FIPS; only its P-384 definition is refused by the FIPS CS2 profile.
 */
class OpenFIPS201KeyImportAtomicityTest extends OpenFIPS201TestSupport {
  private static final int KEY_MANAGEMENT = 0x9D;

  enum Curve {
    P256(0x11, "secp256r1", 32),
    P384(0x14, "secp384r1", 48);

    final int mechanism;
    final String name;
    final int fieldBytes;

    Curve(int mechanism, String name, int fieldBytes) {
      this.mechanism = mechanism;
      this.name = name;
      this.fieldBytes = fieldBytes;
    }
  }

  @Test
  void failedConsistencyTestClearsTheWholeImport() throws Exception {
    Curve curve = Curve.P256;
    KeyPair card = keyPair(curve);
    KeyPair mismatch = keyPair(curve);
    byte[] cardPoint = point(curve, (ECPublicKey) card.getPublic());

    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before key import");
          assertSw(
              0x9000,
              transmit(0x84, 0xDB, 0xFF, 0xFF, importableKeyDefinition(curve)),
              "Create an importable P-256 key-management key");
          try (MockedStatic<JCSystem> jcSystem =
              Mockito.mockStatic(JCSystem.class, Mockito.CALLS_REAL_METHODS)) {
            assertSw(0x9000, importElement(curve, 0x86, cardPoint), "Import the public point");
            jcSystem.verify(JCSystem::beginTransaction, Mockito.atLeastOnce());
            jcSystem.clearInvocations();

            assertSw(
                ISO7816.SW_WRONG_DATA,
                importElement(curve, 0x87, scalar(curve, (ECPrivateKey) mismatch.getPrivate())),
                "A private scalar that does not match the public point fails the PCT");
            // An abort would restore the import flags but not the non-atomically cleared key
            // components, so the rejection must not depend on rolling a transaction back.
            jcSystem.verify(JCSystem::abortTransaction, Mockito.never());
          }

          // The failed import cleared the point too, so this scalar alone completes nothing.
          assertSw(
              0x9000,
              importElement(curve, 0x87, scalar(curve, (ECPrivateKey) card.getPrivate())),
              "Import the matching private scalar into the cleared key");
        });

    assertKeyUnusable(curve);

    withMockedScp(
        () ->
            assertSw(
                0x9000,
                importElement(curve, 0x86, cardPoint),
                "Re-importing the point completes a consistent pair"));

    assertKeyAgreementMatches(curve, card);
  }

  @ParameterizedTest
  @EnumSource(Curve.class)
  void offCurvePointIsRejectedAndClearsTheImport(Curve curve) throws Exception {
    assumeKeyManagementCurveAllowed(curve);
    KeyPair card = keyPair(curve);
    byte[] validPoint = point(curve, (ECPublicKey) card.getPublic());
    byte[] offCurve = validPoint.clone();
    // Changing the last octet of Y keeps both coordinates below p but leaves the curve.
    offCurve[offCurve.length - 1] ^= (byte) 0x01;

    withMockedScp(
        () -> {
          createImportableKey(curve);
          assertSw(0x9000, importElement(curve, 0x86, validPoint), "Import a valid public point");
          // No private scalar is present, so no pair-wise consistency test runs: only the point
          // validation can reject this element.
          assertSw(
              ISO7816.SW_WRONG_DATA,
              importElement(curve, 0x86, offCurve),
              "A public point that is not on the curve is incorrect command data");
          // The rejection cleared the earlier point, so this scalar alone completes nothing.
          assertSw(
              0x9000,
              importElement(curve, 0x87, scalar(curve, (ECPrivateKey) card.getPrivate())),
              "Import the private scalar into the cleared key");
        });

    assertKeyUnusable(curve);

    withMockedScp(
        () ->
            assertSw(
                0x9000,
                importElement(curve, 0x86, validPoint),
                "Re-importing the point completes a consistent pair"));

    assertKeyAgreementMatches(curve, card);
  }

  @ParameterizedTest
  @EnumSource(Curve.class)
  void coordinateOutsideTheFieldIsRejected(Curve curve) throws Exception {
    assumeKeyManagementCurveAllowed(curve);
    ECPublicKey publicKey = (ECPublicKey) keyPair(curve).getPublic();
    BigInteger p = fieldPrime(publicKey);
    byte[] x = fixed(publicKey.getW().getAffineX(), curve.fieldBytes);
    byte[] y = fixed(publicKey.getW().getAffineY(), curve.fieldBytes);

    withMockedScp(
        () -> {
          createImportableKey(curve);
          assertSw(
              ISO7816.SW_WRONG_DATA,
              importElement(curve, 0x86, concat(new byte[] {0x04}, fixed(p, curve.fieldBytes), y)),
              "x = p is outside the field");
          assertSw(
              ISO7816.SW_WRONG_DATA,
              importElement(curve, 0x86, concat(new byte[] {0x04}, x, fixed(p, curve.fieldBytes))),
              "y = p is outside the field");
          byte[] compressedPrefix = point(curve, publicKey);
          compressedPrefix[0] = 0x02;
          assertSw(
              ISO7816.SW_WRONG_DATA,
              importElement(curve, 0x86, compressedPrefix),
              "Only the uncompressed encoding is accepted");
          byte[] truncated = new byte[curve.fieldBytes * 2];
          System.arraycopy(point(curve, publicKey), 0, truncated, 0, truncated.length);
          assertSw(
              ISO7816.SW_WRONG_LENGTH,
              importElement(curve, 0x86, truncated),
              "A point of the wrong length for the curve");
        });
  }

  @ParameterizedTest
  @EnumSource(Curve.class)
  void validImportedPairPerformsKeyAgreement(Curve curve) throws Exception {
    assumeKeyManagementCurveAllowed(curve);
    KeyPair card = keyPair(curve);

    withMockedScp(
        () -> {
          createImportableKey(curve);
          assertSw(
              0x9000,
              importElement(curve, 0x86, point(curve, (ECPublicKey) card.getPublic())),
              "Import the public point");
          assertSw(
              0x9000,
              importElement(curve, 0x87, scalar(curve, (ECPrivateKey) card.getPrivate())),
              "Import the private scalar");
        });

    assertKeyAgreementMatches(curve, card);
  }

  /**
   * SP 800-78-5 Section 3.1: a VCI-capable card with a P-384 key-management key must use the P-384
   * secure-messaging suite, so the FIPS CS2 profile refuses a P-384 9D definition.
   */
  private static void assumeKeyManagementCurveAllowed(Curve curve) {
    assumeFalse(
        curve == Curve.P384
            && Boolean.getBoolean("fips.mode")
            && "CS2".equalsIgnoreCase(System.getProperty("vci.suite", "CS2")),
        "The FIPS CS2 profile refuses a P-384 key-management key (SP 800-78-5 Section 3.1)");
  }

  private void createImportableKey(Curve curve) {
    assertSw(0x9000, selectApplet(), "SELECT before key import");
    assertSw(
        0x9000,
        transmit(0x84, 0xDB, 0xFF, 0xFF, importableKeyDefinition(curve)),
        "Create an importable " + curve + " key-management key");
  }

  private void assertKeyUnusable(Curve curve) throws Exception {
    assertSw(
        0x9000,
        transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN),
        "VERIFY before key establishment");
    KeyPair host = keyPair(curve);
    assertNotEquals(
        0x9000,
        transmit(0x00, 0x87, curve.mechanism, KEY_MANAGEMENT, keyAgreementRequest(curve, host), 0)
            .getSW(),
        "An incomplete import must not be usable");
  }

  private void assertKeyAgreementMatches(Curve curve, KeyPair card) throws Exception {
    assertSw(
        0x9000,
        transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN),
        "VERIFY before key establishment");
    KeyPair host = keyPair(curve);
    byte[] response =
        collectResponse(
            transmit(
                0x00, 0x87, curve.mechanism, KEY_MANAGEMENT, keyAgreementRequest(curve, host), 0),
            "Key establishment with the completed import");
    KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
    agreement.init(host.getPrivate());
    agreement.doPhase(card.getPublic(), true);
    assertArrayEquals(
        agreement.generateSecret(),
        tlvValue(tlvValue(response, (byte) 0x7C), (byte) 0x82),
        "The card must hold exactly the imported pair");
  }

  private static byte[] keyAgreementRequest(Curve curve, KeyPair host) {
    return tlv((byte) 0x7C, tlv((byte) 0x85, point(curve, (ECPublicKey) host.getPublic())));
  }

  private javax.smartcardio.ResponseAPDU importElement(Curve curve, int tag, byte[] value) {
    return transmit(
        0x84, 0x24, curve.mechanism, KEY_MANAGEMENT, tlv((byte) 0x30, tlv((byte) tag, value)));
  }

  private static byte[] importableKeyDefinition(Curve curve) {
    return new byte[] {
      0x66,
      0x12,
      (byte) 0x8B,
      0x01,
      (byte) KEY_MANAGEMENT,
      (byte) 0x8C,
      0x01,
      0x01,
      (byte) 0x8D,
      0x01,
      0x09,
      (byte) 0x8E,
      0x01,
      (byte) curve.mechanism,
      (byte) 0x8F,
      0x01,
      0x02,
      (byte) 0x90,
      0x01,
      0x10
    };
  }

  private static KeyPair keyPair(Curve curve) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec(curve.name));
    return generator.generateKeyPair();
  }

  private static BigInteger fieldPrime(ECPublicKey key) {
    return ((ECFieldFp) key.getParams().getCurve().getField()).getP();
  }

  private static byte[] point(Curve curve, ECPublicKey key) {
    return concat(
        new byte[] {0x04},
        fixed(key.getW().getAffineX(), curve.fieldBytes),
        fixed(key.getW().getAffineY(), curve.fieldBytes));
  }

  private static byte[] scalar(Curve curve, ECPrivateKey key) {
    return fixed(key.getS(), curve.fieldBytes);
  }

  private static byte[] fixed(BigInteger value, int length) {
    byte[] encoded = value.toByteArray();
    byte[] result = new byte[length];
    int sourceOffset = Math.max(0, encoded.length - length);
    int copyLength = Math.min(encoded.length, length);
    System.arraycopy(encoded, sourceOffset, result, length - copyLength, copyLength);
    return result;
  }
}
