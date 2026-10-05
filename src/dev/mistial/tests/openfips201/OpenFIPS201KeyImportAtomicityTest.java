package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javax.crypto.KeyAgreement;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * Asymmetric key import through CHANGE REFERENCE DATA (INS 24) under the admin key.
 *
 * <p>JC 3.0.5 API Util.arrayCopyNonAtomic "does not use the transaction facility during the copy
 * operation even if a transaction is in progress", and key-component setters have no specified
 * transaction behaviour. A pair-wise consistency failure must therefore leave one coherent state:
 * the whole import is cleared, and a fresh import of every component is required.
 */
class OpenFIPS201KeyImportAtomicityTest extends OpenFIPS201TestSupport {
  private static final int KEY_MANAGEMENT = 0x9D;
  private static final int ALG_ECC_P256 = 0x11;
  private static final int FIELD_BYTES = 32;

  @Test
  void failedConsistencyTestClearsTheWholeImport() throws Exception {
    KeyPair card = p256KeyPair();
    KeyPair mismatch = p256KeyPair();
    byte[] cardPoint = point((ECPublicKey) card.getPublic());

    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before key import");
          assertSw(
              0x9000,
              transmit(0x84, 0xDB, 0xFF, 0xFF, importableKeyDefinition()),
              "Create an importable P-256 key-management key");
          try (MockedStatic<JCSystem> jcSystem =
              Mockito.mockStatic(JCSystem.class, Mockito.CALLS_REAL_METHODS)) {
            assertSw(0x9000, importElement(0x86, cardPoint), "Import the public point");
            jcSystem.verify(JCSystem::beginTransaction, Mockito.atLeastOnce());
            jcSystem.clearInvocations();

            assertSw(
                ISO7816.SW_FILE_INVALID,
                importElement(0x87, scalar((ECPrivateKey) mismatch.getPrivate())),
                "A private scalar that does not match the public point fails the PCT");
            // An abort would restore the import flags but not the non-atomically cleared key
            // components, so the rejection must not depend on rolling a transaction back.
            jcSystem.verify(JCSystem::abortTransaction, Mockito.never());
          }

          // The failed import cleared the point too, so this scalar alone completes nothing.
          assertSw(
              0x9000,
              importElement(0x87, scalar((ECPrivateKey) card.getPrivate())),
              "Import the matching private scalar into the cleared key");
        });

    assertSw(
        0x9000,
        transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN),
        "VERIFY before key establishment");
    KeyPair host = p256KeyPair();
    byte[] request = tlv((byte) 0x7C, tlv((byte) 0x85, point((ECPublicKey) host.getPublic())));
    assertNotEquals(
        0x9000,
        transmit(0x00, 0x87, ALG_ECC_P256, KEY_MANAGEMENT, request, 0).getSW(),
        "An incomplete import must not be usable");

    withMockedScp(
        () ->
            assertSw(
                0x9000,
                importElement(0x86, cardPoint),
                "Re-importing the point completes a consistent pair"));

    assertSw(
        0x9000,
        transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN),
        "VERIFY before key establishment");
    byte[] response =
        collectResponse(
            transmit(0x00, 0x87, ALG_ECC_P256, KEY_MANAGEMENT, request, 0),
            "Key establishment with the completed import");
    KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
    agreement.init(host.getPrivate());
    agreement.doPhase(card.getPublic(), true);
    assertArrayEquals(
        agreement.generateSecret(),
        tlvValue(tlvValue(response, (byte) 0x7C), (byte) 0x82),
        "The card must hold exactly the imported pair");
  }

  private javax.smartcardio.ResponseAPDU importElement(int tag, byte[] value) {
    return transmit(
        0x84, 0x24, ALG_ECC_P256, KEY_MANAGEMENT, tlv((byte) 0x30, tlv((byte) tag, value)));
  }

  private static byte[] importableKeyDefinition() {
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
      ALG_ECC_P256,
      (byte) 0x8F,
      0x01,
      0x02,
      (byte) 0x90,
      0x01,
      0x10
    };
  }

  private static KeyPair p256KeyPair() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    return generator.generateKeyPair();
  }

  private static byte[] point(ECPublicKey key) {
    return concat(
        new byte[] {0x04},
        fixed(key.getW().getAffineX(), FIELD_BYTES),
        fixed(key.getW().getAffineY(), FIELD_BYTES));
  }

  private static byte[] scalar(ECPrivateKey key) {
    return fixed(key.getS(), FIELD_BYTES);
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
