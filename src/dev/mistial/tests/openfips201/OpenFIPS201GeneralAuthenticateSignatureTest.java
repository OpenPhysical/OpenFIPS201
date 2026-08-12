package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Confirms the ECC digital-signature contract for GENERAL AUTHENTICATE.
 *
 * <p>SP 800-78-5 Table 2 permits only ECDSA P-256 with SHA-256 and P-384 with SHA-384, so the
 * applet provides no ECDSA-SHA1 or ECDSA-SHA512 engine. This test proves the observable invariant:
 * a P-256 key signs a 32-byte (SHA-256) digest and refuses the 20-byte (SHA-1) and 64-byte
 * (SHA-512) sizes, so no off-spec ECDSA signature can ever be produced.
 */
@Timeout(value = 10, unit = TimeUnit.SECONDS)
class OpenFIPS201GeneralAuthenticateSignatureTest extends OpenFIPS201TestSupport {

  private static final byte ALG_ECC_P256 = (byte) 0x11;
  private static final byte ALG_ECC_P384 = (byte) 0x14;
  private static final byte ALG_RSA_2048 = (byte) 0x07;
  private static final byte ALG_RSA_3072 = (byte) 0x05;
  private static final byte SLOT_AUTHENTICATION = (byte) 0x9A;
  private static final byte SLOT_SIGNATURE = (byte) 0x9C;
  private static final byte SLOT_CARD_AUTHENTICATION = (byte) 0x9E;
  private static final byte ROLE_KEY_ESTABLISH = (byte) 0x02;
  private static final byte ROLE_SIGN = (byte) 0x04;
  private static final int P256_FIELD_BYTES = 32;
  private static final int P384_FIELD_BYTES = 48;

  @BeforeAll
  static void installProvider() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  void eccSignsSha256DigestButRejectsSha1AndSha512Sizes() throws Exception {
    byte[] publicPoint = provisionEccSignKey(SLOT_SIGNATURE);

    // 32 bytes: the only ECDSA digest size SP 800-78 permits for P-256. Must sign and verify.
    byte[] digest = filled(P256_FIELD_BYTES, (byte) 0xA5);
    ResponseAPDU signed =
        transmit(
            new CommandAPDU(
                0x00, 0x87, ALG_ECC_P256 & 0xFF, SLOT_SIGNATURE & 0xFF, signTemplate(digest), 256));
    byte[] inner =
        tlvValue(collect(signed, "ECC sign over a 32-byte digest must succeed"), (byte) 0x7C);
    byte[] signature = tlvValue(inner, (byte) 0x82);
    assertTrue(signature.length > 0, "A signature must be returned for the curve-sized digest");
    assertTrue(
        verifiesEcdsa(publicPoint, digest, signature),
        "Returned signature must verify as ECDSA over the 32-byte digest");

    // 20 bytes (SHA-1) and 64 bytes (SHA-512): not PIV ECDSA digest sizes; no signature may result.
    verifyLocalPin();
    assertSw(
        0x6A80,
        transmit(
            0x00,
            0x87,
            ALG_ECC_P256 & 0xFF,
            SLOT_SIGNATURE & 0xFF,
            signTemplate(filled(20, (byte) 0x5A))),
        "ECC must not sign a 20-byte (SHA-1) digest");
    verifyLocalPin();
    assertSw(
        0x6A80,
        transmit(
            0x00,
            0x87,
            ALG_ECC_P256 & 0xFF,
            SLOT_SIGNATURE & 0xFF,
            signTemplate(filled(64, (byte) 0x5A))),
        "ECC must not sign a 64-byte (SHA-512) digest");
  }

  @Test
  void p384SignsSha384Digest() throws Exception {
    assumeFalse(
        Boolean.getBoolean("fips.mode")
            && "CS2".equalsIgnoreCase(System.getProperty("vci.suite", "CS2")),
        "SP 800-78-5 requires CS7 when a VCI-capable FIPS profile uses P-384 slot 9C");
    byte[] publicPoint = provisionEccKey(SLOT_SIGNATURE, ROLE_SIGN, ALG_ECC_P384);
    byte[] digest = filled(P384_FIELD_BYTES, (byte) 0x6D);

    byte[] response =
        collect(
            transmit(
                new CommandAPDU(
                    0x00,
                    0x87,
                    ALG_ECC_P384 & 0xFF,
                    SLOT_SIGNATURE & 0xFF,
                    signTemplate(digest),
                    256)),
            "P-384 sign over a SHA-384-sized digest must succeed");
    byte[] signature = tlvValue(tlvValue(response, (byte) 0x7C), (byte) 0x82);
    assertTrue(
        verifiesEcdsa(publicPoint, digest, signature),
        "Returned signature must verify as P-384 ECDSA over the supplied digest");
  }

  @Test
  void rsa2048RawSignatureMatchesGeneratedPublicKey() {
    assertRsaRawSignature(SLOT_SIGNATURE, (byte) 0x02, (byte) 0x0A, ALG_RSA_2048, 256);
  }

  @Test
  void rsa3072RawSignatureMatchesGeneratedPublicKey() {
    assertRsaRawSignature(SLOT_SIGNATURE, (byte) 0x02, (byte) 0x0A, ALG_RSA_3072, 384);
  }

  @Test
  void rsa2048SigningWorksAtEverySigningKeyReference() {
    assertRsaRawSignature(SLOT_AUTHENTICATION, (byte) 0x01, (byte) 0x09, ALG_RSA_2048, 256);
    assertRsaRawSignature(SLOT_CARD_AUTHENTICATION, (byte) 0x7F, (byte) 0x7F, ALG_RSA_2048, 256);
  }

  private void assertRsaRawSignature(
      final byte slot,
      final byte modeContact,
      final byte modeContactless,
      final byte algorithm,
      final int blockLength) {
    final byte[][] publicComponents = new byte[2][];
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before RSA signing-key provisioning");
          byte[] definition =
              new byte[] {
                (byte) 0x66,
                (byte) 0x12,
                (byte) 0x8B,
                (byte) 0x01,
                slot,
                (byte) 0x8C,
                (byte) 0x01,
                modeContact,
                (byte) 0x8D,
                (byte) 0x01,
                modeContactless,
                (byte) 0x8E,
                (byte) 0x01,
                algorithm,
                (byte) 0x8F,
                (byte) 0x01,
                ROLE_SIGN,
                (byte) 0x90,
                (byte) 0x01,
                (byte) 0x10
              };
          assertSw(0x9000, transmit(0x84, 0xDB, 0x3F, 0x00, definition), "Create RSA sign key");
          byte[] generated =
              collect(
                  transmit(
                      0x84,
                      0x47,
                      0x00,
                      slot & 0xFF,
                      new byte[] {(byte) 0xAC, 0x03, (byte) 0x80, 0x01, algorithm},
                      256),
                  "GENERATE RSA sign key");
          publicComponents[0] = tlvValue(generated, (byte) 0x81);
          publicComponents[1] = tlvValue(generated, (byte) 0x82);
        });

    if (slot != SLOT_CARD_AUTHENTICATION) verifyLocalPin();
    byte[] representative = filled(blockLength, (byte) 0x5C);
    representative[0] = 0;
    byte[] request = signTemplate(representative);
    byte[] first = Arrays.copyOfRange(request, 0, 200);
    byte[] last = Arrays.copyOfRange(request, 200, request.length);
    assertSw(
        0x9000,
        transmit(0x10, 0x87, algorithm & 0xFF, slot & 0xFF, first),
        "First chained RSA signature fragment");
    byte[] response =
        collect(
            transmit(new CommandAPDU(0x00, 0x87, algorithm & 0xFF, slot & 0xFF, last, 256)),
            "RSA raw private-key operation must succeed");
    byte[] signature = tlvValue(tlvValue(response, (byte) 0x7C), (byte) 0x82);

    BigInteger modulus = new BigInteger(1, publicComponents[0]);
    BigInteger exponent = new BigInteger(1, publicComponents[1]);
    byte[] recovered = fixed(new BigInteger(1, signature).modPow(exponent, modulus), blockLength);
    assertTrue(
        Arrays.equals(representative, recovered),
        "RSA public operation must recover the exact supplied representative");
  }

  @Test
  void rejectsMismatchedPrivateRotationAndRetainsTheOriginalPair() throws Exception {
    byte[] publicPoint = provisionEccSignKey(SLOT_SIGNATURE);
    KeyPairGenerator generator =
        KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair mismatch = generator.generateKeyPair();
    byte[] privateScalar = fixed(((ECPrivateKey) mismatch.getPrivate()).getS(), P256_FIELD_BYTES);

    withMockedScp(
        () ->
            assertSw(
                0x6985,
                transmit(
                    0x84,
                    0x24,
                    ALG_ECC_P256 & 0xFF,
                    SLOT_SIGNATURE & 0xFF,
                    tlv((byte) 0x30, tlv((byte) 0x87, privateScalar))),
                "A private component that mismatches a live public key must be rejected"));

    verifyLocalPin();
    byte[] digest = filled(P256_FIELD_BYTES, (byte) 0x3C);
    byte[] response =
        collect(
            transmit(
                new CommandAPDU(
                    0x00,
                    0x87,
                    ALG_ECC_P256 & 0xFF,
                    SLOT_SIGNATURE & 0xFF,
                    signTemplate(digest),
                    256)),
            "The original key must remain usable after a rejected rotation");
    byte[] signature = tlvValue(tlvValue(response, (byte) 0x7C), (byte) 0x82);
    assertTrue(
        verifiesEcdsa(publicPoint, digest, signature),
        "The retained private key must still match the advertised public key");
  }

  @Test
  void dualRoleEccKeyIsRejected() {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before dual-role key rejection");
          byte[] definition =
              new byte[] {
                (byte) 0x66,
                (byte) 0x12,
                (byte) 0x8B,
                (byte) 0x01,
                SLOT_SIGNATURE,
                (byte) 0x8C,
                (byte) 0x01,
                (byte) 0x02,
                (byte) 0x8D,
                (byte) 0x01,
                (byte) 0x0A,
                (byte) 0x8E,
                (byte) 0x01,
                ALG_ECC_P256,
                (byte) 0x8F,
                (byte) 0x01,
                (byte) (ROLE_SIGN | ROLE_KEY_ESTABLISH),
                (byte) 0x90,
                (byte) 0x01,
                (byte) 0x10
              };
          assertSw(
              0x6A80,
              transmit(0x84, 0xDB, 0x3F, 0x00, definition),
              "ECC keys must not combine signing and key-establishment roles");
        });
  }

  private byte[] provisionEccSignKey(final byte slot) {
    return provisionEccKey(slot, ROLE_SIGN);
  }

  private byte[] provisionEccKey(final byte slot, final byte roles) {
    return provisionEccKey(slot, roles, ALG_ECC_P256);
  }

  private byte[] provisionEccKey(final byte slot, final byte roles, final byte algorithm) {
    final byte[][] publicPoint = new byte[1][];
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before key provisioning");
          byte[] definition =
              new byte[] {
                (byte) 0x66,
                (byte) 0x12,
                (byte) 0x8B,
                (byte) 0x01,
                slot,
                (byte) 0x8C,
                (byte) 0x01,
                (byte) 0x02,
                (byte) 0x8D,
                (byte) 0x01,
                (byte) 0x0A,
                (byte) 0x8E,
                (byte) 0x01,
                algorithm,
                (byte) 0x8F,
                (byte) 0x01,
                roles,
                (byte) 0x90,
                (byte) 0x01,
                (byte) 0x10
              };
          assertSw(0x9000, transmit(0x84, 0xDB, 0x3F, 0x00, definition), "Create ECC sign key");
          byte[] generated =
              collect(
                  transmit(
                      0x84,
                      0x47,
                      0x00,
                      slot & 0xFF,
                      new byte[] {(byte) 0xAC, 0x03, (byte) 0x80, 0x01, algorithm},
                      256),
                  "GENERATE ECC sign key");
          publicPoint[0] = tlvValue(generated, (byte) 0x86);
        });
    verifyLocalPin();
    return publicPoint[0];
  }

  private void verifyLocalPin() {
    assertSw(
        0x9000,
        transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN),
        "VERIFY immediately before signature use");
  }

  private byte[] signTemplate(byte[] digest) {
    // 7C { 82 00 (response placeholder) 81 <len> <to-be-signed digest> } selects digital signature.
    return tlv((byte) 0x7C, concat(tlv((byte) 0x82, new byte[0]), tlv((byte) 0x81, digest)));
  }

  private byte[] collect(ResponseAPDU response, String context) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ResponseAPDU current = response;
    while ((current.getSW() & 0xFF00) == 0x6100) {
      out.write(current.getData(), 0, current.getData().length);
      int le = current.getSW2() == 0 ? 256 : current.getSW2();
      current = transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00, le));
    }
    assertSw(0x9000, current, context);
    out.write(current.getData(), 0, current.getData().length);
    return out.toByteArray();
  }

  private static byte[] filled(int length, byte value) {
    byte[] buffer = new byte[length];
    Arrays.fill(buffer, value);
    return buffer;
  }

  private static byte[] fixed(BigInteger value, int length) {
    byte[] encoded = value.toByteArray();
    byte[] result = new byte[length];
    int sourceOffset = Math.max(0, encoded.length - length);
    int copyLength = Math.min(encoded.length, length);
    System.arraycopy(encoded, sourceOffset, result, length - copyLength, copyLength);
    return result;
  }

  private static boolean verifiesEcdsa(byte[] uncompressedPoint, byte[] digest, byte[] derSignature)
      throws Exception {
    int fieldBytes = (uncompressedPoint.length - 1) / 2;
    String curveName;
    if (fieldBytes == P256_FIELD_BYTES) {
      curveName = "secp256r1";
    } else if (fieldBytes == P384_FIELD_BYTES) {
      curveName = "secp384r1";
    } else {
      throw new IllegalArgumentException(
          "Unsupported EC point length: " + uncompressedPoint.length);
    }
    AlgorithmParameters parameters =
        AlgorithmParameters.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
    parameters.init(new ECGenParameterSpec(curveName));
    ECParameterSpec ecSpec = parameters.getParameterSpec(ECParameterSpec.class);

    byte[] x = new byte[fieldBytes];
    byte[] y = new byte[fieldBytes];
    System.arraycopy(uncompressedPoint, 1, x, 0, fieldBytes);
    System.arraycopy(uncompressedPoint, 1 + fieldBytes, y, 0, fieldBytes);
    ECPoint w = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
    PublicKey publicKey =
        KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
            .generatePublic(new ECPublicKeySpec(w, ecSpec));

    // The card signs a pre-computed digest, so verify the raw digest with NONEwithECDSA.
    Signature verifier = Signature.getInstance("NONEwithECDSA", BouncyCastleProvider.PROVIDER_NAME);
    verifier.initVerify(publicKey);
    verifier.update(digest);
    return verifier.verify(derSignature);
  }
}
