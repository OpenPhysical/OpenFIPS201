package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertTrue;

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
  private static final byte SLOT_SIGNATURE = (byte) 0x9C;
  private static final byte ROLE_KEY_ESTABLISH = (byte) 0x02;
  private static final byte ROLE_SIGN = (byte) 0x04;
  private static final int P256_FIELD_BYTES = 32;

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
  void rejectsMismatchedPrivateRotationAndRetainsTheOriginalPair() throws Exception {
    byte[] publicPoint = provisionEccSignKey(SLOT_SIGNATURE);
    KeyPairGenerator generator =
        KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair mismatch = generator.generateKeyPair();
    byte[] privateScalar =
        fixed(((ECPrivateKey) mismatch.getPrivate()).getS(), P256_FIELD_BYTES);

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
                ALG_ECC_P256,
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
                  transmit(0x84, 0x47, 0x00, slot & 0xFF, hex("AC03800111"), 256),
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
    AlgorithmParameters parameters =
        AlgorithmParameters.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
    parameters.init(new ECGenParameterSpec("secp256r1"));
    ECParameterSpec ecSpec = parameters.getParameterSpec(ECParameterSpec.class);

    byte[] x = new byte[P256_FIELD_BYTES];
    byte[] y = new byte[P256_FIELD_BYTES];
    System.arraycopy(uncompressedPoint, 1, x, 0, P256_FIELD_BYTES);
    System.arraycopy(uncompressedPoint, 1 + P256_FIELD_BYTES, y, 0, P256_FIELD_BYTES);
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
