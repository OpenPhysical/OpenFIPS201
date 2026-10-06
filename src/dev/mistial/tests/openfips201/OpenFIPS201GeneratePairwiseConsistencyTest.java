package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.lang.reflect.Method;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javacard.framework.ISO7816;
import javacard.security.CryptoException;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.stubbing.Answer;

/**
 * A key pair generated on the card that fails its pair-wise consistency test is an internal fault:
 * GENERATE ASYMMETRIC KEY PAIR returns ISO/IEC 7816-4 '6F00' (no precise diagnosis) and no key
 * material of the failed pair remains usable.
 *
 * <p>The FIPS profile runs the test on every generated cardholder key. The attestation authority F9
 * runs it in every profile, because its public key is certified by the issuer. The failure is
 * forced by intercepting the installed applet instance's {@code PIVCrypto} through {@link
 * AppletCryptoInterceptor}.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class OpenFIPS201GeneratePairwiseConsistencyTest extends OpenFIPS201TestSupport {
  private static final byte ALG_RSA_2048 = (byte) 0x07;
  private static final byte ALG_ECC_P256 = (byte) 0x11;
  private static final byte KEY_MANAGEMENT = (byte) 0x9D;
  private static final byte KEY_ATTESTATION = (byte) 0xF9;
  private static final byte ROLE_KEY_ESTABLISH = (byte) 0x02;
  private static final byte[] F9_DEFINITION = hex("6612 8B01F9 8C0100 8D0100 8E0111 8F0104 900100");
  private static final String FIPS_ONLY =
      "Cardholder keys run the generation consistency test only in the FIPS profile";

  @Test
  void eccKeyAgreementPairFailingItsConsistencyTestIsDiscarded() throws Exception {
    assumeTrue(Boolean.getBoolean("fips.mode"), FIPS_ONLY);
    defineKeyManagementKey(ALG_ECC_P256);

    AtomicInteger calls = new AtomicInteger();
    try (AutoCloseable crypto =
        interceptCrypto("pairwiseAgreementTest", calls, invocation -> Boolean.FALSE)) {
      assertGenerateFails(ALG_ECC_P256, "ECDH consistency failure");
    }
    assertEquals(1, calls.get(), "The ECDH consistency test must run once");
    assertKeyManagementKeyUnusable(ALG_ECC_P256, keyAgreementRequest());

    assertGenerateSucceeds(ALG_ECC_P256);
    assertSw(
        0x9000,
        transmit(0x00, 0x87, ALG_ECC_P256, KEY_MANAGEMENT & 0xFF, keyAgreementRequest()),
        "A consistent regenerated pair performs key establishment");
  }

  @Test
  void rsaPairWhosePublicOperationDoesNotRecoverTheBlockIsDiscarded() throws Exception {
    assumeTrue(Boolean.getBoolean("fips.mode"), FIPS_ONLY);
    defineKeyManagementKey(ALG_RSA_2048);

    AtomicInteger calls = new AtomicInteger();
    try (AutoCloseable crypto =
        interceptCrypto(
            "doRsaPublic",
            calls,
            invocation -> {
              // The public operation recovers a block other than the signed test block.
              short length = (Short) invocation.callRealMethod();
              byte[] out = invocation.getArgument(4);
              short outOffset = invocation.getArgument(5);
              out[(short) (outOffset + length - 1)] ^= (byte) 0x01;
              return length;
            })) {
      assertGenerateFails(ALG_RSA_2048, "RSA consistency mismatch");
    }
    assertEquals(1, calls.get(), "The RSA consistency test must run once");
    assertKeyManagementKeyUnusable(ALG_RSA_2048, rsaKeyTransportRequest());

    assertGenerateSucceeds(ALG_RSA_2048);
  }

  @Test
  void rsaPairWhoseConsistencySignatureFaultsIsDiscarded() throws Exception {
    assumeTrue(Boolean.getBoolean("fips.mode"), FIPS_ONLY);
    defineKeyManagementKey(ALG_RSA_2048);

    AtomicInteger calls = new AtomicInteger();
    try (AutoCloseable crypto =
        interceptCrypto(
            "doSign",
            calls,
            invocation -> {
              if (!(invocation.getArgument(0) instanceof javacard.security.RSAPrivateKey)) {
                return invocation.callRealMethod();
              }
              throw new CryptoException(CryptoException.ILLEGAL_USE);
            })) {
      assertGenerateFails(ALG_RSA_2048, "RSA consistency signature fault");
    }
    assertTrue(calls.get() >= 1, "The RSA consistency signature must be attempted");
    assertKeyManagementKeyUnusable(ALG_RSA_2048, rsaKeyTransportRequest());
  }

  /** F9 runs the consistency test in every profile; a failure leaves no generated authority. */
  @Test
  void attestationAuthorityFailingItsConsistencyTestIsDiscarded() throws Exception {
    assumeTrue(isAttestationEnabledBuild(), "F9 exists only in attestation builds");
    final byte[] nonce = new byte[32];
    AtomicInteger calls = new AtomicInteger();
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before F9 definition");
          assertSw(0x9000, transmit(0x84, 0xDB, 0xFF, 0xFF, F9_DEFINITION), "Define F9");
          try (AutoCloseable crypto =
              interceptCrypto("doVerify", calls, invocation -> Boolean.FALSE)) {
            assertSw(
                ISO7816.SW_UNKNOWN,
                transmit(0x84, 0x47, 0x00, KEY_ATTESTATION & 0xFF, hex("AC03800111"), 256),
                "F9 consistency failure");
          } catch (Exception e) {
            throw new IllegalStateException(e);
          }
          assertSw(
              ISO7816.SW_CONDITIONS_NOT_SATISFIED,
              transmit(0x84, 0xF9, 0xF9, 0x01, nonce, 256),
              "No generated F9 key remains to prove possession");
          collectResponse(
              transmit(0x84, 0x47, 0x00, KEY_ATTESTATION & 0xFF, hex("AC03800111"), 256),
              "A consistent F9 pair is generated");
          assertSw(
              0x9000,
              transmit(0x84, 0xF9, 0xF9, 0x01, nonce, 256),
              "The regenerated F9 key proves possession");
        });
    assertEquals(1, calls.get(), "The F9 consistency test must run once");
  }

  private void defineKeyManagementKey(final byte mechanism) {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before key definition");
          assertSw(
              0x9000,
              transmit(
                  0x84,
                  0xDB,
                  0xFF,
                  0xFF,
                  new byte[] {
                    0x66,
                    0x12,
                    (byte) 0x8B,
                    0x01,
                    KEY_MANAGEMENT,
                    (byte) 0x8C,
                    0x01,
                    0x01,
                    (byte) 0x8D,
                    0x01,
                    0x09,
                    (byte) 0x8E,
                    0x01,
                    mechanism,
                    (byte) 0x8F,
                    0x01,
                    ROLE_KEY_ESTABLISH,
                    (byte) 0x90,
                    0x01,
                    0x00
                  }),
              "Define the key-management key");
        });
  }

  private void assertGenerateFails(final byte mechanism, final String context) {
    withMockedScp(
        () ->
            assertSw(
                ISO7816.SW_UNKNOWN,
                transmit(0x84, 0x47, 0x00, KEY_MANAGEMENT & 0xFF, generateRequest(mechanism), 256),
                context + " is an internal fault"));
  }

  private void assertGenerateSucceeds(final byte mechanism) {
    withMockedScp(
        () ->
            collectResponse(
                transmit(0x84, 0x47, 0x00, KEY_MANAGEMENT & 0xFF, generateRequest(mechanism), 256),
                "Regenerate a consistent pair"));
  }

  /** PRE-CONDITION 4 of GENERAL AUTHENTICATE: a key without key material is '6A86'. */
  private void assertKeyManagementKeyUnusable(byte mechanism, byte[] request) {
    assertSw(0x9000, selectApplet(), "SELECT before key use");
    assertSw(0x9000, transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN), "VERIFY");
    ResponseAPDU response =
        transmitChained(0x00, 0x87, mechanism & 0xFF, KEY_MANAGEMENT & 0xFF, request);
    assertSw(
        ISO7816.SW_INCORRECT_P1P2, response, "No key material of the failed pair may be usable");
  }

  private static byte[] generateRequest(byte mechanism) {
    return new byte[] {(byte) 0xAC, 0x03, (byte) 0x80, 0x01, mechanism};
  }

  private static byte[] keyAgreementRequest() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    ECPublicKey key = (ECPublicKey) generator.generateKeyPair().getPublic();
    byte[] point =
        concat(
            new byte[] {0x04},
            unsigned(key.getW().getAffineX().toByteArray(), 32),
            unsigned(key.getW().getAffineY().toByteArray(), 32));
    return tlv((byte) 0x7C, concat(tlv((byte) 0x82, new byte[0]), tlv((byte) 0x85, point)));
  }

  private static byte[] rsaKeyTransportRequest() {
    byte[] block = new byte[256];
    block[255] = 0x01;
    return tlv((byte) 0x7C, concat(tlv((byte) 0x82, new byte[0]), tlv((byte) 0x81, block)));
  }

  private static byte[] unsigned(byte[] encoded, int length) {
    byte[] result = new byte[length];
    int sourceOffset = Math.max(0, encoded.length - length);
    int copyLength = Math.min(encoded.length, length);
    System.arraycopy(encoded, sourceOffset, result, length - copyLength, copyLength);
    return result;
  }

  /**
   * Intercepts the installed applet's {@code PIVCrypto}: calls to the named method are counted and
   * answered by {@code answer}; every other method runs unchanged.
   */
  private AutoCloseable interceptCrypto(
      final String name, final AtomicInteger calls, final Answer<Object> answer) throws Exception {
    return AppletCryptoInterceptor.intercept(
        AppletCryptoInterceptor.unwrap(engine.getApplet(OPENFIPS201_AID)),
        invocation -> {
          Method method = invocation.getMethod();
          if (!method.getName().equals(name)) return invocation.callRealMethod();
          calls.incrementAndGet();
          return answer.answer(invocation);
        });
  }
}
