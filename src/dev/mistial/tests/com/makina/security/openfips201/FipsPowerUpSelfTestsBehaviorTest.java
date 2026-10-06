package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import javax.crypto.KeyAgreement;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import pro.javacard.engine.JavaCardEngine;

class FipsPowerUpSelfTestsBehaviorTest {
  private static final boolean FIPS_MODE = Boolean.getBoolean("fips.mode");
  private JavaCardEngine engine;
  private PIVCrypto crypto;

  @BeforeEach
  void initializeCryptoProvider() throws Exception {
    engine = JavaCardEngine.create();
    try (AutoCloseable ignored = enterEngineContext()) {
      crypto = new PIVCrypto();
    }
  }

  @Test
  void compiledProfileKnownAnswersPass() throws Exception {
    // FIPS 140-3 IG 10.3.A requires CASTs before first use of each approved
    // cryptographic function implemented inside the module boundary.
    try (AutoCloseable ignored = enterEngineContext()) {
      assertTrue(newSelfTests().run(new byte[FipsPowerUpSelfTests.LENGTH_SCRATCH]));
    }
  }

  @Test
  void incorrectKnownAnswerFailsClosed() throws Exception {
    assertCorruptedVectorFails("AES_ENCRYPT_ZERO");
  }

  @Test
  void incorrectAesDecryptKnownAnswerFailsClosed() throws Exception {
    assertCorruptedVectorFails("AES_DECRYPT_PLAINTEXT");
  }

  /**
   * Each FIPS-profile asymmetric CAST must detect a wrong known answer. ECC_P256_PUBLIC corrupts
   * the verification key (loaded at install), so the self-test object is built after corruption.
   */
  @ParameterizedTest
  @ValueSource(
      strings = {
        "ECDSA_SIGNATURE",
        "ECC_CDH_Z",
        "ECC_CDH_PEER",
        "ECC_P256_PUBLIC",
        "RSA_SIGNATURE",
        "RSA_PRIVATE_EXPONENT"
      })
  void incorrectAsymmetricKnownAnswerFailsClosed(String vector) throws Exception {
    assumeTrue(FIPS_MODE, "asymmetric CASTs are compiled into the FIPS profile only");
    // Corrupt a byte away from the DER header and the point-format byte.
    assertCorruptedVectorFails(vector, 20);
  }

  /** The vectors are recomputed independently with BouncyCastle and BigInteger arithmetic. */
  @Test
  void asymmetricVectorsMatchIndependentComputation() throws Exception {
    assumeTrue(FIPS_MODE, "asymmetric CASTs are compiled into the FIPS profile only");
    java.security.Provider bc = new BouncyCastleProvider();
    java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("EC", bc);
    generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
    ECParameterSpec spec = ((ECPublicKey) generator.generateKeyPair().getPublic()).getParams();
    KeyFactory factory = KeyFactory.getInstance("EC", bc);

    BigInteger d = new BigInteger(1, vector("ECC_P256_PRIVATE"));
    java.security.PrivateKey privateKey = factory.generatePrivate(new ECPrivateKeySpec(d, spec));
    PublicKey publicKey =
        factory.generatePublic(new ECPublicKeySpec(point(vector("ECC_P256_PUBLIC")), spec));
    PublicKey peer =
        factory.generatePublic(new ECPublicKeySpec(point(vector("ECC_CDH_PEER")), spec));

    KeyAgreement agreement = KeyAgreement.getInstance("ECDH", bc);
    agreement.init(privateKey);
    agreement.doPhase(peer, true);
    assertArrayEquals(vector("ECC_CDH_Z"), agreement.generateSecret());

    java.security.Signature verifier = java.security.Signature.getInstance("NONEwithECDSA", bc);
    verifier.initVerify(publicKey);
    verifier.update(MessageDigest.getInstance("SHA-256").digest("abc".getBytes("US-ASCII")));
    assertTrue(verifier.verify(vector("ECDSA_SIGNATURE")));
    assertArrayEquals(
        MessageDigest.getInstance("SHA-256").digest("abc".getBytes("US-ASCII")),
        vector("SHA256_ABC"));

    BigInteger n = new BigInteger(1, vector("RSA_MODULUS"));
    BigInteger e = new BigInteger(1, vector("RSA_PUBLIC_EXPONENT"));
    BigInteger privateExponent = new BigInteger(1, vector("RSA_PRIVATE_EXPONENT"));
    byte[] message = new byte[256];
    for (int index = 0; index < message.length; index++) {
      message[index] = (byte) index;
    }
    BigInteger m = new BigInteger(1, message);
    BigInteger s = new BigInteger(1, vector("RSA_SIGNATURE"));
    assertEquals(s, m.modPow(privateExponent, n));
    assertEquals(m, s.modPow(e, n));
  }

  private void assertCorruptedVectorFails(String name) throws Exception {
    assertCorruptedVectorFails(name, 0);
  }

  private void assertCorruptedVectorFails(String name, int index) throws Exception {
    byte[] expected = vector(name);
    byte original = expected[index];
    expected[index] ^= (byte) 1;
    try {
      try (AutoCloseable ignored = enterEngineContext()) {
        assertFalse(newSelfTests().run(new byte[FipsPowerUpSelfTests.LENGTH_SCRATCH]));
      }
    } finally {
      expected[index] = original;
    }
  }

  private FipsPowerUpSelfTests newSelfTests() {
    return new FipsPowerUpSelfTests(crypto, new ECCurveRegistry(), new ECPointValidator());
  }

  private static byte[] vector(String name) throws Exception {
    Field field = FipsPowerUpSelfTests.class.getDeclaredField(name);
    field.setAccessible(true);
    return (byte[]) field.get(null);
  }

  private static ECPoint point(byte[] encoded) {
    int coordinate = (encoded.length - 1) / 2;
    return new ECPoint(
        new BigInteger(1, Arrays.copyOfRange(encoded, 1, 1 + coordinate)),
        new BigInteger(1, Arrays.copyOfRange(encoded, 1 + coordinate, encoded.length)));
  }

  private AutoCloseable enterEngineContext() throws Exception {
    Method asCurrent = engine.getClass().getMethod("asCurrent");
    return (AutoCloseable) asCurrent.invoke(engine);
  }
}
