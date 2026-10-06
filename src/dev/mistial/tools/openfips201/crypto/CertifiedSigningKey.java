/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.crypto;

import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * A {@link SigningKey} bound to the certificate that names it.
 *
 * <p>Contract: construction succeeds only when the certificate's SubjectPublicKeyInfo is byte-equal
 * to the signer's public key and a fresh random challenge signed by the signer verifies under the
 * certificate's public key. {@link #publicKey()} and {@link #certificate()} then return the
 * certificate's values, and {@link #sign(String, byte[])} delegates to the signer.
 */
public final class CertifiedSigningKey implements SigningKey {
  private static final int CHALLENGE_LENGTH = 32;

  private final SigningKey signer;
  private final X509Certificate certificate;

  public CertifiedSigningKey(SigningKey signer, X509Certificate certificate) throws Exception {
    if (certificate == null) {
      throw new IllegalArgumentException(signer.description() + " has no certificate");
    }
    PublicKey certified = certificate.getPublicKey();
    if (!Arrays.equals(certified.getEncoded(), signer.publicKey().getEncoded())) {
      throw new IllegalArgumentException(
          "Certificate public key does not match signing key " + signer.description());
    }
    String algorithm = challengeAlgorithm(certified);
    byte[] challenge = new byte[CHALLENGE_LENGTH];
    new SecureRandom().nextBytes(challenge);
    byte[] signature = signer.sign(algorithm, challenge);
    CryptoProviders.ensureBouncyCastle();
    Signature verifier = Signature.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
    verifier.initVerify(certified);
    verifier.update(challenge);
    if (!verifier.verify(signature)) {
      throw new IllegalArgumentException(
          "Signing key " + signer.description() + " failed the certificate challenge");
    }
    this.signer = signer;
    this.certificate = certificate;
  }

  /** Binds {@code signer} to the certificate it carries ({@link SigningKey#certificate()}). */
  public static CertifiedSigningKey of(SigningKey signer) throws Exception {
    return new CertifiedSigningKey(signer, signer.certificate());
  }

  @Override
  public PublicKey publicKey() {
    return certificate.getPublicKey();
  }

  @Override
  public byte[] sign(String jcaAlgorithm, byte[] message) throws Exception {
    return signer.sign(jcaAlgorithm, message);
  }

  @Override
  public String description() {
    return signer.description();
  }

  @Override
  public X509Certificate certificate() {
    return certificate;
  }

  private static String challengeAlgorithm(PublicKey key) {
    if (!(key instanceof ECPublicKey)) {
      throw new IllegalArgumentException("Certified signing key must be an EC key");
    }
    int fieldSize = ((ECPublicKey) key).getParams().getCurve().getField().getFieldSize();
    return fieldSize > 256 ? "SHA384withECDSA" : "SHA256withECDSA";
  }
}
