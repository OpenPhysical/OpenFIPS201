/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.crypto;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.operator.ContentSigner;

/**
 * Bouncy Castle {@link ContentSigner} over a {@link SigningKey}.
 *
 * <p>Contract: the bytes written to {@link #getOutputStream()} are signed once, by {@link
 * #getSignature()}, with {@code SHA256withECDSA} (AlgorithmIdentifier ecdsa-with-SHA256, RFC 5758
 * section 3.2, parameters absent) or {@code SHA384withECDSA} (ecdsa-with-SHA384). The signature is
 * the DER ECDSA-Sig-Value returned by the key.
 */
public final class SigningKeyContentSigner implements ContentSigner {
  private final SigningKey signer;
  private final String jcaAlgorithm;
  private final AlgorithmIdentifier algorithm;
  private final ByteArrayOutputStream out = new ByteArrayOutputStream();

  /**
   * @param jcaAlgorithm {@code SHA256withECDSA} or {@code SHA384withECDSA}
   */
  public SigningKeyContentSigner(SigningKey signer, String jcaAlgorithm) {
    this.signer = signer;
    this.jcaAlgorithm = jcaAlgorithm;
    this.algorithm = new AlgorithmIdentifier(oid(jcaAlgorithm));
  }

  /** ecdsa-with-SHA256. */
  public static SigningKeyContentSigner sha256(SigningKey signer) {
    return new SigningKeyContentSigner(signer, "SHA256withECDSA");
  }

  @Override
  public AlgorithmIdentifier getAlgorithmIdentifier() {
    return algorithm;
  }

  @Override
  public OutputStream getOutputStream() {
    return out;
  }

  @Override
  public byte[] getSignature() {
    try {
      return signer.sign(jcaAlgorithm, out.toByteArray());
    } catch (Exception e) {
      throw new IllegalStateException("Signing failed with " + signer.description(), e);
    }
  }

  private static ASN1ObjectIdentifier oid(String jcaAlgorithm) {
    if ("SHA256withECDSA".equals(jcaAlgorithm)) {
      return X9ObjectIdentifiers.ecdsa_with_SHA256;
    }
    if ("SHA384withECDSA".equals(jcaAlgorithm)) {
      return X9ObjectIdentifiers.ecdsa_with_SHA384;
    }
    throw new IllegalArgumentException(
        "Unsupported certificate signing algorithm: " + jcaAlgorithm);
  }
}
