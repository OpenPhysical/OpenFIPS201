/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

import dev.mistial.tools.openfips201.crypto.SigningKey;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;

/**
 * EC private key on a PKCS#11 token, with the certificate stored beside it (same CKA_ID, or the
 * same label when the key has no CKA_ID).
 *
 * <p>Contract: a key created from a {@link Pkcs11Session} signs on that session and never opens
 * another; it is unusable after the session is closed. A key created from a {@link Pkcs11Config}
 * opens, logs in and closes its own session for each operation.
 */
public final class Pkcs11SigningKey implements SigningKey {
  private final Pkcs11Config config;
  private final Pkcs11Session session;
  private final Pkcs11Token.KeyHandle key;
  private final X509Certificate certificate;
  private final String description;

  public Pkcs11SigningKey(Pkcs11Config config) throws Exception {
    this.config = config.copy();
    this.session = null;
    this.key = null;
    try (Pkcs11Token token = Pkcs11Token.open(this.config)) {
      this.certificate = readCertificate(token, token.findPrivateKey(this.config), this.config);
    }
    this.description = "pkcs11:" + keyDescription(this.config);
  }

  Pkcs11SigningKey(Pkcs11Session session, Pkcs11Config selection) throws Exception {
    this.config = selection.copy();
    this.session = session;
    Pkcs11Token token = session.token();
    this.key = token.findPrivateKey(this.config);
    this.certificate = readCertificate(token, key, this.config);
    this.description = "pkcs11:" + keyDescription(this.config);
  }

  @Override
  public PublicKey publicKey() {
    return certificate.getPublicKey();
  }

  @Override
  public X509Certificate certificate() {
    return certificate;
  }

  @Override
  public byte[] sign(String jcaAlgorithm, byte[] message) throws Exception {
    String digestName;
    int coordinateLength;
    if ("SHA256withECDSA".equals(jcaAlgorithm)) {
      digestName = "SHA-256";
      coordinateLength = 32;
    } else if ("SHA384withECDSA".equals(jcaAlgorithm)) {
      digestName = "SHA-384";
      coordinateLength = 48;
    } else {
      throw new IllegalArgumentException("Unsupported PKCS#11 signing algorithm: " + jcaAlgorithm);
    }

    byte[] digest = MessageDigest.getInstance(digestName).digest(message);
    byte[] raw;
    if (session != null) {
      raw = session.token().sign(Pkcs11Constants.CKM_ECDSA, key, digest);
    } else {
      try (Pkcs11Token token = Pkcs11Token.open(config)) {
        raw = token.sign(Pkcs11Constants.CKM_ECDSA, token.findPrivateKey(config), digest);
      }
    }
    return derEncodeEcdsa(raw, coordinateLength);
  }

  @Override
  public String description() {
    return description;
  }

  private static X509Certificate readCertificate(
      Pkcs11Token token, Pkcs11Token.KeyHandle key, Pkcs11Config config) throws Exception {
    byte[] certificateDer = token.findCertificateValue(key, config.keyAlias);
    return (X509Certificate)
        CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(certificateDer));
  }

  static byte[] derEncodeEcdsa(byte[] raw, int coordinateLength) throws Exception {
    if (raw.length != coordinateLength * 2) {
      throw new IllegalArgumentException(
          "ECDSA signature length "
              + raw.length
              + " does not match expected raw length "
              + (coordinateLength * 2));
    }
    byte[] r = Arrays.copyOfRange(raw, 0, coordinateLength);
    byte[] s = Arrays.copyOfRange(raw, coordinateLength, coordinateLength * 2);
    ASN1EncodableVector sequence = new ASN1EncodableVector();
    sequence.add(new ASN1Integer(new BigInteger(1, r)));
    sequence.add(new ASN1Integer(new BigInteger(1, s)));
    return new DERSequence(sequence).getEncoded();
  }

  private static String keyDescription(Pkcs11Config config) {
    if (config.keyAlias != null && !config.keyAlias.isEmpty()) {
      return config.keyAlias;
    }
    if (config.keyId != null && !config.keyId.isEmpty()) {
      return "id:" + config.keyId;
    }
    return "selected-key";
  }
}
