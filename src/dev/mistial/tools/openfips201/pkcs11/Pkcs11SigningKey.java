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

public final class Pkcs11SigningKey implements SigningKey {
  private final Pkcs11Config config;
  private final PublicKey publicKey;
  private final String description;

  public Pkcs11SigningKey(Pkcs11Config config) throws Exception {
    this.config = config.copy();
    try (Pkcs11Token token = Pkcs11Token.open(this.config)) {
      Pkcs11Token.KeyHandle key = token.findPrivateKey(this.config);
      byte[] certificateDer = token.findCertificateValue(key, this.config.keyAlias);
      X509Certificate certificate =
          (X509Certificate)
              CertificateFactory.getInstance("X.509")
                  .generateCertificate(new ByteArrayInputStream(certificateDer));
      this.publicKey = certificate.getPublicKey();
      this.description = "pkcs11:" + keyDescription(this.config);
    }
  }

  @Override
  public PublicKey publicKey() {
    return publicKey;
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
    try (Pkcs11Token token = Pkcs11Token.open(config)) {
      raw =
          token.sign(
              Pkcs11Constants.CKM_ECDSA,
              token.findPrivateKey(config),
              digest);
    }
    return derEncodeEcdsa(raw, coordinateLength);
  }

  @Override
  public String description() {
    return description;
  }

  static byte[] derEncodeEcdsa(byte[] raw, int coordinateLength) throws Exception {
    if (raw.length != coordinateLength * 2) {
      throw new IllegalArgumentException(
          "ECDSA signature length " + raw.length + " does not match expected raw length "
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
