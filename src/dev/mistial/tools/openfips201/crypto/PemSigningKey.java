/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.crypto;

import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;

public final class PemSigningKey implements SigningKey {
  private final PrivateKey privateKey;
  private final PublicKey publicKey;
  private final String description;

  public PemSigningKey(Path keyPath, Path certificatePath, char[] passphrase) throws Exception {
    this.privateKey = PemFiles.readPrivateKey(keyPath, passphrase);
    X509Certificate certificate = PemFiles.readCertificate(certificatePath);
    this.publicKey = certificate.getPublicKey();
    this.description = "pem:" + keyPath;
  }

  public PemSigningKey(PrivateKey privateKey, PublicKey publicKey, String description) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.description = description;
  }

  @Override
  public PublicKey publicKey() {
    return publicKey;
  }

  @Override
  public byte[] sign(String jcaAlgorithm, byte[] message) throws Exception {
    Signature signer = Signature.getInstance(jcaAlgorithm);
    signer.initSign(privateKey);
    signer.update(message);
    return signer.sign();
  }

  @Override
  public String description() {
    return description;
  }
}
