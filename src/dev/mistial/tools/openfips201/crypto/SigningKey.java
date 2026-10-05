/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.crypto;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

public interface SigningKey {
  PublicKey publicKey();

  byte[] sign(String jcaAlgorithm, byte[] message) throws Exception;

  String description();

  /**
   * Returns the certificate stored with this key, or {@code null} when the key source carries none.
   * The certificate is not checked against the key here; {@link CertifiedSigningKey} does that.
   */
  default X509Certificate certificate() {
    return null;
  }
}
