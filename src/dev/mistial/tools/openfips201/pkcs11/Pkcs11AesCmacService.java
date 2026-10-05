/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

/**
 * AES-CMAC under a token-resident AES key selected by {@code keyAlias}/{@code keyId}.
 *
 * <p>Contract: a service created with a {@link Pkcs11Session} computes every CMAC on that session
 * and requires each config to name the session's token; the no-argument service opens, logs in and
 * closes a session for each CMAC.
 */
public class Pkcs11AesCmacService {
  private final Pkcs11Session session;

  public Pkcs11AesCmacService() {
    this.session = null;
  }

  public Pkcs11AesCmacService(Pkcs11Session session) {
    if (session == null) {
      throw new IllegalArgumentException("PKCS#11 session is required");
    }
    this.session = session;
  }

  public byte[] sign(Pkcs11Config config, byte[] message) {
    if (session != null) {
      session.requireSameToken(config);
      return session.aesCmac(config.keyAlias, config.keyId, message);
    }
    try (Pkcs11Token token = Pkcs11Token.open(config)) {
      return token.sign(
          Pkcs11Constants.CKM_AES_CMAC,
          token.findSecretAesKey(config.keyAlias, config.keyId),
          message);
    }
  }
}
