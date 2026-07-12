/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

public class Pkcs11AesCmacService {
  public byte[] sign(Pkcs11Config config, byte[] message) {
    try (Pkcs11Token token = Pkcs11Token.open(config)) {
      return token.sign(
          Pkcs11Constants.CKM_AES_CMAC,
          token.findSecretAesKey(config.keyAlias, config.keyId),
          message);
    }
  }
}
