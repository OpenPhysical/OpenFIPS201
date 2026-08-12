/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.crypto;

import java.security.PublicKey;

public interface SigningKey {
  PublicKey publicKey();

  byte[] sign(String jcaAlgorithm, byte[] message) throws Exception;

  String description();
}
