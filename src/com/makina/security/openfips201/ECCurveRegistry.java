/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2017 Commonwealth of Australia
 ******************************************************************************/

package com.makina.security.openfips201;

/** Install-allocated registry for the immutable supported EC domain parameters. */
final class ECCurveRegistry {
  private final ECParams p256;
  private final ECParams p384;

  ECCurveRegistry() {
    p256 = new ECParamsP256();
    p384 = new ECParamsP384();
  }

  ECParams forMechanism(byte mechanism) {
    switch (mechanism) {
      case PIV.ID_ALG_ECC_P256:
      case PIV.ID_ALG_ECC_CS2:
        return p256;
      case PIV.ID_ALG_ECC_P384:
      case PIV.ID_ALG_ECC_CS7:
        return p384;
      default:
        return null;
    }
  }
}
