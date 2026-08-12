/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2017 Commonwealth of Australia
 ******************************************************************************/

package com.makina.security.openfips201;

/** Compile-time immutable policy for the platform-bound FIPS candidate profile. */
final class FipsPolicy {
  // #if FIPS_MODE
  static final boolean ENABLED = true;
  // #else
  static final boolean ENABLED = false;
  // #endif

  private FipsPolicy() {}

  static boolean allowsMechanism(byte mechanism) {
    if (!ENABLED) return true;
    switch (mechanism) {
      case PIV.ID_ALG_AES_128:
      case PIV.ID_ALG_AES_192:
      case PIV.ID_ALG_AES_256:
      case PIV.ID_ALG_RSA_2048:
      case PIV.ID_ALG_RSA_3072:
      case PIV.ID_ALG_ECC_P256:
      case PIV.ID_ALG_ECC_P384:
      case PIV.ID_ALG_ECC_CS2:
      case PIV.ID_ALG_ECC_CS7:
        return true;
      default:
        return false;
    }
  }
}
