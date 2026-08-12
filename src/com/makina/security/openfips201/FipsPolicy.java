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

  static boolean allowsKeyDefinition(byte id, byte mechanism, byte role, byte attributes) {
    if (id == PIV.ID_KEY_SECURE_MESSAGING) {
      return mechanism == PIV.ID_ALG_ECC_SM && role == PIVKeyObject.ROLE_KEY_ESTABLISH;
    }

    if (id == PIV.ID_KEY_ATTESTATION) {
      return mechanism == PIV.ID_ALG_ECC_P256 && role == PIVKeyObject.ROLE_SIGN;
    }

    if (id == (byte) 0x9B) {
      return isAllowedManagementMechanism(mechanism)
          && role == PIVKeyObject.ROLE_AUTHENTICATE
          && (attributes & PIVKeyObject.ATTR_PERMIT_INTERNAL) == 0;
    }

    if (isRetiredKeyManagement(id) || id == (byte) 0x9D) {
      return isAllowedCardholderAsymmetric(mechanism)
          && role == PIVKeyObject.ROLE_KEY_ESTABLISH;
    }

    if (id == (byte) 0x9A || id == (byte) 0x9C || id == (byte) 0x9E) {
      return isAllowedCardholderAsymmetric(mechanism) && role == PIVKeyObject.ROLE_SIGN;
    }

    return false;
  }

  private static boolean isAes(byte mechanism) {
    return mechanism == PIV.ID_ALG_AES_128
        || mechanism == PIV.ID_ALG_AES_192
        || mechanism == PIV.ID_ALG_AES_256;
  }

  private static boolean isAllowedManagementMechanism(byte mechanism) {
    return isAes(mechanism)
        || (!ENABLED
            && (mechanism == PIV.ID_ALG_DEFAULT || mechanism == PIV.ID_ALG_TDEA_3KEY));
  }

  private static boolean isAllowedCardholderAsymmetric(byte mechanism) {
    return isCardholderAsymmetric(mechanism)
        || (!ENABLED && mechanism == PIV.ID_ALG_RSA_1024);
  }

  private static boolean isCardholderAsymmetric(byte mechanism) {
    return mechanism == PIV.ID_ALG_RSA_2048
        || mechanism == PIV.ID_ALG_RSA_3072
        || mechanism == PIV.ID_ALG_ECC_P256
        || mechanism == PIV.ID_ALG_ECC_P384;
  }

  private static boolean isRetiredKeyManagement(byte id) {
    return id >= (byte) 0x82 && id <= (byte) 0x95;
  }
}
