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

  static boolean allowsKeyDefinition(
      byte id,
      byte modeContact,
      byte modeContactless,
      byte mechanism,
      byte role,
      byte attributes) {
    // SP 800-73-5 Part 1 Table 5 fixes each standard key reference's contact and contactless
    // security conditions. Compatibility builds retain issuer-specific access policies.
    if (ENABLED && !allowsKeyAccessModes(id, modeContact, modeContactless)) {
      return false;
    }
    return allowsKeyDefinition(id, mechanism, role, attributes);
  }

  static boolean allowsKeyDefinition(byte id, byte mechanism, byte role, byte attributes) {
    // SP 800-78-5 Section 3.1: a VCI-capable card with a P-384 digital-signature,
    // key-management, or retired key-management key must use the P-384 secure-messaging suite.
    // #if VCI_CS2
    if (mechanism == PIV.ID_ALG_ECC_P384
        && (id == (byte) 0x9C || id == (byte) 0x9D || isRetiredKeyManagement(id))) {
      return false;
    }
    // #endif

    if (id == PIV.ID_KEY_SECURE_MESSAGING) {
      // SP 800-73-5 Part 1 Section 5.1.2 requires key 04 to be generated on-card and
      // non-exportable. The CVC remains loadable through its dedicated element exception.
      return mechanism == PIV.ID_ALG_ECC_SM
          && role == PIVKeyObject.ROLE_KEY_ESTABLISH
          && (attributes & PIVKeyObject.ATTR_IMPORTABLE) == 0;
    }

    if (id == PIV.ID_KEY_ATTESTATION) {
      return mechanism == PIV.ID_ALG_ECC_P256 && role == PIVKeyObject.ROLE_SIGN;
    }

    if (id == (byte) 0x9B) {
      return isAllowedManagementMechanism(mechanism)
          && role == PIVKeyObject.ROLE_AUTHENTICATE
          && (attributes & PIVKeyObject.ATTR_PERMIT_INTERNAL) == 0;
    }

    if (isRetiredKeyManagement(id)) {
      // SP 800-78-5 Table 10 retains RSA-1024 identifier 06 only for retired
      // key-management references. FIPS mode deliberately omits that legacy compatibility.
      return (isCardholderAsymmetric(mechanism)
              || (!ENABLED && mechanism == PIV.ID_ALG_RSA_1024))
          && role == PIVKeyObject.ROLE_KEY_ESTABLISH;
    }

    if (id == (byte) 0x9D) {
      return isCardholderAsymmetric(mechanism) && role == PIVKeyObject.ROLE_KEY_ESTABLISH;
    }

    if (id == (byte) 0x9A || id == (byte) 0x9C || id == (byte) 0x9E) {
      return isCardholderAsymmetric(mechanism) && role == PIVKeyObject.ROLE_SIGN;
    }

    return false;
  }

  private static boolean allowsKeyAccessModes(byte id, byte contact, byte contactless) {
    if (id == PIV.ID_KEY_ATTESTATION) {
      return accessMatches(contact, contactless, PIVObject.ACCESS_MODE_NEVER,
          PIVObject.ACCESS_MODE_NEVER);
    }
    if (id == PIV.ID_KEY_SECURE_MESSAGING || id == (byte) 0x9E) {
      return accessMatches(contact, contactless, PIVObject.ACCESS_MODE_ALWAYS,
          PIVObject.ACCESS_MODE_ALWAYS);
    }
    if (id == (byte) 0x9B) {
      return accessMatches(contact, contactless, PIVObject.ACCESS_MODE_ALWAYS,
          PIVObject.ACCESS_MODE_NEVER);
    }
    if (id == (byte) 0x9C) {
      return accessMatches(
          contact,
          contactless,
          PIVObject.ACCESS_MODE_PIN_ALWAYS,
          (byte) (PIVObject.ACCESS_MODE_VCI | PIVObject.ACCESS_MODE_PIN_ALWAYS));
    }
    if (id == (byte) 0x9A || id == (byte) 0x9D || isRetiredKeyManagement(id)) {
      return accessMatches(
          contact,
          contactless,
          PIVObject.ACCESS_MODE_PIN,
          (byte) (PIVObject.ACCESS_MODE_VCI | PIVObject.ACCESS_MODE_PIN));
    }
    return false;
  }

  static boolean allowsObjectDefinition(
      byte[] id, short offset, short length, byte contact, byte contactless) {
    if (!ENABLED) return true;

    if (length == (short) 1 && id[offset] == (byte) 0x7E) {
      return accessMatches(contact, contactless, PIVObject.ACCESS_MODE_ALWAYS,
          PIVObject.ACCESS_MODE_ALWAYS);
    }
    if (length == (short) 2
        && id[offset] == (byte) 0x7F
        && id[(short) (offset + 1)] == (byte) 0x61) {
      return accessMatches(contact, contactless, PIVObject.ACCESS_MODE_ALWAYS,
          PIVObject.ACCESS_MODE_ALWAYS);
    }
    if (length != (short) 3
        || id[offset] != (byte) 0x5F
        || id[(short) (offset + 1)] != (byte) 0xC1) {
      // SP 800-73-5 Part 1, Section 4.2 and Table 3 reserve every other PIV
      // interoperable data-object tag. Compatibility builds retain issuer extensions.
      return false;
    }

    byte suffix = id[(short) (offset + 2)];
    if (suffix == (byte) 0x02 || suffix == (byte) 0x01 || suffix == (byte) 0x22) {
      return accessMatches(contact, contactless, PIVObject.ACCESS_MODE_ALWAYS,
          PIVObject.ACCESS_MODE_ALWAYS);
    }
    if (suffix == (byte) 0x03 || suffix == (byte) 0x08 || suffix == (byte) 0x21) {
      return accessMatches(contact, contactless, PIVObject.ACCESS_MODE_PIN,
          (byte) (PIVObject.ACCESS_MODE_VCI | PIVObject.ACCESS_MODE_PIN));
    }
    if (suffix == (byte) 0x09 || suffix == (byte) 0x23) {
      return accessMatches(
          contact,
          contactless,
          PIVObject.ACCESS_MODE_PIN,
          (byte) (PIVObject.ACCESS_MODE_VCI | PIVObject.ACCESS_MODE_PIN));
    }
    if (suffix == (byte) 0x07
        || suffix == (byte) 0x05
        || suffix == (byte) 0x06
        || suffix == (byte) 0x0A
        || suffix == (byte) 0x0B
        || suffix == (byte) 0x0C
        || (suffix >= (byte) 0x0D && suffix <= (byte) 0x20)) {
      return accessMatches(contact, contactless, PIVObject.ACCESS_MODE_ALWAYS,
          PIVObject.ACCESS_MODE_VCI);
    }
    return false;
  }

  private static boolean accessMatches(
      byte contact, byte contactless, byte expectedContact, byte expectedContactless) {
    return contact == expectedContact && contactless == expectedContactless;
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
