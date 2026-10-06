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
      byte id, byte modeContact, byte modeContactless, byte mechanism, byte role, byte attributes) {
    // SP 800-73-5 Part 1 Table 5 fixes each standard key reference's contact and contactless
    // security conditions. Compatibility builds retain issuer-specific access policies.
    // #if FIPS_MODE
    if (!allowsKeyAccessModes(id, modeContact, modeContactless)) {
      return false;
    }
    // #endif
    return allowsKeyDefinition(id, mechanism, role, attributes);
  }

  static boolean allowsKeyDefinition(byte id, byte mechanism, byte role, byte attributes) {
    // SP 800-78-5 Section 3.1: a VCI-capable card with a P-384 digital-signature,
    // key-management, or retired key-management key must use the P-384 secure-messaging suite.
    // #if VCI_CS2
    if (ENABLED
        && mechanism == PIV.ID_ALG_ECC_P384
        && (id == (byte) 0x9C || id == (byte) 0x9D || PIV.isRetiredKeyManagementKey(id))) {
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
      // The attestation authority is generated on the card in every profile so the issuer can
      // certify that its private key never existed outside the card.
      return mechanism == PIV.ID_ALG_ECC_P256
          && role == PIVKeyObject.ROLE_SIGN
          && (attributes & PIVKeyObject.ATTR_IMPORTABLE) == 0;
    }

    if (id == PIVObject.DEFAULT_ADMIN_KEY) {
      return isAllowedManagementMechanism(mechanism)
          && role == PIVKeyObject.ROLE_AUTHENTICATE
          && (attributes & PIVKeyObject.ATTR_PERMIT_INTERNAL) == 0;
    }

    if (PIV.isRetiredKeyManagementKey(id)) {
      // SP 800-78-5 Table 10 retains RSA-1024 identifier 06 only for retired
      // key-management references. The FIPS profile deliberately omits RSA-1024 compatibility.
      return (isCardholderAsymmetric(mechanism) || (!ENABLED && mechanism == PIV.ID_ALG_RSA_1024))
          && role == PIVKeyObject.ROLE_KEY_ESTABLISH;
    }

    if (id == (byte) 0x9D) {
      return isCardholderAsymmetric(mechanism) && role == PIVKeyObject.ROLE_KEY_ESTABLISH;
    }

    if (id == (byte) 0x9A || id == (byte) 0x9C) {
      // FIPS 201-3 Section 4.2.2.1: the PIV authentication key "SHALL be generated on the PIV
      // Card." Section 4.2.2.4: "The PIV digital signature key SHALL be generated on the PIV
      // Card." The FIPS profile therefore refuses importable definitions for both references.
      return isCardholderAsymmetric(mechanism)
          && role == PIVKeyObject.ROLE_SIGN
          && (!ENABLED || (attributes & PIVKeyObject.ATTR_IMPORTABLE) == 0);
    }

    if (id == (byte) 0x9E) {
      return isCardholderAsymmetric(mechanism) && role == PIVKeyObject.ROLE_SIGN;
    }

    // SP 800-73-5 Part 1 Table 5 and SP 800-78-5 Table 10 reserve all other PIV key references.
    // Compatibility builds retain the dynamically-defined keystore extension.
    return !ENABLED;
  }

  // #if FIPS_MODE
  private static boolean allowsKeyAccessModes(byte id, byte contact, byte contactless) {
    if (id == PIV.ID_KEY_ATTESTATION) {
      return accessMatches(
          contact, contactless, PIVObject.ACCESS_MODE_NEVER, PIVObject.ACCESS_MODE_NEVER);
    }
    if (id == PIV.ID_KEY_SECURE_MESSAGING || id == (byte) 0x9E) {
      return accessMatches(
          contact, contactless, PIVObject.ACCESS_MODE_ALWAYS, PIVObject.ACCESS_MODE_ALWAYS);
    }
    if (id == PIVObject.DEFAULT_ADMIN_KEY) {
      return accessMatches(
          contact, contactless, PIVObject.ACCESS_MODE_ALWAYS, PIVObject.ACCESS_MODE_NEVER);
    }
    if (id == (byte) 0x9C) {
      return accessMatches(
          contact,
          contactless,
          PIVObject.ACCESS_MODE_PIN_ALWAYS,
          (byte) (PIVObject.ACCESS_MODE_VCI | PIVObject.ACCESS_MODE_PIN_ALWAYS));
    }
    if (id == (byte) 0x9A || id == (byte) 0x9D || PIV.isRetiredKeyManagementKey(id)) {
      return accessMatches(
          contact,
          contactless,
          PIVObject.ACCESS_MODE_PIN,
          (byte) (PIVObject.ACCESS_MODE_VCI | PIVObject.ACCESS_MODE_PIN));
    }
    return false;
  }
  // #endif

  static boolean allowsObjectDefinition(
      byte[] id, short offset, short length, byte contact, byte contactless) {
    // #if FIPS_MODE
    if (length == (short) 1 && id[offset] == (byte) 0x7E) {
      return accessMatches(
          contact, contactless, PIVObject.ACCESS_MODE_ALWAYS, PIVObject.ACCESS_MODE_ALWAYS);
    }
    if (length == (short) 2
        && id[offset] == (byte) 0x7F
        && id[(short) (offset + 1)] == (byte) 0x61) {
      return accessMatches(
          contact, contactless, PIVObject.ACCESS_MODE_ALWAYS, PIVObject.ACCESS_MODE_ALWAYS);
    }
    if (length != (short) 3
        || id[offset] != (byte) 0x5F
        || id[(short) (offset + 1)] != (byte) 0xC1) {
      // Apply SP 800-73-5 Part 1 Section 4.2 Table 3 only within the
      // interoperable PIV namespace.
      return true;
    }

    byte suffix = id[(short) (offset + 2)];
    if (suffix == (byte) 0x02 || suffix == (byte) 0x01 || suffix == (byte) 0x22) {
      return accessMatches(
          contact, contactless, PIVObject.ACCESS_MODE_ALWAYS, PIVObject.ACCESS_MODE_ALWAYS);
    }
    if (suffix == (byte) 0x03 || suffix == (byte) 0x08 || suffix == (byte) 0x21) {
      return accessMatches(
          contact,
          contactless,
          PIVObject.ACCESS_MODE_PIN,
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
      return accessMatches(
          contact, contactless, PIVObject.ACCESS_MODE_ALWAYS, PIVObject.ACCESS_MODE_VCI);
    }
    return false;
    // #else
    return true;
    // #endif
  }

  /**
   * Returns whether {@code capacity} meets the container minimum for an interoperable object.
   *
   * <p>SP 800-73-5 Part 1 Appendix A Table 8, footnote 17: "The values in this column denote the
   * guaranteed minimum capacities of the on-card storage containers in bytes." The FIPS profile
   * guarantees them at CREATE OBJECT time. Compatibility builds and objects outside Table 8 accept
   * any positive capacity.
   */
  static boolean allowsObjectCapacity(byte[] id, short offset, short length, short capacity) {
    // #if FIPS_MODE
    return capacity >= minimumObjectCapacity(id, offset, length);
    // #else
    return true;
    // #endif
  }

  // #if FIPS_MODE
  /** Returns the SP 800-73-5 Part 1 Table 8 minimum container capacity, or zero when none. */
  static short minimumObjectCapacity(byte[] id, short offset, short length) {
    if (length == (short) 1 && id[offset] == (byte) 0x7E) return (short) 19;
    if (length == (short) 2
        && id[offset] == (byte) 0x7F
        && id[(short) (offset + 1)] == (byte) 0x61) {
      return (short) 65;
    }
    if (length != (short) 3
        || id[offset] != (byte) 0x5F
        || id[(short) (offset + 1)] != (byte) 0xC1) {
      return (short) 0;
    }
    byte suffix = id[(short) (offset + 2)];
    if (suffix >= (byte) 0x0D && suffix <= (byte) 0x20) return (short) 1895;
    switch (suffix) {
      case (byte) 0x07:
        return (short) 170;
      case (byte) 0x02:
        return (short) 2881;
      case (byte) 0x05:
      case (byte) 0x01:
      case (byte) 0x0A:
      case (byte) 0x0B:
        return (short) 1857;
      case (byte) 0x03:
        return (short) 4006;
      case (byte) 0x06:
        return (short) 1336;
      case (byte) 0x08:
        return (short) 12710;
      case (byte) 0x09:
        return (short) 245;
      case (byte) 0x0C:
        return (short) 128;
      case (byte) 0x21:
        return (short) 7106;
      case (byte) 0x22:
        return (short) 2471;
      case (byte) 0x23:
        return (short) 12;
      default:
        return (short) 0;
    }
  }

  private static boolean accessMatches(
      byte contact, byte contactless, byte expectedContact, byte expectedContactless) {
    return contact == expectedContact && contactless == expectedContactless;
  }
  // #endif

  private static boolean isAes(byte mechanism) {
    return mechanism == PIV.ID_ALG_AES_128
        || mechanism == PIV.ID_ALG_AES_192
        || mechanism == PIV.ID_ALG_AES_256;
  }

  private static boolean isAllowedManagementMechanism(byte mechanism) {
    return isAes(mechanism)
        || (!ENABLED && (mechanism == PIV.ID_ALG_DEFAULT || mechanism == PIV.ID_ALG_TDEA_3KEY));
  }

  private static boolean isCardholderAsymmetric(byte mechanism) {
    return mechanism == PIV.ID_ALG_RSA_2048
        || mechanism == PIV.ID_ALG_RSA_3072
        || mechanism == PIV.ID_ALG_ECC_P256
        || mechanism == PIV.ID_ALG_ECC_P384;
  }
}
