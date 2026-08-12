package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class FipsPolicyTest {
  private static final byte[] ACCESS_MODES = {
    PIVObject.ACCESS_MODE_NEVER,
    PIVObject.ACCESS_MODE_PIN,
    PIVObject.ACCESS_MODE_PIN_ALWAYS,
    PIVObject.ACCESS_MODE_OCC,
    PIVObject.ACCESS_MODE_VCI,
    (byte) (PIVObject.ACCESS_MODE_VCI | PIVObject.ACCESS_MODE_PIN),
    (byte) (PIVObject.ACCESS_MODE_VCI | PIVObject.ACCESS_MODE_PIN_ALWAYS),
    PIVObject.ACCESS_MODE_USER_ADMIN,
    PIVObject.ACCESS_MODE_ALWAYS
  };

  @Test
  void strictProfileProtectsPart1Namespace() {
    byte always = PIVObject.ACCESS_MODE_ALWAYS;
    assertEquals(
        !FipsPolicy.ENABLED,
        FipsPolicy.allowsObjectDefinition(
            new byte[] {(byte) 0x5F, (byte) 0xC1, (byte) 0x04},
            (short) 0,
            (short) 3,
            always,
            always),
        "5FC104 is reserved by SP 800-73-5 Part 1 Table 3");
    assertTrue(
        FipsPolicy.allowsObjectDefinition(
            new byte[] {(byte) 0xDF, (byte) 0x01},
            (short) 0,
            (short) 2,
            always,
            always),
        "Table 3 validation is scoped to the interoperable PIV namespace");
    assertTrue(
        FipsPolicy.allowsObjectDefinition(
            new byte[] {(byte) 0x5F, (byte) 0xC1, (byte) 0x07},
            (short) 0,
            (short) 3,
            always,
            PIVObject.ACCESS_MODE_VCI));
  }

  @Test
  void rsa1024CompatibilityIsRetiredKeyOnly() {
    assertEquals(
        !FipsPolicy.ENABLED,
        FipsPolicy.allowsKeyDefinition(
            (byte) 0x82,
            PIVObject.ACCESS_MODE_ALWAYS,
            PIVObject.ACCESS_MODE_NEVER,
            PIV.ID_ALG_RSA_1024,
            PIVKeyObject.ROLE_KEY_ESTABLISH,
            PIVKeyObject.ATTR_IMPORTABLE));
    assertFalse(
        FipsPolicy.allowsKeyDefinition(
            (byte) 0x9A,
            PIVObject.ACCESS_MODE_ALWAYS,
            PIVObject.ACCESS_MODE_NEVER,
            PIV.ID_ALG_RSA_1024,
            PIVKeyObject.ROLE_SIGN,
            PIVKeyObject.ATTR_IMPORTABLE));
    assertFalse(
        FipsPolicy.allowsKeyDefinition(
            (byte) 0x9C,
            PIVObject.ACCESS_MODE_ALWAYS,
            PIVObject.ACCESS_MODE_NEVER,
            PIV.ID_ALG_RSA_1024,
            PIVKeyObject.ROLE_SIGN,
            PIVKeyObject.ATTR_IMPORTABLE));
    assertFalse(
        FipsPolicy.allowsKeyDefinition(
            (byte) 0x9D,
            PIVObject.ACCESS_MODE_ALWAYS,
            PIVObject.ACCESS_MODE_NEVER,
            PIV.ID_ALG_RSA_1024,
            PIVKeyObject.ROLE_KEY_ESTABLISH,
            PIVKeyObject.ATTR_IMPORTABLE));
    assertFalse(
        FipsPolicy.allowsKeyDefinition(
            (byte) 0x9E,
            PIVObject.ACCESS_MODE_ALWAYS,
            PIVObject.ACCESS_MODE_NEVER,
            PIV.ID_ALG_RSA_1024,
            PIVKeyObject.ROLE_SIGN,
            PIVKeyObject.ATTR_IMPORTABLE));
  }

  @Test
  void secureMessagingKeyMustBeGeneratedOnCard() {
    assertTrue(
        FipsPolicy.allowsKeyDefinition(
            PIV.ID_KEY_SECURE_MESSAGING,
            PIVObject.ACCESS_MODE_ALWAYS,
            PIVObject.ACCESS_MODE_ALWAYS,
            PIV.ID_ALG_ECC_SM,
            PIVKeyObject.ROLE_KEY_ESTABLISH,
            PIVKeyObject.ATTR_NONE));
    assertFalse(
        FipsPolicy.allowsKeyDefinition(
            PIV.ID_KEY_SECURE_MESSAGING,
            PIVObject.ACCESS_MODE_ALWAYS,
            PIVObject.ACCESS_MODE_ALWAYS,
            PIV.ID_ALG_ECC_SM,
            PIVKeyObject.ROLE_KEY_ESTABLISH,
            PIVKeyObject.ATTR_IMPORTABLE));
  }

  @Test
  void p384VciKeysRequireCs7() {
    boolean cs7 = "CS7".equalsIgnoreCase(System.getProperty("vci.suite", "CS2"));

    assertEquals(
        !FipsPolicy.ENABLED || cs7,
        FipsPolicy.allowsKeyDefinition(
            (byte) 0x9C,
            PIVObject.ACCESS_MODE_PIN_ALWAYS,
            (byte) (PIVObject.ACCESS_MODE_VCI | PIVObject.ACCESS_MODE_PIN_ALWAYS),
            PIV.ID_ALG_ECC_P384,
            PIVKeyObject.ROLE_SIGN,
            PIVKeyObject.ATTR_IMPORTABLE));
    assertEquals(
        !FipsPolicy.ENABLED || cs7,
        FipsPolicy.allowsKeyDefinition(
            (byte) 0x9D,
            PIVObject.ACCESS_MODE_PIN,
            (byte) (PIVObject.ACCESS_MODE_VCI | PIVObject.ACCESS_MODE_PIN),
            PIV.ID_ALG_ECC_P384,
            PIVKeyObject.ROLE_KEY_ESTABLISH,
            PIVKeyObject.ATTR_IMPORTABLE));
    assertEquals(
        !FipsPolicy.ENABLED || cs7,
        FipsPolicy.allowsKeyDefinition(
            (byte) 0x82,
            PIVObject.ACCESS_MODE_PIN,
            (byte) (PIVObject.ACCESS_MODE_VCI | PIVObject.ACCESS_MODE_PIN),
            PIV.ID_ALG_ECC_P384,
            PIVKeyObject.ROLE_KEY_ESTABLISH,
            PIVKeyObject.ATTR_IMPORTABLE));
  }

  @Test
  void customKeyReferencesAreCompatibilityOnly() {
    assertEquals(
        !FipsPolicy.ENABLED,
        FipsPolicy.allowsKeyDefinition(
            (byte) 0xA0,
            PIVObject.ACCESS_MODE_ALWAYS,
            PIVObject.ACCESS_MODE_NEVER,
            PIV.ID_ALG_ECC_P256,
            PIVKeyObject.ROLE_SIGN,
            PIVKeyObject.ATTR_IMPORTABLE));
  }

  @Test
  void fipsKeyAccessModesFollowTableFive() {
    assertEquals(
        !FipsPolicy.ENABLED,
        FipsPolicy.allowsKeyDefinition(
            (byte) 0x9A,
            PIVObject.ACCESS_MODE_ALWAYS,
            PIVObject.ACCESS_MODE_NEVER,
            PIV.ID_ALG_ECC_P256,
            PIVKeyObject.ROLE_SIGN,
            PIVKeyObject.ATTR_IMPORTABLE));
    assertTrue(
        FipsPolicy.allowsKeyDefinition(
            (byte) 0x9A,
            PIVObject.ACCESS_MODE_PIN,
            (byte) (PIVObject.ACCESS_MODE_VCI | PIVObject.ACCESS_MODE_PIN),
            PIV.ID_ALG_ECC_P256,
            PIVKeyObject.ROLE_SIGN,
            PIVKeyObject.ATTR_IMPORTABLE));
    assertTrue(
        FipsPolicy.allowsKeyDefinition(
            PIV.ID_KEY_SECURE_MESSAGING,
            PIVObject.ACCESS_MODE_ALWAYS,
            PIVObject.ACCESS_MODE_ALWAYS,
            PIV.ID_ALG_ECC_SM,
            PIVKeyObject.ROLE_KEY_ESTABLISH,
            PIVKeyObject.ATTR_NONE));
    assertEquals(
        !FipsPolicy.ENABLED,
        FipsPolicy.allowsKeyDefinition(
            PIV.ID_KEY_SECURE_MESSAGING,
            PIVObject.ACCESS_MODE_ALWAYS,
            PIVObject.ACCESS_MODE_NEVER,
            PIV.ID_ALG_ECC_SM,
            PIVKeyObject.ROLE_KEY_ESTABLISH,
            PIVKeyObject.ATTR_NONE));
  }

  @Test
  void objectPolicyDoesNotOpenReservedPivTags() {
    assertTrue(
        FipsPolicy.allowsObjectDefinition(
            new byte[] {(byte) 0x5F, (byte) 0xFF, (byte) 0x01},
            (short) 0,
            (short) 3,
            PIVObject.ACCESS_MODE_ALWAYS,
            PIVObject.ACCESS_MODE_NEVER));
    assertEquals(
        !FipsPolicy.ENABLED,
        FipsPolicy.allowsObjectDefinition(
            new byte[] {(byte) 0x5F, (byte) 0xC1, (byte) 0x5A},
            (short) 0,
            (short) 3,
            PIVObject.ACCESS_MODE_ALWAYS,
            PIVObject.ACCESS_MODE_NEVER));
  }

  @Test
  void everyPartOneObjectAcceptsOnlyItsTableThreeAccessPair() {
    assertExactObjectAccess(new byte[] {(byte) 0x7E}, modeAlways(), modeAlways());
    assertExactObjectAccess(new byte[] {(byte) 0x7F, (byte) 0x61}, modeAlways(), modeAlways());

    for (int suffix : new int[] {0x01, 0x02, 0x22}) {
      assertExactObjectAccess(pivObject(suffix), modeAlways(), modeAlways());
    }
    for (int suffix : new int[] {0x03, 0x08, 0x09, 0x21, 0x23}) {
      assertExactObjectAccess(
          pivObject(suffix), modePin(), (byte) (modeVci() | modePin()));
    }
    for (int suffix = 0x05; suffix <= 0x20; suffix++) {
      if (suffix == 0x08 || suffix == 0x09) continue;
      assertExactObjectAccess(pivObject(suffix), modeAlways(), modeVci());
    }
  }

  @Test
  void everyPartOneKeyAcceptsOnlyItsTableFiveAccessPair() {
    assertExactKeyAccess(
        PIV.ID_KEY_SECURE_MESSAGING,
        PIV.ID_ALG_ECC_SM,
        PIVKeyObject.ROLE_KEY_ESTABLISH,
        PIVKeyObject.ATTR_NONE,
        modeAlways(),
        modeAlways());
    assertExactKeyAccess(
        PIV.ID_KEY_ATTESTATION,
        PIV.ID_ALG_ECC_P256,
        PIVKeyObject.ROLE_SIGN,
        PIVKeyObject.ATTR_NONE,
        PIVObject.ACCESS_MODE_NEVER,
        PIVObject.ACCESS_MODE_NEVER);
    assertExactKeyAccess(
        (byte) 0x9B,
        PIV.ID_ALG_AES_128,
        PIVKeyObject.ROLE_AUTHENTICATE,
        PIVKeyObject.ATTR_IMPORTABLE,
        modeAlways(),
        PIVObject.ACCESS_MODE_NEVER);
    assertExactKeyAccess(
        (byte) 0x9C,
        PIV.ID_ALG_RSA_2048,
        PIVKeyObject.ROLE_SIGN,
        PIVKeyObject.ATTR_IMPORTABLE,
        PIVObject.ACCESS_MODE_PIN_ALWAYS,
        (byte) (modeVci() | PIVObject.ACCESS_MODE_PIN_ALWAYS));
    for (byte key : new byte[] {(byte) 0x9A, (byte) 0x9D}) {
      assertExactKeyAccess(
          key,
          PIV.ID_ALG_RSA_2048,
          key == (byte) 0x9D ? PIVKeyObject.ROLE_KEY_ESTABLISH : PIVKeyObject.ROLE_SIGN,
          PIVKeyObject.ATTR_IMPORTABLE,
          modePin(),
          (byte) (modeVci() | modePin()));
    }
    assertExactKeyAccess(
        (byte) 0x9E,
        PIV.ID_ALG_RSA_2048,
        PIVKeyObject.ROLE_SIGN,
        PIVKeyObject.ATTR_IMPORTABLE,
        modeAlways(),
        modeAlways());
    for (int key = 0x82; key <= 0x95; key++) {
      assertExactKeyAccess(
          (byte) key,
          PIV.ID_ALG_RSA_2048,
          PIVKeyObject.ROLE_KEY_ESTABLISH,
          PIVKeyObject.ATTR_IMPORTABLE,
          modePin(),
          (byte) (modeVci() | modePin()));
    }
  }

  private static void assertExactObjectAccess(
      byte[] id, byte expectedContact, byte expectedContactless) {
    for (byte contact : ACCESS_MODES) {
      for (byte contactless : ACCESS_MODES) {
        boolean exact = contact == expectedContact && contactless == expectedContactless;
        assertEquals(
            !FipsPolicy.ENABLED || exact,
            FipsPolicy.allowsObjectDefinition(
                id, (short) 0, (short) id.length, contact, contactless),
            "object " + hex(id) + " access " + hex(contact) + "/" + hex(contactless));
      }
    }
  }

  private static void assertExactKeyAccess(
      byte id,
      byte mechanism,
      byte role,
      byte attributes,
      byte expectedContact,
      byte expectedContactless) {
    for (byte contact : ACCESS_MODES) {
      for (byte contactless : ACCESS_MODES) {
        boolean exact = contact == expectedContact && contactless == expectedContactless;
        assertEquals(
            !FipsPolicy.ENABLED || exact,
            FipsPolicy.allowsKeyDefinition(
                id, contact, contactless, mechanism, role, attributes),
            "key " + hex(id) + " access " + hex(contact) + "/" + hex(contactless));
      }
    }
  }

  private static byte[] pivObject(int suffix) {
    return new byte[] {(byte) 0x5F, (byte) 0xC1, (byte) suffix};
  }

  private static byte modeAlways() {
    return PIVObject.ACCESS_MODE_ALWAYS;
  }

  private static byte modePin() {
    return PIVObject.ACCESS_MODE_PIN;
  }

  private static byte modeVci() {
    return PIVObject.ACCESS_MODE_VCI;
  }

  private static String hex(byte[] value) {
    StringBuilder out = new StringBuilder();
    for (byte item : value) out.append(hex(item));
    return out.toString();
  }

  private static String hex(byte value) {
    return String.format("%02X", value & 0xFF);
  }
}
