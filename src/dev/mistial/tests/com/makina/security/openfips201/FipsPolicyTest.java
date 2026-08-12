package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class FipsPolicyTest {
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
}
