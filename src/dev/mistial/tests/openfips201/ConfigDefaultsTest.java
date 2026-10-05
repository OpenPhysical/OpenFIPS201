package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javacard.framework.JCSystem;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class ConfigDefaultsTest {

  @Test
  void applicationPropertyTemplateHasConsistentOuterLength() {
    // The standard APT no longer advertises RSA-1024 ('80 01 06'), which no standard key
    // reference accepts.
    assertEquals(FipsPolicy.ENABLED ? 140 : 146, Config.TEMPLATE_APT.length);
    assertEquals(0x61, Config.TEMPLATE_APT[0] & 0xFF);
    assertEquals(0x81, Config.TEMPLATE_APT[1] & 0xFF);
    assertEquals(Config.TEMPLATE_APT.length - 3, Config.TEMPLATE_APT[2] & 0xFF);
  }

  @Test
  void algorithmTemplateAdvertisesExactlyTheProfileMechanisms() {
    // SP 800-73-5 Part 2 Section 3.1.1: "Tag 0xAC encodes the cryptographic algorithms supported by
    // the PIV Card Application." The hand-written template must agree with FipsPolicy, the single
    // source of the profile's mechanism set. RSA-1024 is held back (retired references only), and
    // the secure messaging suite is inserted at SELECT only once key 04 is ready.
    byte[] apt = Config.TEMPLATE_APT;
    int offset = 3;
    int ac = -1;
    while (offset < apt.length) {
      int tagLength = (apt[offset] & 0x1F) == 0x1F ? 2 : 1;
      assertTrue((apt[offset + tagLength] & 0x80) == 0, "APT elements use short-form lengths");
      if ((apt[offset] & 0xFF) == 0xAC) ac = offset;
      offset += tagLength + 1 + (apt[offset + tagLength] & 0xFF);
    }
    assertEquals(apt.length, offset, "The APT elements fill the template exactly");
    assertTrue(ac > 0, "The APT carries the algorithm template");

    int acEnd = ac + 2 + (apt[ac + 1] & 0xFF);
    java.util.Set<Byte> advertised = new java.util.HashSet<>();
    int entry = ac + 2;
    while (apt[entry] == (byte) 0x80) {
      assertEquals(0x01, apt[entry + 1], "Each algorithm identifier is one byte");
      assertTrue(advertised.add(apt[entry + 2]), "No algorithm is advertised twice");
      entry += 3;
    }
    assertArrayEquals(
        new byte[] {0x06, 0x01, 0x00},
        java.util.Arrays.copyOfRange(apt, entry, acEnd),
        "The template ends with its object identifier");

    java.util.Set<Byte> expected = new java.util.HashSet<>();
    byte[] candidates = {
      PIV.ID_ALG_DEFAULT,
      PIV.ID_ALG_TDEA_3KEY,
      PIV.ID_ALG_RSA_2048,
      PIV.ID_ALG_RSA_3072,
      PIV.ID_ALG_AES_128,
      PIV.ID_ALG_AES_192,
      PIV.ID_ALG_AES_256,
      PIV.ID_ALG_ECC_P256,
      PIV.ID_ALG_ECC_P384
    };
    for (byte mechanism : candidates) {
      if (FipsPolicy.allowsMechanism(mechanism)) expected.add(mechanism);
    }
    assertEquals(expected, advertised);
  }

  @Test
  void fipsProfileExcludesDisallowedMechanisms() {
    assertEquals(!FipsPolicy.ENABLED, FipsPolicy.allowsMechanism(PIV.ID_ALG_TDEA_3KEY));
    assertEquals(!FipsPolicy.ENABLED, FipsPolicy.allowsMechanism(PIV.ID_ALG_RSA_1024));
  }

  @Test
  void contactlessAdministrationIsRestrictedByDefault() {
    Config config = new Config();
    assertTrue(config.readFlag(Config.OPTION_RESTRICT_CONTACTLESS_ADMIN));
  }

  @Test
  void rsa3072HasRequiredKeyLengthAndIsAdvertised() {
    assertEquals(0x05, PIV.ID_ALG_RSA_3072 & 0xFF);
    assertEquals(3072, PIVKeyObjectRSA.keyLengthBitsForMechanism(PIV.ID_ALG_RSA_3072));

    boolean advertised = false;
    boolean reservedIdentifierAdvertised = false;
    for (int i = 0; i + 2 < Config.TEMPLATE_APT.length; i++) {
      if (Config.TEMPLATE_APT[i] == (byte) 0x80
          && Config.TEMPLATE_APT[i + 1] == (byte) 0x01
          && Config.TEMPLATE_APT[i + 2] == PIV.ID_ALG_RSA_3072) {
        advertised = true;
      }
      if (Config.TEMPLATE_APT[i] == (byte) 0x80
          && Config.TEMPLATE_APT[i + 1] == (byte) 0x01
          && Config.TEMPLATE_APT[i + 2] == (byte) 0x0E) {
        reservedIdentifierAdvertised = true;
      }
    }
    assertTrue(advertised, "The application property template must advertise RSA-3072");
    assertFalse(reservedIdentifierAdvertised, "Reserved algorithm ID 0x0E must not appear");
  }

  @Test
  void issuerCanApplyCompleteConformantPinAndPukPolicies() {
    Config config = new Config();
    update(
        config,
        new byte[] {
          (byte) 0xA0,
          0x24,
          (byte) 0x80,
          0x01,
          0x01,
          (byte) 0x81,
          0x01,
          0x00,
          (byte) 0x82,
          0x01,
          0x00,
          (byte) 0x83,
          0x01,
          0x00,
          (byte) 0x84,
          0x01,
          0x06,
          (byte) 0x85,
          0x01,
          0x08,
          (byte) 0x86,
          0x01,
          0x06,
          (byte) 0x87,
          0x01,
          0x04,
          (byte) 0x88,
          0x01,
          0x00,
          (byte) 0x89,
          0x01,
          0x04,
          (byte) 0x8A,
          0x01,
          0x03,
          (byte) 0x8B,
          0x01,
          0x04
        });
    assertEquals(2, config.getIntermediatePINRetries());
    assertEquals(6, config.readValue(Config.CONFIG_PIN_MIN_LENGTH));
    assertEquals(8, config.readValue(Config.CONFIG_PIN_MAX_LENGTH));

    // SP 800-73-5 Part 2, Section 3.2.3 fixes the PUK wire field at eight bytes.
    update(
        config,
        new byte[] {
          (byte) 0xA1,
          0x0F,
          (byte) 0x80,
          0x01,
          0x01,
          (byte) 0x81,
          0x01,
          0x00,
          (byte) 0x82,
          0x01,
          0x08,
          (byte) 0x83,
          0x01,
          0x08,
          (byte) 0x84,
          0x01,
          0x05
        });
    assertEquals(3, config.getIntermediatePUKRetries());
  }

  @Test
  void issuerCanApplyVciAndStrictInterfaceOptions() {
    Config config = new Config();
    update(config, new byte[] {(byte) 0xA2, 0x03, (byte) 0x80, 0x01, 0x01});
    assertEquals(Config.VCI_MODE_ENABLED, config.readValue(Config.CONFIG_VCI_MODE));

    update(
        config,
        new byte[] {
          (byte) 0xA4,
          0x09,
          (byte) 0x80,
          0x01,
          0x01,
          (byte) 0x81,
          0x01,
          0x01,
          (byte) 0x84,
          0x01,
          0x00
        });
    assertTrue(config.readFlag(Config.OPTION_RESTRICT_CONTACTLESS_GLOBAL));
    assertTrue(config.readFlag(Config.OPTION_RESTRICT_CONTACTLESS_ADMIN));
    assertFalse(config.readFlag(Config.OPTION_IGNORE_CONTACTLESS_ACL));
  }

  @Test
  void retryPoliciesRejectContactBelowTheStoredContactlessLimit() {
    Config config = new Config();
    assertThrows(
        RuntimeException.class,
        () -> update(config, new byte[] {(byte) 0xA0, 0x03, (byte) 0x86, 0x01, 0x03}));
    assertThrows(
        RuntimeException.class,
        () -> update(config, new byte[] {(byte) 0xA1, 0x03, (byte) 0x83, 0x01, 0x03}));
  }

  @Test
  void rejectsAConfigurationPolicyNestedInsideAnotherPolicy() {
    Config config = new Config();
    assertThrows(
        RuntimeException.class,
        () ->
            update(
                config,
                new byte[] {
                  (byte) 0xA0,
                  0x0A,
                  (byte) 0x80,
                  0x01,
                  0x01,
                  (byte) 0xA2,
                  0x05,
                  (byte) 0x80,
                  0x01,
                  0x01,
                  (byte) 0x81,
                  0x00
                }));
  }

  @Test
  void rejectsUnknownConfigurationFields() {
    Config config = new Config();
    assertThrows(
        RuntimeException.class,
        () ->
            update(
                config,
                new byte[] {(byte) 0xA2, 0x06, (byte) 0x80, 0x01, 0x01, (byte) 0x81, 0x01, 0x01}));
  }

  private static void update(Config config, byte[] encoded) {
    try (MockedStatic<JCSystem> mocked = Mockito.mockStatic(JCSystem.class)) {
      mocked
          .when(() -> JCSystem.makeTransientObjectArray(Mockito.anyShort(), Mockito.anyByte()))
          .thenReturn(new Object[1]);
      mocked
          .when(() -> JCSystem.makeTransientShortArray(Mockito.anyShort(), Mockito.anyByte()))
          .thenAnswer(call -> new short[(short) call.getArgument(0)]);
      TLVReader reader = TLVReader.getInstance();
      reader.init(encoded, (short) 0, (short) encoded.length);
      config.update(reader);
    }
  }
}
