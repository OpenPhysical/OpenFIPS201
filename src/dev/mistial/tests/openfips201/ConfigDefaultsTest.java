package com.makina.security.openfips201;

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
    assertEquals(FipsPolicy.ENABLED ? 140 : 149, Config.TEMPLATE_APT.length);
    assertEquals(0x61, Config.TEMPLATE_APT[0] & 0xFF);
    assertEquals(0x81, Config.TEMPLATE_APT[1] & 0xFF);
    assertEquals(Config.TEMPLATE_APT.length - 3, Config.TEMPLATE_APT[2] & 0xFF);
  }

  @Test
  void fipsProfileExcludesLegacyMechanisms() {
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
          (byte) 0xA0, 0x26,
          (byte) 0x80, 0x01, 0x01,
          (byte) 0x81, 0x01, 0x00,
          (byte) 0x82, 0x01, 0x00,
          (byte) 0x83, 0x01, 0x00,
          (byte) 0x84, 0x01, 0x06,
          (byte) 0x85, 0x01, 0x08,
          (byte) 0x86, 0x01, 0x06,
          (byte) 0x87, 0x01, 0x04,
          (byte) 0x88, 0x01, 0x00,
          (byte) 0x89, 0x01, 0x04,
          (byte) 0x8A, 0x01, 0x03,
          (byte) 0x8B, 0x01, 0x04,
          (byte) 0x8C, 0x00
        });
    assertEquals(2, config.getIntermediatePINRetries());
    assertEquals(6, config.readValue(Config.CONFIG_PIN_MIN_LENGTH));
    assertEquals(8, config.readValue(Config.CONFIG_PIN_MAX_LENGTH));

    // SP 800-73-5 Part 2, Section 3.2.3 fixes the PUK wire field at eight bytes.
    update(
        config,
        new byte[] {
          (byte) 0xA1, 0x11,
          (byte) 0x80, 0x01, 0x01,
          (byte) 0x81, 0x01, 0x00,
          (byte) 0x82, 0x01, 0x08,
          (byte) 0x83, 0x01, 0x08,
          (byte) 0x84, 0x01, 0x05,
          (byte) 0x86, 0x00
        });
    assertEquals(3, config.getIntermediatePUKRetries());
  }

  @Test
  void issuerCanApplyVciAndStrictInterfaceOptions() {
    Config config = new Config();
    update(
        config,
        new byte[] {(byte) 0xA2, 0x05, (byte) 0x80, 0x01, 0x01, (byte) 0x81, 0x00});
    assertEquals(Config.VCI_MODE_ENABLED, config.readValue(Config.CONFIG_VCI_MODE));

    update(
        config,
        new byte[] {
          (byte) 0xA4, 0x0B,
          (byte) 0x80, 0x01, 0x01,
          (byte) 0x81, 0x01, 0x01,
          (byte) 0x84, 0x01, 0x00,
          (byte) 0x87, 0x00
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
        () ->
            update(
                config,
                new byte[] {
                  (byte) 0xA0, 0x03, (byte) 0x86, 0x01, 0x03
                }));
    assertThrows(
        RuntimeException.class,
        () ->
            update(
                config,
                new byte[] {
                  (byte) 0xA1, 0x03, (byte) 0x83, 0x01, 0x03
                }));
  }

  private static void update(Config config, byte[] encoded) {
    try (MockedStatic<JCSystem> mocked = Mockito.mockStatic(JCSystem.class)) {
      mocked
          .when(() -> JCSystem.makeTransientObjectArray(Mockito.anyShort(), Mockito.anyByte()))
          .thenReturn(new Object[1]);
      mocked
          .when(() -> JCSystem.makeTransientShortArray(Mockito.anyShort(), Mockito.anyByte()))
          .thenReturn(new short[4]);
      TLVReader reader = TLVReader.getInstance();
      reader.init(encoded, (short) 0, (short) encoded.length);
      config.update(reader);
    }
  }
}
