package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

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
}
