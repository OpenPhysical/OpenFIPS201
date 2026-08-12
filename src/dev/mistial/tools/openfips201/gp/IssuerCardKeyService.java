/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.gp;

import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11Config;
import dev.mistial.tools.openfips201.profiles.IssuerProfile;

public final class IssuerCardKeyService {
  public ScpConfig stockScp(IssuerProfile profile) {
    if ("emulator-dev".equals(profile.name) && profile.stockScp.masterKeyEnv == null) {
      return ScpConfig.defaultTestScp03();
    }
    return ScpConfig.fromMaster(
        ScpConfig.parseMode(profile.stockScp.mode),
        profile.stockScp.keyVersion,
        secret(profile.stockScp.masterKeyEnv));
  }

  public DerivedScpKeys deriveCardKeys(IssuerProfile profile, byte[] kdd) throws Exception {
    if (!"pkcs11".equals(profile.cardKeys.deriver) || !"scp03-kdf3".equals(profile.cardKeys.kdf)) {
      throw new IllegalArgumentException("cardKeys must use deriver=pkcs11 and kdf=scp03-kdf3");
    }
    return new Scp03Kdf3DerivationService()
        .derive(
            cardMasterKey(profile),
            kdd,
            profile.cardKeys.newKeyVersion,
            profile.cardKeys.keyLengthBytes);
  }

  public Pkcs11Config cardMasterKey(IssuerProfile profile) {
    Pkcs11Config base =
        profile.cardKeys.pkcs11 == null
            ? profile.pkcs11.copy()
            : merge(profile.pkcs11, profile.cardKeys.pkcs11);
    if (profile.cardKeys.masterKeyAlias != null) {
      base.keyAlias = profile.cardKeys.masterKeyAlias;
    }
    if (profile.cardKeys.masterKeyId != null) {
      base.keyId = profile.cardKeys.masterKeyId;
    }
    if ((base.keyAlias == null || base.keyAlias.isEmpty())
        && (base.keyId == null || base.keyId.isEmpty())) {
      throw new IllegalArgumentException("cardKeys must set masterKeyAlias or masterKeyId");
    }
    return base;
  }

  public String describeCardMasterKey(IssuerProfile profile) {
    Pkcs11Config config = cardMasterKey(profile);
    if (config.keyAlias != null && !config.keyAlias.isEmpty()) {
      return config.keyAlias;
    }
    return "id:" + config.keyId;
  }

  private static Pkcs11Config merge(Pkcs11Config defaults, Pkcs11Config override) {
    Pkcs11Config result = defaults.copy();
    if (override.module != null) {
      result.module = override.module;
    }
    if (override.tokenLabel != null) {
      result.tokenLabel = override.tokenLabel;
    }
    if (override.slot != null) {
      result.slot = override.slot;
    }
    if (override.keyAlias != null) {
      result.keyAlias = override.keyAlias;
    }
    if (override.keyId != null) {
      result.keyId = override.keyId;
    }
    if (override.pinEnv != null) {
      result.pinEnv = override.pinEnv;
    }
    if (override.pinFile != null) {
      result.pinFile = override.pinFile;
    }
    if (override.softhsmConfig != null) {
      result.softhsmConfig = override.softhsmConfig;
    }
    return result;
  }

  private static byte[] secret(String env) {
    if (env == null || env.isEmpty()) {
      throw new IllegalArgumentException(
          "profile must name an environment variable for secret material");
    }
    String value = System.getenv(env);
    if (value == null) {
      throw new IllegalArgumentException("Environment variable is not set: " + env);
    }
    return HexUtil.parse(value);
  }
}
