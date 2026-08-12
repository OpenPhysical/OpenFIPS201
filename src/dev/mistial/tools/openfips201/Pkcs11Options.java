package dev.mistial.tools.openfips201;

import dev.mistial.tools.openfips201.pkcs11.Pkcs11Config;
import picocli.CommandLine.Option;

/** Shared PKCS#11 token and key selection options. */
class Pkcs11Options {
  @Option(names = "--pkcs11-module")
  String module;

  @Option(names = "--pkcs11-token-label")
  String tokenLabel;

  @Option(names = "--pkcs11-slot")
  Integer slot;

  @Option(names = "--pkcs11-key-alias")
  String keyAlias;

  @Option(names = "--pkcs11-key-id")
  String keyId;

  @Option(names = "--pkcs11-pin-env")
  String pinEnv;

  @Option(names = "--pkcs11-pin-file")
  String pinFile;

  @Option(names = "--softhsm-config")
  String softhsmConfig;

  Pkcs11Config pkcs11() {
    Pkcs11Config config = new Pkcs11Config();
    config.module = module;
    config.tokenLabel = tokenLabel;
    config.slot = slot;
    config.keyAlias = keyAlias;
    config.keyId = keyId;
    config.pinEnv = pinEnv;
    config.pinFile = pinFile;
    config.softhsmConfig = softhsmConfig;
    if (config.module == null || config.module.isEmpty()) {
      throw new IllegalArgumentException("--pkcs11-module is required");
    }
    return config;
  }
}
