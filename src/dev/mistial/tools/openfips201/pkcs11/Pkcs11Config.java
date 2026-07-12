/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public final class Pkcs11Config {
  public String module;
  public String tokenLabel;
  public Integer slot;
  public String keyAlias;
  public String keyId;
  public String pinEnv;
  public String pinFile;
  public String softhsmConfig;

  public Pkcs11Config copy() {
    Pkcs11Config copy = new Pkcs11Config();
    copy.module = module;
    copy.tokenLabel = tokenLabel;
    copy.slot = slot;
    copy.keyAlias = keyAlias;
    copy.keyId = keyId;
    copy.pinEnv = pinEnv;
    copy.pinFile = pinFile;
    copy.softhsmConfig = softhsmConfig;
    return copy;
  }

  public char[] readPin() {
    if (pinEnv != null && !pinEnv.isEmpty()) {
      String value = System.getenv(pinEnv);
      if (value == null) {
        throw new IllegalArgumentException("Environment variable is not set: " + pinEnv);
      }
      return value.toCharArray();
    }
    if (pinFile != null && !pinFile.isEmpty()) {
      try {
        String value =
            new String(Files.readAllBytes(Paths.get(pinFile)), StandardCharsets.UTF_8).trim();
        if (!value.isEmpty()) {
          return value.toCharArray();
        }
      } catch (java.io.IOException e) {
        throw new IllegalArgumentException("Unable to read PKCS#11 pinFile: " + pinFile, e);
      }
    }
    throw new IllegalArgumentException("PKCS#11 pinEnv or pinFile is required");
  }
}
