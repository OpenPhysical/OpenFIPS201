/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

public final class Pkcs11Config {
  public String module;
  public String tokenLabel;
  public Integer slot;
  public String keyAlias;
  public String pinEnv;

  public char[] readPin() {
    if (pinEnv == null || pinEnv.isEmpty()) {
      throw new IllegalArgumentException("PKCS#11 pinEnv is required");
    }
    String value = System.getenv(pinEnv);
    if (value == null) {
      throw new IllegalArgumentException("Environment variable is not set: " + pinEnv);
    }
    return value.toCharArray();
  }
}
