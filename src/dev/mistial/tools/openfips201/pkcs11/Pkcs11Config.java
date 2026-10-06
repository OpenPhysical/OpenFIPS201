/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

import dev.mistial.tools.openfips201.crypto.SecretSource;
import java.io.IOException;
import java.nio.file.Paths;

/**
 * PKCS#11 module, token, key and PIN-source selection.
 *
 * <p>Contract: the user PIN is never held here. It is named by exactly one of {@link #pinEnv} (an
 * environment variable), {@link #pinFile} (a regular file owned by the current user with no group
 * or other permission bits) or {@link #pinPrompt} (read from the console without echo), and is read
 * by {@link #readPin()} each time a session logs in.
 */
public final class Pkcs11Config {
  public String module;
  public String tokenLabel;
  public Integer slot;
  public String keyAlias;
  public String keyId;
  public String pinEnv;
  public String pinFile;
  public boolean pinPrompt;
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
    copy.pinPrompt = pinPrompt;
    copy.softhsmConfig = softhsmConfig;
    return copy;
  }

  /**
   * Returns the user PIN in a new array owned (and wiped) by the caller. A {@link #pinFile} that is
   * not owner-only is refused ({@link SecretSource#fromFile(java.nio.file.Path)}).
   */
  public char[] readPin() {
    char[] value;
    if (pinEnv != null && !pinEnv.isEmpty()) {
      value = SecretSource.fromEnv(pinEnv);
    } else if (pinFile != null && !pinFile.isEmpty()) {
      try {
        value = SecretSource.fromFile(Paths.get(pinFile));
      } catch (IOException e) {
        throw new IllegalArgumentException("Unable to read PKCS#11 pinFile: " + pinFile, e);
      }
    } else if (pinPrompt) {
      value =
          SecretSource.fromConsole(
              "PKCS#11 user PIN for token " + (tokenLabel == null ? "" : tokenLabel),
              "--pkcs11-pin");
    } else {
      throw new IllegalArgumentException("PKCS#11 pinEnv, pinFile or pinPrompt is required");
    }
    if (value.length == 0) {
      throw new IllegalArgumentException("PKCS#11 PIN is empty");
    }
    return value;
  }
}
