/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.common;

import pro.javacard.gp.keys.PlaintextKeys;

public final class ScpConfig {
  public enum Mode {
    AUTO,
    SCP02,
    SCP03
  }

  public final Mode mode;
  public final int keyVersion;
  public final byte[] encKey;
  public final byte[] macKey;
  public final byte[] dekKey;

  public ScpConfig(Mode mode, int keyVersion, byte[] encKey, byte[] macKey, byte[] dekKey) {
    this.mode = mode;
    this.keyVersion = keyVersion;
    this.encKey = encKey.clone();
    this.macKey = macKey.clone();
    this.dekKey = dekKey.clone();
  }

  public static ScpConfig fromMaster(Mode mode, int keyVersion, byte[] masterKey) {
    return new ScpConfig(mode, keyVersion, masterKey, masterKey, masterKey);
  }

  public static ScpConfig defaultTestScp03() {
    return fromMaster(Mode.SCP03, 0, PlaintextKeys.DEFAULT_KEY());
  }

  public PlaintextKeys toPlaintextKeys() {
    PlaintextKeys keys = PlaintextKeys.fromKeys(encKey, macKey, dekKey);
    keys.setVersion(keyVersion);
    return keys;
  }

  public static Mode parseMode(String value) {
    if (value == null || "auto".equalsIgnoreCase(value)) {
      return Mode.AUTO;
    }
    if ("02".equals(value) || "2".equals(value) || "scp02".equalsIgnoreCase(value)) {
      return Mode.SCP02;
    }
    if ("03".equals(value) || "3".equals(value) || "scp03".equalsIgnoreCase(value)) {
      return Mode.SCP03;
    }
    throw new IllegalArgumentException("--scp must be auto, 02, or 03");
  }
}
