/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.common;

import pro.javacard.gp.keys.PlaintextKeys;

public final class ScpConfig {
  public static final int KEY_VERSION_AUTO = 0;
  // GlobalPlatform Card Specification 2.3.1, Section 11.8.2.3: PUT KEY destinations.
  public static final int KEY_VERSION_MIN = 1;
  public static final int KEY_VERSION_MAX = 0x7F;

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
    return fromMaster(Mode.SCP03, KEY_VERSION_AUTO, PlaintextKeys.DEFAULT_KEY());
  }

  /** Resolves the mutually exclusive shared-key and split-key CLI representations. */
  public static ScpConfig fromCliKeys(
      Mode mode, int keyVersion, String sharedKey, String encKey, String macKey, String dekKey) {
    return fromKeys(
        mode,
        keyVersion,
        sharedKey == null ? null : HexUtil.parse(sharedKey),
        encKey == null ? null : HexUtil.parse(encKey),
        macKey == null ? null : HexUtil.parse(macKey),
        dekKey == null ? null : HexUtil.parse(dekKey));
  }

  /**
   * Resolves the mutually exclusive shared-key and split-key representations. The arguments are
   * copied, so the caller may wipe them after this returns.
   */
  public static ScpConfig fromKeys(
      Mode mode, int keyVersion, byte[] sharedKey, byte[] encKey, byte[] macKey, byte[] dekKey) {
    boolean shared = sharedKey != null;
    boolean enc = encKey != null;
    boolean mac = macKey != null;
    boolean dek = dekKey != null;
    boolean split = enc || mac || dek;
    if (shared && split) {
      throw new IllegalArgumentException("Use one shared SCP key or the three split SCP keys");
    }
    if (shared) {
      return fromMaster(mode, keyVersion, sharedKey);
    }
    if (enc && mac && dek) {
      return new ScpConfig(mode, keyVersion, encKey, macKey, dekKey);
    }
    throw new IllegalArgumentException("Provide one shared SCP key or all three split SCP keys");
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
