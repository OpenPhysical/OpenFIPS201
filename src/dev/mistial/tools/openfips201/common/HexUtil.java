/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.common;

import org.bouncycastle.util.encoders.Hex;

public final class HexUtil {
  private HexUtil() {}

  public static byte[] parse(String value) {
    if (value == null) {
      throw new IllegalArgumentException("hex value is required");
    }
    String normalized =
        value.replace(" ", "").replace(":", "").replace("\n", "").replace("\t", "");
    if ((normalized.length() & 1) != 0) {
      throw new IllegalArgumentException("hex value has an odd number of digits");
    }
    try {
      return Hex.decode(normalized);
    } catch (RuntimeException e) {
      throw new IllegalArgumentException("invalid hex value: " + value, e);
    }
  }

  public static String format(byte[] value) {
    return Hex.toHexString(value).toUpperCase();
  }
}
