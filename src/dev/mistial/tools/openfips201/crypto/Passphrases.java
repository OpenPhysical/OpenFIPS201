/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.crypto;

import java.util.Arrays;

public final class Passphrases {
  private Passphrases() {}

  public static char[] requireNonEmpty(char[] value, String source) {
    if (value == null || value.length == 0) {
      clear(value);
      throw new IllegalArgumentException("Empty passphrase is not allowed for " + source);
    }
    return value;
  }

  public static void clear(char[] value) {
    if (value != null) {
      Arrays.fill(value, '\0');
    }
  }
}
