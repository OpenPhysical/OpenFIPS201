/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.common;

import java.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Hexadecimal parsing and formatting.
 *
 * <p>Parse errors never contain the rejected value: inputs include SCP keys and master keys, so a
 * message reports only the digit count and the index of the first invalid character.
 */
public final class HexUtil {
  private HexUtil() {}

  /**
   * Parses hex digits, ignoring spaces, colons, tabs and newlines.
   *
   * @throws IllegalArgumentException for a missing value, an odd digit count, or a non-hex
   *     character; the message carries no part of {@code value}
   */
  public static byte[] parse(String value) {
    if (value == null) {
      throw new IllegalArgumentException("hex value is required");
    }
    char[] chars = value.toCharArray();
    try {
      return parseSecret(chars);
    } finally {
      Arrays.fill(chars, '\0');
    }
  }

  /**
   * Parses secret hex digits without creating a {@code String}, ignoring spaces, colons, tabs and
   * newlines. Every intermediate buffer is wiped before return; the caller owns and wipes {@code
   * value} and the returned array.
   *
   * @throws IllegalArgumentException for a missing value, an odd digit count, or a non-hex
   *     character; the message carries no part of {@code value}
   */
  public static byte[] parseSecret(char[] value) {
    if (value == null) {
      throw new IllegalArgumentException("hex value is required");
    }
    char[] digits = new char[value.length];
    try {
      int count = 0;
      for (int i = 0; i < value.length; i++) {
        char c = value[i];
        if (c == ' ' || c == ':' || c == '\n' || c == '\r' || c == '\t') {
          continue;
        }
        if (nibble(c) < 0) {
          throw new IllegalArgumentException(
              "invalid hex value: non-hex character at index "
                  + i
                  + " of "
                  + value.length
                  + " characters");
        }
        digits[count++] = c;
      }
      if ((count & 1) != 0) {
        throw new IllegalArgumentException(
            "hex value has an odd number of digits (" + count + " digits)");
      }
      byte[] out = new byte[count / 2];
      for (int i = 0; i < out.length; i++) {
        out[i] = (byte) ((nibble(digits[2 * i]) << 4) | nibble(digits[2 * i + 1]));
      }
      return out;
    } finally {
      Arrays.fill(digits, '\0');
    }
  }

  /** Returns the value of an ASCII hex digit, or -1 for any other character. */
  private static int nibble(char c) {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'A' && c <= 'F') {
      return c - 'A' + 10;
    }
    if (c >= 'a' && c <= 'f') {
      return c - 'a' + 10;
    }
    return -1;
  }

  public static String format(byte[] value) {
    return Hex.toHexString(value).toUpperCase();
  }
}
