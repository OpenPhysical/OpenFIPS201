/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.opid;

/** Locale-independent decimal helpers shared by the OPID classes. */
final class Digits {
  private Digits() {}

  /** Zero-pads the non-negative {@code value} to {@code width} ASCII digits. */
  static String pad(long value, int width) {
    String digits = Long.toString(value);
    if (value < 0 || digits.length() > width) {
      throw new IllegalArgumentException("value does not fit in " + width + " digits");
    }
    StringBuilder out = new StringBuilder(width);
    for (int i = digits.length(); i < width; i++) {
      out.append('0');
    }
    return out.append(digits).toString();
  }

  /** Returns {@code 10^digits} for {@code 0 <= digits <= 18}. */
  static long pow10(int digits) {
    if (digits < 0 || digits > 18) {
      throw new IllegalArgumentException("power of ten out of range");
    }
    long value = 1L;
    for (int i = 0; i < digits; i++) {
      value *= 10L;
    }
    return value;
  }

  /** Throws unless every character of {@code value} is ASCII {@code '0'..'9'}. */
  static void requireAscii(String value, String what) {
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (ch < '0' || ch > '9') {
        throw new IllegalArgumentException(what + " contains a non-digit character at index " + i);
      }
    }
  }

  /** Writes {@code value} as {@code out.length} digit values (0..9), most-significant first. */
  static void toDigitValues(long value, byte[] out) {
    long remaining = value;
    for (int i = out.length - 1; i >= 0; i--) {
      out[i] = (byte) (remaining % 10);
      remaining /= 10;
    }
  }

  /** Reads digit values (0..9), most-significant first. */
  static long fromDigitValues(byte[] in) {
    long value = 0;
    for (byte digit : in) {
      value = value * 10 + digit;
    }
    return value;
  }
}
