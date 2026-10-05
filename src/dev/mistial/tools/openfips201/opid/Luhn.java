/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.opid;

/**
 * Luhn mod-10 check digit (ISO/IEC 7812-1 Annex B).
 *
 * <p>Doubling starts at the rightmost payload digit. Only ASCII {@code '0'..'9'} is accepted; any
 * other character, including non-ASCII Unicode digits, is rejected with {@link
 * IllegalArgumentException}.
 */
public final class Luhn {
  private Luhn() {}

  /** Returns the check digit (0..9) to append to {@code payload}. */
  public static int checkDigit(CharSequence payload) {
    if (payload == null || payload.length() == 0) {
      throw new IllegalArgumentException("Luhn payload must contain at least one digit");
    }
    int sum = 0;
    boolean doubled = true;
    for (int i = payload.length() - 1; i >= 0; i--) {
      int digit = digit(payload.charAt(i), i);
      if (doubled) {
        digit <<= 1;
        if (digit > 9) {
          digit -= 9;
        }
      }
      sum += digit;
      doubled = !doubled;
    }
    return (10 - (sum % 10)) % 10;
  }

  /** Returns true when the final digit of {@code withCheck} is the Luhn digit of the rest. */
  public static boolean isValid(CharSequence withCheck) {
    if (withCheck == null || withCheck.length() < 2) {
      throw new IllegalArgumentException("Luhn input must contain a payload and a check digit");
    }
    int last = withCheck.length() - 1;
    int check = digit(withCheck.charAt(last), last);
    return checkDigit(withCheck.subSequence(0, last)) == check;
  }

  private static int digit(char ch, int index) {
    if (ch < '0' || ch > '9') {
      throw new IllegalArgumentException("non-digit character at index " + index);
    }
    return ch - '0';
  }
}
