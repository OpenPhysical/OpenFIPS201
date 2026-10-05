/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.opid;

/**
 * OpenPhysical credential identifier (OPID), layout v2, immutable.
 *
 * <pre>
 * OPID = IIII || E || L            17 decimal digits; the canonical form has no separators
 *   IIII  issuer identification number, plaintext
 *   E     12 digits, FF1_K(batch(4) || x_n(8), ASCII(IIII))  (see OpidSequence)
 *   L     Luhn check digit over the 16 typed digits IIII || E
 * </pre>
 *
 * <p>The IIN is always plaintext; the batch and CIN are only ever present enciphered inside E. L
 * covers exactly the digits a user types, never the plaintext batch or LCG state. The display
 * grouping {@code IIII EEEE EEEE EEEEL} (4-4-4-5) is presentation only.
 */
public final class Opid {
  public static final int LENGTH = 17;
  public static final int IIN_DIGITS = 4;
  public static final int E_DIGITS = 12;
  public static final int MAX_IIN = 9999;
  public static final long E_MODULUS = 1000000000000L;

  public final int iin;

  /** Enciphered field E, {@code 0 <= e < 10^12}. */
  public final long e;

  public final int check;

  private final String digits;

  private Opid(int iin, long e) {
    this.iin = iin;
    this.e = e;
    String payload = Digits.pad(iin, IIN_DIGITS) + Digits.pad(e, E_DIGITS);
    this.check = Luhn.checkDigit(payload);
    this.digits = payload + check;
  }

  /**
   * Builds an OPID from its IIN and enciphered field and computes the check digit.
   *
   * @throws IllegalArgumentException unless {@code 0 <= iin <= 9999} and {@code 0 <= e < 10^12}
   */
  public static Opid of(int iin, long e) {
    if (iin < 0 || iin > MAX_IIN) {
      throw new IllegalArgumentException("OPID IIN must be 0..9999");
    }
    if (e < 0 || e >= E_MODULUS) {
      throw new IllegalArgumentException("OPID enciphered field must have 12 digits");
    }
    return new Opid(iin, e);
  }

  /** Strict parser: exactly 17 ASCII digits, no separators, valid Luhn check digit. */
  public static Opid parseCanonical(String value) {
    if (value == null) {
      throw new IllegalArgumentException("OPID is required");
    }
    Digits.requireAscii(value, "OPID");
    if (value.length() != LENGTH) {
      throw new IllegalArgumentException(
          "OPID requires " + LENGTH + " digits, got " + value.length());
    }
    if (!Luhn.isValid(value)) {
      throw new IllegalArgumentException("OPID check digit is invalid");
    }
    return of(
        Integer.parseInt(value.substring(0, IIN_DIGITS)),
        Long.parseLong(value.substring(IIN_DIGITS, IIN_DIGITS + E_DIGITS)));
  }

  /** Lenient parser: removes {@code ' '} and {@code '-'}, then applies {@link #parseCanonical}. */
  public static Opid parse(String value) {
    if (value == null) {
      throw new IllegalArgumentException("OPID is required");
    }
    StringBuilder stripped = new StringBuilder(value.length());
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (ch != '-' && ch != ' ') {
        stripped.append(ch);
      }
    }
    return parseCanonical(stripped.toString());
  }

  /** Returns the canonical 17 digits. */
  public String toPrinted() {
    return digits;
  }

  /** Returns the display grouping {@code IIII EEEE EEEE EEEEL}. */
  public String toDisplay() {
    return digits.substring(0, 4)
        + " "
        + digits.substring(4, 8)
        + " "
        + digits.substring(8, 12)
        + " "
        + digits.substring(12, 17);
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof Opid)) {
      return false;
    }
    Opid that = (Opid) other;
    return iin == that.iin && e == that.e;
  }

  @Override
  public int hashCode() {
    return digits.hashCode();
  }

  /** Same as {@link #toPrinted()}. */
  @Override
  public String toString() {
    return digits;
  }
}
