/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.opid;

/**
 * 200-bit (25-byte) FASC-N encoding per TIG SCEPACS section 6.
 *
 * <p>The value is 40 characters of 5 bits each: 4 data bits least-significant first, then an odd
 * parity bit. Bits are packed most-significant bit first into the bytes. Character layout:
 *
 * <pre>
 * SS AAAA FS SSSS FS CCCCCC FS S FS I FS PPPPPPPPPP O OOOO P ES LRC
 * </pre>
 *
 * with SS = 11010 (0xB), FS = 10110 (0xD), ES = 11111 (0xF). The LRC data bits are the XOR of the
 * data bits of the 39 preceding characters; its fifth bit is odd parity over the LRC itself.
 */
public final class FascNCodec {
  public static final int LENGTH = 25;

  private static final int CHARACTERS = 40;
  private static final int START_SENTINEL = 0xB;
  private static final int FIELD_SEPARATOR = 0xD;
  private static final int END_SENTINEL = 0xF;
  private static final int LRC_POSITION = 39;
  private static final int END_POSITION = 38;

  /** Character positions of the field separators. */
  private static final int[] SEPARATORS = {5, 10, 17, 19, 21};

  private FascNCodec() {}

  /** Encodes {@code fascN} to its 25-byte form. */
  public static byte[] encode(FascN fascN) {
    if (fascN == null) {
      throw new IllegalArgumentException("FASC-N is required");
    }
    String digits = fascN.digits();
    int[] characters = new int[CHARACTERS];
    int digit = 0;
    for (int position = 0; position < END_POSITION; position++) {
      characters[position] =
          isSeparator(position)
              ? FIELD_SEPARATOR
              : position == 0 ? START_SENTINEL : digits.charAt(digit++) - '0';
    }
    characters[END_POSITION] = END_SENTINEL;
    int lrc = 0;
    for (int position = 0; position < LRC_POSITION; position++) {
      lrc ^= characters[position];
    }
    characters[LRC_POSITION] = lrc;

    byte[] out = new byte[LENGTH];
    for (int position = 0; position < CHARACTERS; position++) {
      int value = characters[position];
      int ones = 0;
      for (int bit = 0; bit < 4; bit++) {
        int set = (value >>> bit) & 1;
        ones += set;
        setBit(out, position * 5 + bit, set);
      }
      setBit(out, position * 5 + 4, (ones & 1) == 0 ? 1 : 0);
    }
    return out;
  }

  /**
   * Strictly decodes a 25-byte FASC-N: every character must have odd parity, SS, FS and ES must
   * appear exactly at their positions, every other non-LRC character must be a decimal digit, and
   * the LRC must match.
   */
  public static FascN decode(byte[] encoded) {
    if (encoded == null || encoded.length != LENGTH) {
      throw new IllegalArgumentException("FASC-N length must be " + LENGTH + " bytes");
    }
    int[] characters = new int[CHARACTERS];
    for (int position = 0; position < CHARACTERS; position++) {
      int value = 0;
      int ones = 0;
      for (int bit = 0; bit < 5; bit++) {
        int set = getBit(encoded, position * 5 + bit);
        ones += set;
        if (bit < 4) {
          value |= set << bit;
        }
      }
      if ((ones & 1) == 0) {
        throw new IllegalArgumentException("FASC-N parity error at character " + position);
      }
      characters[position] = value;
    }
    int lrc = 0;
    for (int position = 0; position < LRC_POSITION; position++) {
      lrc ^= characters[position];
    }
    if (lrc != characters[LRC_POSITION]) {
      throw new IllegalArgumentException("FASC-N lrc mismatch");
    }
    StringBuilder digits = new StringBuilder(32);
    for (int position = 0; position < LRC_POSITION; position++) {
      int expected =
          position == 0
              ? START_SENTINEL
              : position == END_POSITION
                  ? END_SENTINEL
                  : isSeparator(position) ? FIELD_SEPARATOR : -1;
      int value = characters[position];
      if (expected >= 0) {
        if (value != expected) {
          throw new IllegalArgumentException("FASC-N sentinel missing at character " + position);
        }
      } else if (value > 9) {
        throw new IllegalArgumentException("FASC-N non-digit at character " + position);
      } else {
        digits.append((char) ('0' + value));
      }
    }
    String d = digits.toString();
    return new FascN(
        Integer.parseInt(d.substring(0, 4)),
        Integer.parseInt(d.substring(4, 8)),
        Integer.parseInt(d.substring(8, 14)),
        d.charAt(14) - '0',
        d.charAt(15) - '0',
        Long.parseLong(d.substring(16, 26)),
        d.charAt(26) - '0',
        Integer.parseInt(d.substring(27, 31)),
        d.charAt(31) - '0');
  }

  private static boolean isSeparator(int position) {
    for (int separator : SEPARATORS) {
      if (separator == position) {
        return true;
      }
    }
    return false;
  }

  private static void setBit(byte[] out, int index, int value) {
    if (value != 0) {
      out[index >>> 3] |= (byte) (0x80 >>> (index & 7));
    }
  }

  private static int getBit(byte[] in, int index) {
    return (in[index >>> 3] >>> (7 - (index & 7))) & 1;
  }
}
