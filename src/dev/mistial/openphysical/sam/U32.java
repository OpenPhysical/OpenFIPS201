/******************************************************************************
 * MIT License
 *
 * Project: OpenPhysical Issuer SAM
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ******************************************************************************/

package dev.mistial.openphysical.sam;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/**
 * Unsigned big-endian arithmetic on byte arrays of 4 (u32) and 8 (u64) octets.
 *
 * <p>{@link javacard.framework.Util#arrayCompare} compares signed octets, so every ordering of
 * counters, quotas and timestamps goes through {@link #compare}. All arithmetic uses short
 * intermediates whose ranges are stated at each loop.
 */
final class U32 {
  private U32() {}

  /**
   * Compares two unsigned big-endian values of equal length.
   *
   * @return -1, 0 or 1 when left is less than, equal to or greater than right
   */
  static short compare(
      byte[] left, short leftOffset, byte[] right, short rightOffset, short length) {
    for (short i = 0; i < length; i++) {
      short a = (short) (left[(short) (leftOffset + i)] & 0xFF);
      short b = (short) (right[(short) (rightOffset + i)] & 0xFF);
      if (a < b) return (short) -1;
      if (a > b) return (short) 1;
    }
    return (short) 0;
  }

  /** Returns true when every octet of the value is zero. */
  static boolean isZero(byte[] value, short offset, short length) {
    for (short i = 0; i < length; i++) {
      if (value[(short) (offset + i)] != (byte) 0) return false;
    }
    return true;
  }

  /**
   * Writes {@code out = left + right} over {@code length} octets.
   *
   * @return true when the sum overflowed (a carry left the most significant octet)
   */
  static boolean add(
      byte[] left,
      short leftOffset,
      byte[] right,
      short rightOffset,
      byte[] out,
      short outOffset,
      short length) {
    short carry = 0;
    for (short i = (short) (length - 1); i >= 0; i--) {
      // 0 <= sum <= 255 + 255 + 1
      short sum =
          (short)
              ((left[(short) (leftOffset + i)] & 0xFF)
                  + (right[(short) (rightOffset + i)] & 0xFF)
                  + carry);
      out[(short) (outOffset + i)] = (byte) sum;
      carry = (short) (sum >> 8);
    }
    return carry != 0;
  }

  /**
   * Writes {@code out = value + 1} over {@code length} octets.
   *
   * @return true when the increment overflowed
   */
  static boolean increment(byte[] value, short offset, byte[] out, short outOffset, short length) {
    short carry = 1;
    for (short i = (short) (length - 1); i >= 0; i--) {
      short sum = (short) ((value[(short) (offset + i)] & 0xFF) + carry);
      out[(short) (outOffset + i)] = (byte) sum;
      carry = (short) (sum >> 8);
    }
    return carry != 0;
  }

  /**
   * Divides an unsigned big-endian value by ten in place.
   *
   * @return the remainder 0..9
   */
  static byte divideByTen(byte[] value, short offset, short length) {
    short remainder = 0;
    for (short i = 0; i < length; i++) {
      // 0 <= current <= 9 * 256 + 255
      short current = (short) ((short) (remainder << 8) | (value[(short) (offset + i)] & 0xFF));
      value[(short) (offset + i)] = (byte) (current / 10);
      remainder = (short) (current % 10);
    }
    return (byte) remainder;
  }

  /**
   * Converts a u32 to {@code k} little-endian decimal digits (digit[0] = units).
   *
   * <p>The value is copied into {@code work} (4 octets) and divided by ten {@code k} times; the
   * conversion is exact only if the remaining quotient is zero, that is, {@code value < 10^k}. With
   * {@code k == 0} the method only tests that the value is zero.
   *
   * @return true when the value fits in k digits
   */
  static boolean toDecimal(
      byte[] value,
      short offset,
      byte[] work,
      short workOffset,
      byte[] digits,
      short digitsOffset,
      short k) {
    for (short i = 0; i < LENGTH_U32; i++) {
      work[(short) (workOffset + i)] = value[(short) (offset + i)];
    }
    for (short i = 0; i < k; i++) {
      digits[(short) (digitsOffset + i)] = divideByTen(work, workOffset, LENGTH_U32);
    }
    return isZero(work, workOffset, LENGTH_U32);
  }

  /**
   * Converts {@code k <= 8} little-endian decimal digits back to a u32 (big-endian).
   *
   * <p>The caller guarantees the value is below 10^8, which fits 32 bits.
   */
  static void fromDecimal(byte[] digits, short digitsOffset, short k, byte[] out, short outOffset) {
    for (short i = 0; i < LENGTH_U32; i++) out[(short) (outOffset + i)] = (byte) 0;
    for (short d = (short) (k - 1); d >= 0; d--) {
      // out = out * 10 + digit; 0 <= product <= 255 * 10 + 9 + carry
      short carry = digits[(short) (digitsOffset + d)];
      for (short i = (short) (LENGTH_U32 - 1); i >= 0; i--) {
        short product = (short) ((short) ((out[(short) (outOffset + i)] & 0xFF) * 10) + carry);
        out[(short) (outOffset + i)] = (byte) product;
        carry = (short) (product >> 8);
      }
    }
  }

  /**
   * Parses one DER INTEGER as an unsigned 32-bit value.
   *
   * <p>X.690 Section 8.3.2: "the bits of the first octet and bit 8 of the second octet shall not
   * all be ones; and shall not all be zero." Non-minimal encodings, negative values and values that
   * do not fit 32 bits are rejected with {@link ISO7816#SW_WRONG_DATA}.
   *
   * @param buffer input
   * @param offset first octet (tag) of the INTEGER
   * @param limit exclusive limit of the enclosing structure
   * @param out destination of the 4-octet big-endian value
   * @param outOffset destination offset
   * @return exclusive end offset of the INTEGER
   */
  static short parseDerInteger(
      byte[] buffer, short offset, short limit, byte[] out, short outOffset) {
    if (offset >= limit || buffer[offset] != TLV.ASN1_INTEGER) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    short end = DERValidator.derObjectEnd(buffer, offset, limit);
    short content = DERValidator.derContentOffset(buffer, offset, end);
    short length = (short) (end - content);
    if (length < (short) 1 || length > (short) 5) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    byte first = buffer[content];
    if ((first & (byte) 0x80) != (byte) 0) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    if (length > (short) 1
        && first == (byte) 0x00
        && (buffer[(short) (content + 1)] & (byte) 0x80) == (byte) 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    if (length == (short) 5) {
      // A five-octet minimal non-negative INTEGER is 00 followed by a magnitude >= 0x80000000.
      if (first != (byte) 0x00) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      content++;
      length--;
    }
    short pad = (short) (LENGTH_U32 - length);
    for (short i = 0; i < pad; i++) out[(short) (outOffset + i)] = (byte) 0;
    for (short i = 0; i < length; i++) {
      out[(short) (outOffset + pad + i)] = buffer[(short) (content + i)];
    }
    return end;
  }

  private static final short LENGTH_U32 = (short) 4;
}
