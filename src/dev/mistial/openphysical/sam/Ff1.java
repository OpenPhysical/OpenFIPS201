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

import javacard.framework.Util;
import javacardx.crypto.Cipher;

/**
 * NIST SP 800-38G Rev. 1 FF1 with AES-256 and radix 10: FF1.Encrypt (Algorithm 7) and FF1.Decrypt
 * (Algorithm 8).
 *
 * <p>Supported lengths are 6 &lt;= n &lt;= 12 digits ({@code radix^minlen >= 10^6}), so u =
 * floor(n/2) &lt;= 6 and v = n - u &lt;= 6. Then b = ceil(ceil(v log2 10)/8) is 2 for v in 3..4 and
 * 3 for v in 5..6, and d = 4 ceil(b/4) + 4 = 8, so S is the first 8 octets of the single PRF output
 * block R and y = NUM_2(S) &lt; 2^64. The tweak satisfies t + 1 + b &lt;= 16, so Q is one block and
 * the PRF input P || Q is exactly two blocks. The PRF is AES-256-CBC-MAC with a zero IV.
 *
 * <p>{@code c = (NUM_10(A) + y) mod 10^m} (encrypt) and {@code c = (NUM_10(B) - y) mod 10^m}
 * (decrypt) are computed digit-wise: y mod 10^m is the m low decimal digits of y, obtained by
 * dividing the 8-octet S by ten m times, and the sum or difference is a decimal addition or
 * subtraction truncated to m digits. All intermediates use short arithmetic and are zeroized on
 * return.
 *
 * <p>Work area layout (offsets relative to {@code work}): P || Q at 0..31, CBC output at 32..63 (R
 * at 48..63), A at 64..69, B at 70..75, the low digits of y at 76..81; {@link #LENGTH_WORK} octets.
 */
final class Ff1 {
  private Ff1() {}

  static final short LENGTH_WORK = (short) 82;
  static final short MIN_DIGITS = (short) 6;
  static final short MAX_DIGITS = (short) 12;

  private static final short P = (short) 0;
  private static final short Q = (short) 16;
  private static final short OUT = (short) 32;
  private static final short R = (short) 48;
  private static final short A = (short) 64;
  private static final short B = (short) 70;
  private static final short Y = (short) 76;
  private static final short ROUNDS = (short) 10;

  /** FF1.Encrypt(K, T, X) of {@code n} digits (values 0..9, most significant first) in place. */
  static void encrypt(
      SamCrypto crypto,
      byte[] digits,
      short digitsOffset,
      short n,
      byte[] tweak,
      short tweakOffset,
      short t,
      byte[] work,
      short workOffset) {
    cipher(crypto, true, digits, digitsOffset, n, tweak, tweakOffset, t, work, workOffset);
  }

  /** FF1.Decrypt(K, T, Y) of {@code n} digits (values 0..9, most significant first) in place. */
  static void decrypt(
      SamCrypto crypto,
      byte[] digits,
      short digitsOffset,
      short n,
      byte[] tweak,
      short tweakOffset,
      short t,
      byte[] work,
      short workOffset) {
    cipher(crypto, false, digits, digitsOffset, n, tweak, tweakOffset, t, work, workOffset);
  }

  private static void cipher(
      SamCrypto crypto,
      boolean encrypt,
      byte[] digits,
      short digitsOffset,
      short n,
      byte[] tweak,
      short tweakOffset,
      short t,
      byte[] work,
      short workOffset) {
    short u = (short) (n >> 1);
    short v = (short) (n - u);
    short b = v >= (short) 5 ? (short) 3 : (short) 2;

    // Step 5: P = [1]^1 [2]^1 [1]^1 [radix]^3 [10]^1 [u mod 256]^1 [n]^4 [t]^4.
    short p = (short) (workOffset + P);
    Util.arrayFillNonAtomic(work, p, (short) 16, (byte) 0);
    work[p] = (byte) 0x01;
    work[(short) (p + 1)] = (byte) 0x02;
    work[(short) (p + 2)] = (byte) 0x01;
    work[(short) (p + 5)] = (byte) 10;
    work[(short) (p + 6)] = (byte) 10;
    work[(short) (p + 7)] = (byte) u;
    work[(short) (p + 11)] = (byte) n;
    work[(short) (p + 15)] = (byte) t;

    // Step 2: A = X[1..u], B = X[u+1..n].
    short aOffset = (short) (workOffset + A);
    short bOffset = (short) (workOffset + B);
    short aLength = u;
    short bLength = v;
    Util.arrayCopyNonAtomic(digits, digitsOffset, work, aOffset, u);
    Util.arrayCopyNonAtomic(digits, (short) (digitsOffset + u), work, bOffset, v);

    short q = (short) (workOffset + Q);
    short r = (short) (workOffset + R);
    short y = (short) (workOffset + Y);
    for (short round = 0; round < ROUNDS; round++) {
      // Encrypt runs i = 0..9 over (A, B); decrypt runs i = 9..0 with the roles of A and B
      // exchanged: Q takes NUM(A) and C replaces B.
      short i = encrypt ? round : (short) (ROUNDS - 1 - round);
      short sourceOffset = encrypt ? bOffset : aOffset;
      short sourceLength = encrypt ? bLength : aLength;
      short targetOffset = encrypt ? aOffset : bOffset;
      short m = encrypt ? aLength : bLength;

      // Step i: Q = T || [0]^((-t-b-1) mod 16) || [i]^1 || [NUM_radix(source)]^b.
      Util.arrayFillNonAtomic(work, q, (short) 16, (byte) 0);
      Util.arrayCopyNonAtomic(tweak, tweakOffset, work, q, t);
      work[(short) (q + 15 - b)] = (byte) i;
      short num = (short) (q + 16 - b);
      for (short j = 0; j < sourceLength; j++) {
        // value = value * 10 + digit over b octets; 0 <= product <= 255 * 10 + 9
        short carry = work[(short) (sourceOffset + j)];
        for (short k = (short) (b - 1); k >= 0; k--) {
          short product = (short) ((short) ((work[(short) (num + k)] & 0xFF) * 10) + carry);
          work[(short) (num + k)] = (byte) product;
          carry = (short) (product >> 8);
        }
      }

      // R = PRF(P || Q); S = R[0..8); y = NUM_2(S).
      crypto.fpeCipher.init(crypto.fpeKey, Cipher.MODE_ENCRYPT);
      crypto.fpeCipher.doFinal(
          work, (short) (workOffset + P), (short) 32, work, (short) (workOffset + OUT));

      // c = (NUM(target) +/- y) mod 10^m, written over the target half.
      for (short j = 0; j < m; j++) {
        work[(short) (y + j)] = U32.divideByTen(work, r, (short) 8);
      }
      short carry = 0;
      for (short j = 0; j < m; j++) {
        short position = (short) (targetOffset + m - 1 - j);
        short value;
        if (encrypt) {
          value = (short) (work[position] + work[(short) (y + j)] + carry);
          carry = value > (short) 9 ? (short) 1 : (short) 0;
          if (carry != (short) 0) value -= (short) 10;
        } else {
          value = (short) (work[position] - work[(short) (y + j)] - carry);
          carry = value < (short) 0 ? (short) 1 : (short) 0;
          if (carry != (short) 0) value += (short) 10;
        }
        work[position] = (byte) value;
      }

      // Encrypt: A = B; B = C. Decrypt: B = A; A = C. Both exchange the two halves.
      short swapOffset = aOffset;
      aOffset = bOffset;
      bOffset = swapOffset;
      short swapLength = aLength;
      aLength = bLength;
      bLength = swapLength;
    }

    // Return A || B.
    Util.arrayCopyNonAtomic(work, aOffset, digits, digitsOffset, aLength);
    Util.arrayCopyNonAtomic(work, bOffset, digits, (short) (digitsOffset + aLength), bLength);
    Util.arrayFillNonAtomic(work, workOffset, LENGTH_WORK, (byte) 0);
  }

  /** Writes the OPID tweak T = ASCII(IIN), 4 octets, and returns its length. */
  static short writeTweak(SamState state, byte[] out, short offset) {
    for (short i = 0; i < SamConst.ISSUER_DIGITS; i++) {
      out[(short) (offset + i)] = (byte) (state.issuerDigits[i] + (byte) '0');
    }
    return SamConst.ISSUER_DIGITS;
  }

  /**
   * Writes the 12-digit FF1 input numeral batch(4) | x(8), most significant first, from the stored
   * batch digits and an LCG value given as 8 little-endian digits.
   */
  static void writeNumeral(SamState state, byte[] x, short xOffset, byte[] out, short offset) {
    Util.arrayCopyNonAtomic(state.batchDigits, (short) 0, out, offset, SamConst.BATCH_DIGITS);
    for (short i = 0; i < SamConst.CIN_DIGITS; i++) {
      out[(short) (offset + SamConst.BATCH_DIGITS + i)] =
          x[(short) (xOffset + SamConst.CIN_DIGITS - 1 - i)];
    }
  }
}
