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

/**
 * Linear congruential generator {@code x' = (a * x + c) mod 10^k} on decimal digit arrays.
 *
 * <p>Digits are little-endian ({@code d[0]} is the units digit) with {@code 1 <= k <= 8}. Because
 * the modulus is a power of ten, reduction is truncation to k digits: the schoolbook product
 * discards every partial product and carry at digit position k or above. All loop bounds are fixed
 * by k and every intermediate fits a short ({@code t <= 9 + 9 * 9 + 9}).
 *
 * <p>The parameters are provisioned by the issuance software and only validated here. With
 * Hull-Dobell parameters the sequence has full period m, so issuance n receives {@code f^n(x0)}.
 */
final class DecimalLcg {
  private DecimalLcg() {}

  /**
   * Computes {@code out = (a * x + c) mod 10^k}.
   *
   * <pre>
   * out = c; for i &lt; k: carry = 0; for j &lt;= k-1-i: t = out[i+j] + a[i]*x[j] + carry;
   *   out[i+j] = t % 10; carry = t / 10   // the carry beyond position k-1 is dropped
   * </pre>
   *
   * {@code out} must not alias {@code a}, {@code x} or {@code c}.
   */
  static void step(
      byte[] a,
      short aOffset,
      byte[] x,
      short xOffset,
      byte[] c,
      short cOffset,
      short k,
      byte[] out,
      short outOffset) {
    for (short i = 0; i < k; i++) out[(short) (outOffset + i)] = c[(short) (cOffset + i)];
    for (short i = 0; i < k; i++) {
      short ai = a[(short) (aOffset + i)];
      short carry = 0;
      short limit = (short) (k - i);
      for (short j = 0; j < limit; j++) {
        short position = (short) (outOffset + i + j);
        short t = (short) (out[position] + (short) (ai * x[(short) (xOffset + j)]) + carry);
        out[position] = (byte) (t % 10);
        carry = (short) (t / 10);
      }
    }
  }

  /**
   * Computes the jump maps M_j = f^(10^(j-1)), j = 1..8, as affine pairs (A_j, C_j) mod 10^8 with
   * M_1 = (a, c) and M_{j+1} = M_j^10. Composing x -&gt; A x + C with M_j gives (A_j A, A_j C +
   * C_j); each product is one {@link #step} with a zero or C_j increment.
   *
   * @param outA destination of the 8 A_j, 8 little-endian digits each
   * @param outC destination of the 8 C_j
   * @param work 40 octets of work area, zeroized on return
   */
  static void jumpMaps(
      byte[] a, byte[] c, byte[] outA, byte[] outC, byte[] work, short workOffset) {
    short k = SamConst.CIN_DIGITS;
    short runA = workOffset;
    short runC = (short) (workOffset + 8);
    short nextA = (short) (workOffset + 16);
    short nextC = (short) (workOffset + 24);
    short zero = (short) (workOffset + 32);
    Util.arrayCopyNonAtomic(a, (short) 0, outA, (short) 0, k);
    Util.arrayCopyNonAtomic(c, (short) 0, outC, (short) 0, k);
    for (short j = 1; j < SamConst.JUMP_MAPS; j++) {
      short previous = (short) ((short) (j - 1) * k);
      Util.arrayFillNonAtomic(work, workOffset, (short) 40, (byte) 0);
      work[runA] = (byte) 1;
      for (short r = 0; r < (short) 10; r++) {
        step(outA, previous, work, runA, work, zero, k, work, nextA);
        step(outA, previous, work, runC, outC, previous, k, work, nextC);
        Util.arrayCopyNonAtomic(work, nextA, work, runA, (short) 16);
      }
      Util.arrayCopyNonAtomic(work, runA, outA, (short) (j * k), k);
      Util.arrayCopyNonAtomic(work, runC, outC, (short) (j * k), k);
    }
    Util.arrayFillNonAtomic(work, workOffset, (short) 40, (byte) 0);
  }

  /**
   * Recovers the index n (0 &lt;= n &lt; 10^8) with f^n(x0) = target, digit by digit.
   *
   * <p>For a full-period LCG mod 10^8, x mod 10^j is itself a full-period LCG mod 10^j, so x_n mod
   * 10^j depends only on n mod 10^j. Starting from y = x0, digit j of n (j = 1..8) is the number of
   * applications of M_j = f^(10^(j-1)) needed before the low j digits of y equal those of the
   * target; at most 9 applications are tried per digit.
   *
   * @param n destination of the 8 little-endian digits of the index
   * @param work 16 octets of work area (y and the next value), zeroized on return
   * @return false if no index was found (the parameters are not full period)
   */
  static boolean recoverIndex(
      byte[] jumpA,
      byte[] jumpC,
      byte[] x0,
      byte[] target,
      short targetOffset,
      byte[] work,
      short workOffset,
      byte[] n,
      short nOffset) {
    short k = SamConst.CIN_DIGITS;
    short y = workOffset;
    short next = (short) (workOffset + 8);
    Util.arrayCopyNonAtomic(x0, (short) 0, work, y, k);
    boolean found = true;
    for (short j = 0; j < k && found; j++) {
      found = false;
      for (short t = 0; t < (short) 10 && !found; t++) {
        if (Util.arrayCompare(work, y, target, targetOffset, (short) (j + 1)) == (byte) 0) {
          n[(short) (nOffset + j)] = (byte) t;
          found = true;
        } else {
          step(jumpA, (short) (j * k), work, y, jumpC, (short) (j * k), k, work, next);
          Util.arrayCopyNonAtomic(work, next, work, y, k);
        }
      }
    }
    Util.arrayFillNonAtomic(work, workOffset, (short) 16, (byte) 0);
    return found;
  }

  /** Returns true when every one of the k entries is a decimal digit value 0..9. */
  static boolean isDigits(byte[] digits, short offset, short k) {
    for (short i = 0; i < k; i++) {
      byte d = digits[(short) (offset + i)];
      if (d < (byte) 0 || d > (byte) 9) return false;
    }
    return true;
  }

  /**
   * Checks the Hull-Dobell full-period conditions for m = 10^k (k >= 2).
   *
   * <p>Hull and Dobell (1962): the period is m if and only if gcd(c, m) = 1, a - 1 is divisible by
   * every prime factor of m, and a - 1 is divisible by 4 when 4 divides m. For m = 10^k this is:
   * the units digit of c is 1, 3, 7 or 9, and a = 1 mod 20 (units digit 1 and an even tens digit).
   * The multiplier a = 1 is excluded because it degenerates to a counter.
   */
  static boolean isHullDobell(byte[] a, short aOffset, byte[] c, short cOffset, short k) {
    if (k < (short) 2) return false;
    byte c0 = c[cOffset];
    if (c0 != (byte) 1 && c0 != (byte) 3 && c0 != (byte) 7 && c0 != (byte) 9) return false;
    if (a[aOffset] != (byte) 1) return false;
    if ((a[(short) (aOffset + 1)] & (byte) 1) != (byte) 0) return false;
    for (short i = 1; i < k; i++) {
      if (a[(short) (aOffset + i)] != (byte) 0) return true;
    }
    return false;
  }
}
