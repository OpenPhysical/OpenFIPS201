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

/**
 * OPID layout v2: {@code IIII | E | L}, 17 ASCII digits with no separators. IIII is the plaintext
 * IIN, E = FF1_K(batch | x_n, ASCII(IIN)) the 12 enciphered digits, and L the Luhn mod-10 check
 * digit over the 16 digits IIII | E.
 */
final class Opid {
  private Opid() {}

  /**
   * Computes the Luhn check digit over digit values (0..9, most significant first).
   *
   * <p>ISO/IEC 7812-1 Annex B: starting from the rightmost payload digit, every second digit is
   * doubled (subtracting 9 when the result exceeds 9) and the check digit makes the total a
   * multiple of ten.
   *
   * @return the check digit value 0..9
   */
  static byte luhn(byte[] digits, short offset, short length) {
    short sum = 0;
    boolean doubled = true;
    for (short i = (short) (offset + length - 1); i >= offset; i--) {
      short d = digits[i];
      if (doubled) {
        d = (short) (d * 2);
        if (d > (short) 9) d = (short) (d - 9);
      }
      // sum <= 18 * 9: no overflow for at most 17 payload digits
      sum = (short) (sum + d);
      doubled = !doubled;
    }
    return (byte) ((short) (10 - (short) (sum % 10)) % 10);
  }

  /**
   * Renders the 17-digit OPID IIII | E | L in ASCII.
   *
   * @param state provisioned issuer digits
   * @param e the 12 enciphered digit values E, most significant first
   * @param out destination of the 17 ASCII digits
   * @return {@link SamConst#LENGTH_OPID}
   */
  static short render(SamState state, byte[] e, short eOffset, byte[] out, short outOffset) {
    short cursor = outOffset;
    for (short i = 0; i < SamConst.ISSUER_DIGITS; i++) out[cursor++] = state.issuerDigits[i];
    for (short i = 0; i < SamConst.ENCIPHERED_DIGITS; i++) out[cursor++] = e[(short) (eOffset + i)];
    byte check = luhn(out, outOffset, (short) (cursor - outOffset));
    out[cursor++] = check;
    for (short i = outOffset; i < cursor; i++) out[i] = (byte) (out[i] + (byte) '0');
    return SamConst.LENGTH_OPID;
  }

  /**
   * Parses a 17-digit ASCII OPID into digit values in place at {@code out}. Returns false unless
   * every octet is an ASCII digit and the Luhn digit over all 17 digits checks.
   */
  static boolean parse(byte[] in, short offset, byte[] out, short outOffset) {
    for (short i = 0; i < SamConst.LENGTH_OPID; i++) {
      byte c = in[(short) (offset + i)];
      if (c < (byte) '0' || c > (byte) '9') return false;
      out[(short) (outOffset + i)] = (byte) (c - (byte) '0');
    }
    short payload = (short) (SamConst.LENGTH_OPID - 1);
    return luhn(out, outOffset, payload) == out[(short) (outOffset + payload)];
  }
}
