/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
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

package dev.mistial.tools.openfips201.provisioning;

import dev.mistial.tools.openfips201.common.BerTlvWriter;
import dev.mistial.tools.openfips201.common.ByteArrays;
import java.math.BigInteger;

/** Minimal BER-TLV helpers shared by conformance provisioning APDU builders. */
public final class AdminTlv {
  private AdminTlv() {}

  public static byte[] tlv(int tag, byte[] value) {
    return BerTlvWriter.encode(tag, value);
  }

  public static byte[] concat(byte[]... parts) {
    return ByteArrays.concat(parts);
  }

  /** Unsigned fixed-width encoding of a BigInteger (big-endian, zero-padded or trimmed). */
  public static byte[] fixed(BigInteger value, int length) {
    return ByteArrays.unsignedFixed(value, length);
  }

  public static byte[] copyOf(byte[] value) {
    return ByteArrays.copyOfNullable(value);
  }
}
