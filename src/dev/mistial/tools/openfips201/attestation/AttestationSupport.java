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

package dev.mistial.tools.openfips201.attestation;

import static dev.mistial.tools.openfips201.common.ByteArrays.concat;

import dev.mistial.tools.openfips201.common.BerTlvWriter;
import dev.mistial.tools.openfips201.crypto.CryptoProviders;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

/** PIV key-definition constants and encodings shared by the attestation proof flow. */
final class AttestationSupport {
  static final byte ALG_ECC_P256 = (byte) 0x11;
  static final byte ROLE_SIGN = (byte) 0x04;
  static final byte ACCESS_ALWAYS = (byte) 0x7F;

  private AttestationSupport() {}

  static void ensureProvider() {
    CryptoProviders.ensureBouncyCastle();
  }

  /** The uncompressed point {@code 04 || X || Y} of an EC public key. */
  static byte[] publicPoint(PublicKey publicKey) {
    if (!(publicKey instanceof ECPublicKey)) {
      throw new IllegalArgumentException("public key must be an EC public key");
    }
    ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
    int size = (ecPublicKey.getParams().getCurve().getField().getFieldSize() + 7) / 8;
    ECPoint point = ecPublicKey.getW();
    return concat(
        new byte[] {(byte) 0x04}, fixed(point.getAffineX(), size), fixed(point.getAffineY(), size));
  }

  static byte[] tlv(int tag, byte[] value) {
    return BerTlvWriter.encode(tag, value);
  }

  static byte[] fixed(BigInteger value, int size) {
    byte[] source = value.toByteArray();
    if (source.length > size + 1 || (source.length == size + 1 && source[0] != (byte) 0x00)) {
      throw new IllegalArgumentException("Integer does not fit in " + size + " bytes");
    }
    byte[] output = new byte[size];
    int copyLength = Math.min(source.length, size);
    System.arraycopy(source, source.length - copyLength, output, size - copyLength, copyLength);
    return output;
  }
}
