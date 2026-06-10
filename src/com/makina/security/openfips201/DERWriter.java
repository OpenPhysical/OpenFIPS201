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

package com.makina.security.openfips201;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.framework.Util;

/**
 * Minimal definite-length DER writer for certificate assembly.
 *
 * <p>Java Card does not provide a growable DER stream, so {@link #begin(byte)} reserves the largest
 * length form this applet needs and {@link #end()} backpatches and compacts the content to the
 * shortest DER length encoding. The main singleton writes the outer certificate and the nested
 * singleton is available for helpers that need to build an embedded structure, such as Subject
 * Public Key Info, without disturbing the outer writer's depth stack.
 *
 * <p>The writer deliberately implements only the DER primitives needed by the applet, including
 * positive INTEGER encoding for RSA modulus and serial-number values.
 */
final class DERWriter {

  private static final short MAX_DEPTH = (short) 0x0C;
  private static DERWriter instance;
  private static DERWriter nestedInstance;

  private byte[] buffer;
  private short offset;
  private short limit;
  private final short[] lengthOffsets;
  private short depth;

  private DERWriter() {
    short[] offsets;
    try {
      offsets = JCSystem.makeTransientShortArray(MAX_DEPTH, JCSystem.CLEAR_ON_DESELECT);
    } catch (SystemException e) {
      // The depth stack holds structure offsets only, never key material, so persistent memory
      // is an acceptable substitute when the platform cannot provide a transient array.
      offsets = new short[MAX_DEPTH];
    }
    lengthOffsets = offsets;
  }

  static DERWriter getInstance() {
    if (instance == null) instance = new DERWriter();
    return instance;
  }

  static DERWriter getNestedInstance() {
    if (nestedInstance == null) nestedInstance = new DERWriter();
    return nestedInstance;
  }

  static void terminate() {
    instance = null;
    nestedInstance = null;
    JCSystem.requestObjectDeletion();
  }

  void init(byte[] out, short outOffset) {
    buffer = out;
    offset = outOffset;
    limit = (short) out.length;
    depth = (short) 0x00;
  }

  short getOffset() {
    return offset;
  }

  void setOffset(short value) {
    if (value < (short) 0x00 || value > limit) ISOException.throwIt(ISO7816.SW_FILE_FULL);
    offset = value;
  }

  void begin(byte tag) {
    if (depth >= MAX_DEPTH) ISOException.throwIt(ISO7816.SW_FILE_FULL);
    requireCapacity((short) 0x04);
    buffer[offset++] = tag;
    lengthOffsets[depth++] = offset;
    // Reserve a canonical long-form length. end() compacts to the shortest DER length.
    buffer[offset++] = (byte) 0x82;
    buffer[offset++] = (byte) 0x00;
    buffer[offset++] = (byte) 0x00;
  }

  void end() {
    if (depth == (short) 0x00) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    short lengthOffset = lengthOffsets[--depth];
    short contentOffset = (short) (lengthOffset + 3);
    short contentLength = (short) (offset - contentOffset);
    if (contentLength < (short) 0x00) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    short encodedLengthBytes;

    // JavaCard gives us fixed byte arrays, not a growable DER stream. begin() reserves a 3-byte
    // length and end() compacts the content left when DER permits a shorter length encoding.
    if (contentLength < (short) 0x80) {
      encodedLengthBytes = (short) 0x01;
      Util.arrayCopyNonAtomic(
          buffer,
          contentOffset,
          buffer,
          (short) (lengthOffset + encodedLengthBytes),
          contentLength);
      buffer[lengthOffset] = (byte) contentLength;
    } else if (contentLength < (short) 0x0100) {
      encodedLengthBytes = (short) 0x02;
      Util.arrayCopyNonAtomic(
          buffer,
          contentOffset,
          buffer,
          (short) (lengthOffset + encodedLengthBytes),
          contentLength);
      buffer[lengthOffset] = (byte) 0x81;
      buffer[(short) (lengthOffset + 1)] = (byte) contentLength;
    } else {
      encodedLengthBytes = (short) 0x03;
      buffer[lengthOffset] = (byte) 0x82;
      Util.setShort(buffer, (short) (lengthOffset + 1), contentLength);
    }

    offset = (short) (lengthOffset + encodedLengthBytes + contentLength);
  }

  void write(byte value) {
    requireCapacity((short) 0x01);
    buffer[offset++] = value;
  }

  void write(byte[] in, short inOffset, short length) {
    requireCapacity(length);
    offset = Util.arrayCopyNonAtomic(in, inOffset, buffer, offset, length);
  }

  void writeTlv(byte tag, byte[] in, short inOffset, short length) {
    requireCapacity((short) 0x01);
    buffer[offset++] = tag;
    writeLength(length);
    write(in, inOffset, length);
  }

  void writeIntegerByte(byte value) {
    requireCapacity((short) 0x03);
    buffer[offset++] = (byte) 0x02;
    buffer[offset++] = (byte) 0x01;
    buffer[offset++] = value;
  }

  void writePositiveInteger(byte[] in, short inOffset, short length) {
    requireCapacity((short) (0x03 + length));
    buffer[offset++] = (byte) 0x02;
    if ((in[inOffset] & (byte) 0x80) != (byte) 0) {
      writeLength((short) (length + 1));
      requireCapacity((short) 0x01);
      buffer[offset++] = (byte) 0x00;
    } else {
      writeLength(length);
    }
    write(in, inOffset, length);
  }

  void writeLength(short length) {
    if (length < (short) 0x00) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    if (length < (short) 0x80) {
      requireCapacity((short) 0x01);
      buffer[offset++] = (byte) length;
    } else if (length < (short) 0x0100) {
      requireCapacity((short) 0x02);
      buffer[offset++] = (byte) 0x81;
      buffer[offset++] = (byte) length;
    } else {
      requireCapacity((short) 0x03);
      buffer[offset++] = (byte) 0x82;
      Util.setShort(buffer, offset, length);
      offset += (short) 0x02;
    }
  }

  private void requireCapacity(short length) {
    short next = (short) (offset + length);
    if (length < (short) 0x00 || next < offset || next > limit) {
      ISOException.throwIt(ISO7816.SW_FILE_FULL);
    }
  }
}
