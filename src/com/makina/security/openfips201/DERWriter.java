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
 * <p>All cursor state (output buffer reference, write offset, limit and depth stack) is held in
 * CLEAR_ON_DESELECT transient memory. Building a certificate therefore performs no persistent
 * writes, and a writer left mid-structure by a tear or deselect starts from a cleared state.
 *
 * <p>The writer deliberately implements only the DER primitives needed by the applet. INTEGER
 * values written through {@link #writePositiveInteger} are canonical per X.690 §8.3.2: redundant
 * leading zero octets are removed and a single zero octet is prepended only when the most
 * significant bit of the magnitude is set.
 */
final class DERWriter {

  private static final short MAX_DEPTH = (short) 0x0C;

  // Cursor state indices that follow the depth stack in the transient state array.
  private static final short STATE_OFFSET = MAX_DEPTH;
  private static final short STATE_LIMIT = (short) (MAX_DEPTH + 1);
  private static final short STATE_DEPTH = (short) (MAX_DEPTH + 2);
  private static final short LENGTH_STATE = (short) (MAX_DEPTH + 3);

  private static DERWriter instance;
  private static DERWriter nestedInstance;

  // Holds the output buffer reference for the current structure.
  private final Object[] bufferRef;

  // Depth stack of reserved length offsets, followed by offset, limit and depth.
  private final short[] state;

  private DERWriter() {
    bufferRef = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
    state = JCSystem.makeTransientShortArray(LENGTH_STATE, JCSystem.CLEAR_ON_DESELECT);
  }

  static void initialize() {
    if (instance == null) instance = new DERWriter();
    if (nestedInstance == null) nestedInstance = new DERWriter();
  }

  static DERWriter getInstance() {
    if (instance == null) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    return instance;
  }

  static DERWriter getNestedInstance() {
    if (nestedInstance == null) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    return nestedInstance;
  }

  static void terminate() {
    instance = null;
    nestedInstance = null;
    JCSystem.requestObjectDeletion();
  }

  void init(byte[] out, short outOffset) {
    bufferRef[0] = out;
    state[STATE_OFFSET] = outOffset;
    state[STATE_LIMIT] = (short) out.length;
    state[STATE_DEPTH] = (short) 0x00;
  }

  short getOffset() {
    return state[STATE_OFFSET];
  }

  void setOffset(short value) {
    if (value < (short) 0x00 || value > state[STATE_LIMIT]) {
      ISOException.throwIt(ISO7816.SW_FILE_FULL);
    }
    state[STATE_OFFSET] = value;
  }

  void begin(byte tag) {
    short depth = state[STATE_DEPTH];
    if (depth >= MAX_DEPTH) ISOException.throwIt(ISO7816.SW_FILE_FULL);
    requireCapacity((short) 0x04);
    byte[] buffer = buffer();
    short offset = state[STATE_OFFSET];
    buffer[offset++] = tag;
    state[depth] = offset;
    state[STATE_DEPTH] = (short) (depth + 1);
    // Reserve a canonical long-form length. end() compacts to the shortest DER length.
    buffer[offset++] = (byte) 0x82;
    buffer[offset++] = (byte) 0x00;
    buffer[offset++] = (byte) 0x00;
    state[STATE_OFFSET] = offset;
  }

  void end() {
    short depth = state[STATE_DEPTH];
    if (depth == (short) 0x00) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    depth--;
    state[STATE_DEPTH] = depth;
    byte[] buffer = buffer();
    short lengthOffset = state[depth];
    short contentOffset = (short) (lengthOffset + 3);
    short contentLength = (short) (state[STATE_OFFSET] - contentOffset);
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

    state[STATE_OFFSET] = (short) (lengthOffset + encodedLengthBytes + contentLength);
  }

  void write(byte value) {
    requireCapacity((short) 0x01);
    short offset = state[STATE_OFFSET];
    buffer()[offset] = value;
    state[STATE_OFFSET] = (short) (offset + 1);
  }

  void write(byte[] in, short inOffset, short length) {
    requireCapacity(length);
    state[STATE_OFFSET] =
        Util.arrayCopyNonAtomic(in, inOffset, buffer(), state[STATE_OFFSET], length);
  }

  void writeTlv(byte tag, byte[] in, short inOffset, short length) {
    write(tag);
    writeLength(length);
    write(in, inOffset, length);
  }

  void writeIntegerByte(byte value) {
    requireCapacity((short) 0x03);
    byte[] buffer = buffer();
    short offset = state[STATE_OFFSET];
    buffer[offset++] = (byte) 0x02;
    buffer[offset++] = (byte) 0x01;
    buffer[offset++] = value;
    state[STATE_OFFSET] = offset;
  }

  /**
   * Writes an unsigned big-endian magnitude as a canonical DER INTEGER.
   *
   * <p>X.690 §8.3.2: "If the contents octets of an integer value encoding consist of more than one
   * octet, then the bits of the first octet and bit 8 of the second octet shall not all be ones;
   * and shall not all be zero." Leading zero octets of the magnitude are therefore removed, a
   * single zero octet is kept for the value zero, and one zero octet is prepended when bit 8 of the
   * first remaining octet is set so the value stays positive. The input may overlap the output
   * region because copies use {@link Util#arrayCopyNonAtomic}, which handles overlap.
   *
   * @param in the magnitude buffer
   * @param inOffset the offset of the magnitude
   * @param length the magnitude length, which must be at least one octet
   */
  void writePositiveInteger(byte[] in, short inOffset, short length) {
    if (length <= (short) 0x00) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    while (length > (short) 0x01 && in[inOffset] == (byte) 0x00) {
      inOffset++;
      length--;
    }
    boolean padded = (in[inOffset] & (byte) 0x80) != (byte) 0;
    short contentLength = padded ? (short) (length + 1) : length;
    requireCapacity((short) (0x01 + TLV.encodedLengthSize(contentLength) + contentLength));
    write((byte) 0x02);
    writeLength(contentLength);
    if (padded) write((byte) 0x00);
    write(in, inOffset, length);
  }

  void writeLength(short length) {
    short encodedLength = TLV.encodedLengthSize(length);
    requireCapacity(encodedLength);
    short offset = state[STATE_OFFSET];
    state[STATE_OFFSET] = (short) (offset + TLV.writeLength(buffer(), offset, length));
  }

  private byte[] buffer() {
    byte[] buffer = (byte[]) bufferRef[0];
    if (buffer == null) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    return buffer;
  }

  private void requireCapacity(short length) {
    short offset = state[STATE_OFFSET];
    short next = (short) (offset + length);
    if (length < (short) 0x00 || next < offset || next > state[STATE_LIMIT]) {
      ISOException.throwIt(ISO7816.SW_FILE_FULL);
    }
  }
}
