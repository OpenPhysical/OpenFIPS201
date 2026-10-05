/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2017 Commonwealth of Australia
 * Author: Kim O'Sullivan - Makina (kim@makina.com.au)
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
 * Supports reading the modified BER-TLV format that is used by PIV for data objects. The format is
 * essentially BER-TLV, with the following exceptions: - The hierarchy is flat (constructed objects
 * are outside the scope of PIV to interpret itself) - The TAG identifier is non-compliant (no
 * class, no constructed flag, no length formatting)
 */
final class TLVReader {

  // The length of the entire TLV buffer for boundary checking
  private static final short CONTEXT_LENGTH = (short) 0;
  // The current position in the buffer
  private static final short CONTEXT_POSITION = (short) 1;
  // The offset given when the data was set, allowing for a reset
  private static final short CONTEXT_POSITION_RESET = (short) 2;
  // Exclusive ends of the open constructed objects during validation, innermost last
  private static final short CONTEXT_OPEN_ENDS = (short) 3;
  // Maximum number of nested non-empty constructed objects accepted by validation
  private static final short MAX_NESTING = (short) 8;
  private static final short LENGTH_CONTEXT = (short) (CONTEXT_OPEN_ENDS + MAX_NESTING);

  //
  // CONSTANTS
  //
  private final Object[] dataPtr;

  private final short[] context;

  private static TLVReader instance;

  private TLVReader() {
    dataPtr = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
    context = JCSystem.makeTransientShortArray(LENGTH_CONTEXT, JCSystem.CLEAR_ON_DESELECT);
  }

  static TLVReader getInstance() {

    if (instance == null) {
      instance = new TLVReader();
    }

    return instance;
  }

  static void terminate() {
    instance = null;
    JCSystem.requestObjectDeletion();
  }

  /**
   * Returns the length of the data element for the tag found at offset
   *
   * @param data The data to search
   * @param offset The offset of the tag to read
   * @return The length of the data element
   */
  static short getLength(byte[] data, short offset) throws ISOException {
    return TLV.readLength(data, offset, (short) data.length);
  }

  /**
   * Gets the offset to the data element of the tag found at the requested offset
   *
   * @param data The buffer containing the TLV object
   * @param offset The offset of the TLV element to inspect
   * @return The data element offset
   */
  static short getDataOffset(byte[] data, short offset) {
    return TLV.dataOffset(data, offset, (short) data.length);
  }

  /**
   * Initialises the TLVReader object with a data buffer, starting offset and length
   *
   * @param buffer The buffer to read the object from
   * @param offset The starting offset for the object
   * @param length The length of the data object
   */
  void init(byte[] buffer, short offset, short length) {

    if (buffer == null
        || offset < (short) 0
        || length <= (short) 0
        || offset > (short) (buffer.length - length)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    dataPtr[0] = buffer;
    context[CONTEXT_POSITION] = offset;
    context[CONTEXT_POSITION_RESET] = offset;
    context[CONTEXT_LENGTH] = length;

    if (!validate()) {
      clear();
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
  }

  /**
   * Checks that the input is a concatenation of well-formed BER-TLV objects and that the value of
   * every non-empty constructed object is itself such a concatenation, ending exactly at its
   * parent's end.
   *
   * <p>The walk is iterative: the ends of the open constructed objects are kept in {@link
   * #context}, so input received before any authentication cannot grow the Java Card stack. At most
   * {@link #MAX_NESTING} non-empty constructed objects may be open at once.
   */
  private boolean validate() {
    byte[] data = (byte[]) dataPtr[0];
    short position = context[CONTEXT_POSITION_RESET];
    short end = (short) (position + context[CONTEXT_LENGTH]);
    short depth = (short) 0;

    while (true) {
      short parentEnd = depth == (short) 0 ? end : context[(short) (CONTEXT_OPEN_ENDS + depth - 1)];
      if (position == parentEnd) {
        if (depth == (short) 0) return true;
        depth--;
        continue;
      }

      short objectEnd = TLV.endOrInvalid(data, position, parentEnd);
      if (objectEnd == TLV.INVALID) return false;
      short valueOffset = TLV.valueOffsetOrInvalid(data, position, parentEnd);
      if ((data[position] & TLV.MASK_CONSTRUCTED) == 0 || valueOffset == objectEnd) {
        position = objectEnd;
        continue;
      }
      if (depth == MAX_NESTING) return false;
      context[(short) (CONTEXT_OPEN_ENDS + depth)] = objectEnd;
      depth++;
      position = valueOffset;
    }
  }

  /***
   * Evaluates whether we have moved past the end of the buffer supplied at init()
   * @return True if the current position exceeds the length of the supplied buffer
   */
  boolean isEOF() {
    return (context[CONTEXT_POSITION]
        >= (short) (context[CONTEXT_POSITION_RESET] + context[CONTEXT_LENGTH]));
  }

  /** Clears any active TLV object being read */
  void clear() {
    dataPtr[0] = null;

    context[CONTEXT_POSITION] = 0;
    context[CONTEXT_POSITION_RESET] = 0;
    context[CONTEXT_LENGTH] = 0;
  }

  /**
   * Moves to the next tag
   *
   * @return True if the move was successful, or False if the buffer was overrun
   */
  boolean moveNext() {
    // Skip to the next tag
    short dataLength = getLength();
    context[CONTEXT_POSITION] = getDataOffset();
    context[CONTEXT_POSITION] += dataLength;
    return ((short) (context[CONTEXT_POSITION] - context[CONTEXT_POSITION_RESET])
        < context[CONTEXT_LENGTH]);
  }

  /**
   * Moves to the first tag inside the current tag
   *
   * @return True if the move was successful, or False if the buffer was overrun
   */
  boolean moveInto() {
    context[CONTEXT_POSITION] = getDataOffset();
    return ((short) (context[CONTEXT_POSITION] - context[CONTEXT_POSITION_RESET])
        < context[CONTEXT_LENGTH]);
  }

  /**
   * Tests if the current tag matches the supplied one
   *
   * @param tag The tag to find
   * @return True if the current tag matches the supplied one
   */
  boolean match(byte tag) {
    if (isEOF()) return false;
    byte[] data = (byte[]) dataPtr[0];
    return (tag == data[context[CONTEXT_POSITION]]);
  }

  /**
   * Tests if the current value matches the data for the current tag
   *
   * @param value The value to compare against
   * @return True if the first byte of the data matches the comparison
   */
  boolean matchData(byte value) {
    byte[] data = (byte[]) dataPtr[0];
    return (value == data[getDataOffset()]);
  }

  /**
   * Returns the tag identifier for the current tag
   *
   * @return The identifier for the current tag
   */
  byte getTag() {
    byte[] data = (byte[]) dataPtr[0];
    return data[context[CONTEXT_POSITION]];
  }

  /**
   * Returns true if the current tag is a constructed tag (has children)
   *
   * @return True if the current tag is constructed
   */
  boolean isConstructed() {
    return ((getTag() & TLV.MASK_CONSTRUCTED) == TLV.MASK_CONSTRUCTED);
  }

  /**
   * Gets the length of the current tag's data element
   *
   * @return The length of the current tag's data element
   */
  short getLength() {
    return getLength((byte[]) dataPtr[0], context[CONTEXT_POSITION]);
  }

  /**
   * Returns true of the current tag has a zero-length (empty) data element
   *
   * @return Whether the current tag has a zero length element
   */
  boolean isNull() {
    return (getLength() == (short) 0);
  }

  /**
   * Gets the current position within the TLV object
   *
   * @return The current position within the TLV object
   */
  short getOffset() {
    return context[CONTEXT_POSITION];
  }

  /**
   * Returns the exclusive end of the reader's current top-level input range.
   *
   * @return reset position plus the validated input length
   */
  short getEndOffset() {
    return (short) (context[CONTEXT_POSITION_RESET] + context[CONTEXT_LENGTH]);
  }

  public byte[] getBuffer() {
    return (byte[]) dataPtr[0];
  }

  /**
   * Gets the offset in the current tag to it's data element
   *
   * @return The data offset in the current tag
   */
  short getDataOffset() {
    return getDataOffset((byte[]) dataPtr[0], context[CONTEXT_POSITION]);
  }

  /**
   * Reads the current tag value as a short integer value
   *
   * @return The current tag value as a short integer
   */
  short toShort() throws ISOException {
    byte[] data = (byte[]) dataPtr[0];
    short length = getLength();
    short offset = getDataOffset();

    if ((short) 1 == length) {
      return (short) (data[offset] & 0xFF);
    } else if ((short) 2 == length) {
      return Util.getShort(data, offset);
    } else {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      return (short) -1; // Dummy
    }
  }

  /**
   * Reads the current tag value as a byte value
   *
   * @return The current tag value as a byte
   */
  byte toByte() throws ISOException {
    byte[] data = (byte[]) dataPtr[0];
    short length = getLength();

    if ((short) 1 == length) {
      return data[getDataOffset()];
    } else {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      return (byte) 0; // Keep compiler happy
    }
  }
}
