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
  private static final short LENGTH_CONTEXT = (short) 4;

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
    return TLV.readLength(data, offset, (short) data.length, false);
  }

  /**
   * Gets the offset to the data element of the tag found at the requested offset
   *
   * @param data The buffer containing the TLV object
   * @param offset The offset of the TLV element to inspect
   * @return The data element offset
   */
  static short getDataOffset(byte[] data, short offset) {
    return TLV.dataOffset(data, offset, (short) data.length, false);
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

  private boolean validate() {
    byte[] data = (byte[]) dataPtr[0];
    short start = context[CONTEXT_POSITION_RESET];
    short end = (short) (start + context[CONTEXT_LENGTH]);
    return validateRange(data, start, end, (byte) 0);
  }

  private static boolean validateRange(byte[] data, short start, short end, byte depth) {
    if (depth > (byte) 8) return false;

    short position = start;
    while (position < end) {
      short tagStart = position;
      byte firstTag = data[position++];
      if ((firstTag & TLV.MASK_TAG_MULTI_BYTE) == TLV.MASK_TAG_MULTI_BYTE) {
        byte tagBytes = 0;
        byte value;
        do {
          if (position >= end || tagBytes == (byte) 2) return false;
          value = data[position++];
          if (tagBytes == 0 && (value & 0x7F) == 0) return false;
          tagBytes++;
        } while ((value & TLV.MASK_HIGH_TAG_MOREDATA) == TLV.MASK_HIGH_TAG_MOREDATA);
      }

      if (position >= end) return false;
      short valueLength;
      short lengthByte = (short) (data[position++] & 0xFF);
      if ((lengthByte & 0x80) == 0) {
        valueLength = lengthByte;
      } else {
        short lengthBytes = (short) (lengthByte & 0x7F);
        if (lengthBytes == 0 || lengthBytes > 2 || position > (short) (end - lengthBytes)) {
          return false;
        }
        if (lengthBytes == 1) {
          valueLength = (short) (data[position++] & 0xFF);
          if (valueLength <= 127) return false;
        } else {
          valueLength = Util.getShort(data, position);
          position += 2;
          if (valueLength <= 255) return false;
        }
      }

      if (valueLength < 0 || position > (short) (end - valueLength)) return false;
      short valueEnd = (short) (position + valueLength);
      if ((data[tagStart] & (byte) 0x20) != 0
          && valueLength != 0
          && !validateRange(data, position, valueEnd, (byte) (depth + 1))) {
        return false;
      }
      position = valueEnd;
    }
    return position == end;
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
   * Tests whether there is a TLV object initialised for reading
   *
   * @return true if there is a TLV object initialised for reading
   */
  boolean isInitialized() {
    return (dataPtr[0] != null);
  }

  /** Restores the current position to the offset originally supplied to init() */
  void resetPosition() throws ISOException {
    if (!isInitialized()) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    context[CONTEXT_POSITION] = context[CONTEXT_POSITION_RESET];
  }

  /**
   * Finds a tag in the currently active TLV object
   *
   * @param tag The tag to find
   * @return True if the requested tag was found before the end of the buffer was reached
   */
  boolean find(byte tag) {
    while ((short) (context[CONTEXT_POSITION] - context[CONTEXT_POSITION_RESET])
        < context[CONTEXT_LENGTH]) {
      // Is this our tag number?
      if (tag == getTag()) return true;

      // Skip to the next tag at this level (i.e. it will not descend into children)
      if (!moveNext()) return false;
    }

    // We didn't find the requested tag
    return false;
  }

  /**
   * Finds a tag in the currently active TLV object
   *
   * @param tag The tag to find
   * @return True if the requested tag was found before the end of the buffer was reached
   */
  boolean find(short tag) {
    while ((short) (context[CONTEXT_POSITION] - context[CONTEXT_POSITION_RESET])
        < context[CONTEXT_LENGTH]) {
      // Is this our tag number?
      if (tag == getTagShort()) return true;

      // Skip to the next tag at this level (i.e. it will not descend into children)
      if (!moveNext()) return false;
    }

    // We didn't find the requested tag
    return false;
  }

  /**
   * Finds a tag in the currently active TLV object, not including the current tag
   *
   * @param tag The tag to find
   * @return True if the requested tag was found before the end of the buffer was reached
   */
  boolean findNext(byte tag) {
    // Skip to the next tag
    if (!moveNext()) return false;

    return find(tag);
  }

  /**
   * Finds a tag in the currently active TLV object, not including the current tag
   *
   * @param tag The tag to find
   * @return True if the requested tag was found before the end of the buffer was reached
   */
  boolean findNext(short tag) {
    // Skip to the next tag
    if (!moveNext()) return false;

    return find(tag);
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
    return matchData(value, (short) 0);
  }

  /**
   * Tests if the current value matches the data for the current tag
   *
   * @param value The value to compare against
   * @param offset The offset within the data to compare against
   * @return True if the first byte of the data matches the comparison
   */
  boolean matchData(byte value, short offset) {
    byte[] data = (byte[]) dataPtr[0];
    offset += getDataOffset();
    return (value == data[offset]);
  }

  /**
   * Tests if the current value matches the data for the current tag
   *
   * @param value The value to compare against
   * @return True if the first two bytes of the data matches the comparison
   */
  boolean matchData(short value) {
    return matchData(value, (short) 0);
  }

  /**
   * Tests if the current value matches the data for the current tag
   *
   * @param value The value to compare against
   * @param offset The offset within the data to compare against
   * @return True if the first two bytes of the data matches the comparison
   */
  boolean matchData(short value, short offset) {
    byte[] data = (byte[]) dataPtr[0];
    offset += getDataOffset();
    return (value == Util.getShort(data, offset));
  }

  /**
   * Tests if the current tag matches the supplied one
   *
   * @param tag The tag to find
   * @return True if the current tag matches the supplied one
   */
  boolean match(short tag) {
    return (tag == Util.getShort((byte[]) dataPtr[0], context[CONTEXT_POSITION]));
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
   * Returns the tag identifier for the current tag
   *
   * @return The identifier for the current tag
   */
  short getTagShort() {
    return Util.getShort((byte[]) dataPtr[0], context[CONTEXT_POSITION]);
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
   * Sets the current position within the TLV object
   *
   * @param offset The current position within the TLV object
   */
  void setOffset(short offset) {
    context[CONTEXT_POSITION] = offset;
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

  /**
   * Reads the current tag value as a boolean value
   *
   * @return True if the current data element is non-zero, otherwise False.
   */
  boolean toBoolean() throws ISOException {
    byte[] data = (byte[]) dataPtr[0];
    short length = getLength();

    if ((short) 1 == length) {
      return (data[getDataOffset()] != (byte) 0);
    } else {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      return false; // Keep compiler happy
    }
  }

  /**
   * Writes the raw bytes for this tag to the specified buffer, which must have enough space to
   * write the entire object to (as per getLength()).
   *
   * @param buffer The buffer to write the bytes to
   * @param offset The offset to start writing from in buffer
   */
  void toBytes(byte[] buffer, short offset) {

    byte[] data = (byte[]) dataPtr[0];
    short dataLength = getLength();
    short dataOffset = getDataOffset();

    Util.arrayCopyNonAtomic(data, dataOffset, buffer, offset, dataLength);
  }
}
