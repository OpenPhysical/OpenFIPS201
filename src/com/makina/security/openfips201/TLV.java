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
import javacard.framework.Util;

final class TLV {
  private TLV() {
    // Prevent instantiation
  }

  // Tag Class
  static final byte CLASS_UNIVERSAL = (byte) 0x00;
  static final byte CLASS_APPLICATION = (byte) 0x40;
  static final byte CLASS_CONTEXT = (byte) 0x80;
  static final byte CLASS_PRIVATE = (byte) 0xC0;

  // Length Constants
  static final short LENGTH_1BYTE = (short) 1;
  static final short LENGTH_2BYTE = (short) 2;
  static final short LENGTH_3BYTE = (short) 3;

  static final short LENGTH_1BYTE_MAX = (short) 0x7F;
  static final short LENGTH_2BYTE_MAX = (short) 0xFF;
  static final short LENGTH_3BYTE_MAX = (short) 0x7FFF;

  // Masks
  static final byte MASK_CONSTRUCTED = (byte) 0x20;
  static final byte MASK_LOW_TAG_NUMBER = (byte) 0x1F;
  static final byte MASK_HIGH_TAG_NUMBER = (byte) 0x7F;
  static final byte MASK_TAG_MULTI_BYTE = (byte) 0x1F;
  static final byte MASK_HIGH_TAG_MOREDATA = (byte) 0x80;
  static final byte MASK_LONG_LENGTH = (byte) 0x80;
  static final byte MASK_LENGTH = (byte) 0x7F;

  // Parser limits and the non-throwing parsers' failure result
  static final short INVALID = (short) -1;
  private static final short MAX_SUBSEQUENT_TAG_BYTES = (short) 2;

  // Universal tags
  static final byte ASN1_BOOLEAN = (byte) 0x01;
  static final byte ASN1_INTEGER = (byte) 0x02;
  static final byte ASN1_BIT_STRING = (byte) 0x03;
  static final byte ASN1_OCTET_STRING = (byte) 0x04;
  static final byte ASN1_NULL = (byte) 0x05;
  static final byte ASN1_OBJECT = (byte) 0x06;
  static final byte ASN1_ENUMERATED = (byte) 0x0A;
  static final byte ASN1_SEQUENCE = (byte) 0x10; //  "Sequence" and "Sequence of"
  static final byte ASN1_SET = (byte) 0x11; //  "Set" and "Set of"
  static final byte ASN1_PRINT_STRING = (byte) 0x13;
  static final byte ASN1_T61_STRING = (byte) 0x14;
  static final byte ASN1_IA5_STRING = (byte) 0x16;
  static final byte ASN1_UTC_TIME = (byte) 0x17;

  // Type Values
  static final byte TRUE = (byte) 0xFF;
  static final byte FALSE = (byte) 0x00;

  static short encodedLengthSize(short length) {
    if (length < (short) 0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    if (length <= LENGTH_1BYTE_MAX) return LENGTH_1BYTE;
    if (length <= LENGTH_2BYTE_MAX) return LENGTH_2BYTE;
    return LENGTH_3BYTE;
  }

  static short writeLength(byte[] buffer, short offset, short length) {
    if (length < (short) 0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    if (length <= LENGTH_1BYTE_MAX) {
      buffer[offset] = (byte) length;
      return LENGTH_1BYTE;
    }
    if (length <= LENGTH_2BYTE_MAX) {
      buffer[offset++] = (byte) 0x81;
      buffer[offset] = (byte) length;
      return LENGTH_2BYTE;
    }
    buffer[offset++] = (byte) 0x82;
    Util.setShort(buffer, offset, length);
    return LENGTH_3BYTE;
  }

  /**
   * Returns the value length of the BER-TLV object at {@code tlvOffset}.
   *
   * @throws ISOException with {@link ISO7816#SW_WRONG_DATA} when {@link #valueLengthOrInvalid}
   *     rejects the header
   */
  static short readLength(byte[] buffer, short tlvOffset, short limit, boolean strictDer) {
    return requireValid(valueLengthOrInvalid(buffer, tlvOffset, limit, strictDer));
  }

  /**
   * Returns the offset of the first value octet of the BER-TLV object at {@code tlvOffset}.
   *
   * @throws ISOException with {@link ISO7816#SW_WRONG_DATA} when {@link #valueOffsetOrInvalid}
   *     rejects the header
   */
  static short dataOffset(byte[] buffer, short tlvOffset, short limit, boolean strictDer) {
    return requireValid(valueOffsetOrInvalid(buffer, tlvOffset, limit, strictDer));
  }

  /**
   * Returns the exclusive end of the BER-TLV object at {@code tlvOffset}.
   *
   * @throws ISOException with {@link ISO7816#SW_WRONG_DATA} when {@link #endOrInvalid} rejects the
   *     object
   */
  static short objectEnd(byte[] buffer, short tlvOffset, short limit, boolean strictDer) {
    return requireValid(endOrInvalid(buffer, tlvOffset, limit, strictDer));
  }

  /**
   * Returns the value length of the BER-TLV object at {@code tlvOffset}, or {@link #INVALID}.
   *
   * <p>This is the single BER-TLV header parser of the applet. Only the tag and length fields must
   * lie below {@code limit}; the value may extend past it, as for the first frame of a chained PUT
   * DATA. ISO/IEC 7816-4 Section 6.3 "precludes the use of the "indefinite length" (coded '80')"
   * and "recommends to use the shortest possible coding of the length field, according to DER
   * encoding rules". Long-form lengths are limited to two subsequent octets that encode a
   * non-negative {@code short}. The shortest coding is required only with {@code strictDer}; BER
   * permits longer codings, so other callers accept them.
   */
  static short valueLengthOrInvalid(
      byte[] buffer, short tlvOffset, short limit, boolean strictDer) {
    short lengthOffset = lengthOffsetOrInvalid(buffer, tlvOffset, limit);
    if (lengthOffset == INVALID) return INVALID;
    short first = (short) (buffer[lengthOffset] & 0xFF);
    if (first <= LENGTH_1BYTE_MAX) return first;

    short count = (short) (first & MASK_LENGTH);
    short valueOffset = (short) (lengthOffset + 1 + count);
    if (count == (short) 0
        || count > (short) 2
        || valueOffset > limit
        || valueOffset < lengthOffset) {
      return INVALID;
    }
    short length;
    short minimum;
    if (count == (short) 1) {
      length = (short) (buffer[(short) (lengthOffset + 1)] & 0xFF);
      minimum = (short) (LENGTH_1BYTE_MAX + 1);
    } else {
      length = Util.getShort(buffer, (short) (lengthOffset + 1));
      minimum = (short) (LENGTH_2BYTE_MAX + 1);
    }
    if (length < (short) 0 || (strictDer && length < minimum)) return INVALID;
    return length;
  }

  /**
   * Returns the offset of the first value octet of the BER-TLV object at {@code tlvOffset}, or
   * {@link #INVALID} when {@link #valueLengthOrInvalid} rejects the header.
   */
  static short valueOffsetOrInvalid(
      byte[] buffer, short tlvOffset, short limit, boolean strictDer) {
    if (valueLengthOrInvalid(buffer, tlvOffset, limit, strictDer) == INVALID) return INVALID;
    short lengthOffset = lengthOffsetOrInvalid(buffer, tlvOffset, limit);
    byte first = buffer[lengthOffset];
    short count = (first & MASK_LONG_LENGTH) == 0 ? (short) 0 : (short) (first & MASK_LENGTH);
    return (short) (lengthOffset + 1 + count);
  }

  /**
   * Returns the exclusive end of the BER-TLV object at {@code tlvOffset}, or {@link #INVALID} when
   * its header is malformed or its value does not end at or before {@code limit}.
   */
  static short endOrInvalid(byte[] buffer, short tlvOffset, short limit, boolean strictDer) {
    short length = valueLengthOrInvalid(buffer, tlvOffset, limit, strictDer);
    if (length == INVALID) return INVALID;
    short valueOffset = valueOffsetOrInvalid(buffer, tlvOffset, limit, strictDer);
    if (length > (short) (limit - valueOffset)) return INVALID;
    return (short) (valueOffset + length);
  }

  /**
   * Returns the offset of the length field of the BER-TLV object at {@code tlvOffset}, or {@link
   * #INVALID}.
   *
   * <p>ISO/IEC 7816-4 Section 6.3: "ISO/IEC 7816 (all parts) supports tag fields of one, two and
   * three bytes; longer tag fields are RFU." A first subsequent tag byte with bits b7-b1 set to
   * zero is a non-minimal tag number and is rejected.
   */
  private static short lengthOffsetOrInvalid(byte[] buffer, short tlvOffset, short limit) {
    if (tlvOffset < (short) 0 || tlvOffset >= limit) return INVALID;
    short cursor = tlvOffset;
    if ((buffer[cursor] & MASK_TAG_MULTI_BYTE) == MASK_TAG_MULTI_BYTE) {
      short subsequent = (short) 0;
      do {
        cursor++;
        if (cursor >= limit || subsequent == MAX_SUBSEQUENT_TAG_BYTES) return INVALID;
        if (subsequent == (short) 0 && (buffer[cursor] & MASK_HIGH_TAG_NUMBER) == 0) {
          return INVALID;
        }
        subsequent++;
      } while ((buffer[cursor] & MASK_HIGH_TAG_MOREDATA) == MASK_HIGH_TAG_MOREDATA);
    }
    cursor++;
    return cursor < limit ? cursor : INVALID;
  }

  private static short requireValid(short value) {
    if (value == INVALID) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    return value;
  }
}
