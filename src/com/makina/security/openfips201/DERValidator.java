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

/**
 * Strict DER validation primitives for RFC 5280 certificate fields.
 *
 * <p>Every method is static, allocates nothing and reports any malformed, non-canonical or
 * out-of-profile input with {@link ISO7816#SW_WRONG_DATA}. The class is build-profile independent
 * and carries no preprocessor directives, so other applets in this repository may share it
 * verbatim.
 */
final class DERValidator {

  /** Length of the ASCII {@code YYYYMMDDHHMMSS} form written by {@link #normalizeTime}. */
  static final short LENGTH_NORMALIZED_TIME = (short) 14;

  private DERValidator() {}

  /**
   * Validates one complete DER-encoded X.501 Name used as the certificate issuer.
   *
   * <p>RFC 5280, Section 4.1 requires certificates to use DER. X.690, Section 11.6 requires SET OF
   * components to &quot;appear in ascending order.&quot; This method also rejects empty names,
   * malformed attributes, unsupported string encodings, and trailing objects.
   *
   * @param buffer input buffer
   * @param offset first DER octet
   * @param length number of input octets
   * @throws ISOException with {@link ISO7816#SW_WRONG_DATA} if validation fails
   */
  static void validateDerName(byte[] buffer, short offset, short length) {
    short cursor = validateSingleDerObject(buffer, offset, length, (byte) 0x30);
    short end = (short) (offset + length);
    if (cursor == end) ISOException.throwIt(ISO7816.SW_WRONG_DATA);

    while (cursor < end) {
      if (buffer[cursor] != (byte) 0x31) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      short setEnd = derObjectEnd(buffer, cursor, end);
      short attribute = derContentOffset(buffer, cursor, setEnd);
      if (attribute == setEnd) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      short previousAttribute = (short) -1;

      while (attribute < setEnd) {
        if (buffer[attribute] != (byte) 0x30) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        short attributeEnd = derObjectEnd(buffer, attribute, setEnd);
        if (previousAttribute >= (short) 0
            && !isDerOrdered(buffer, previousAttribute, attribute, attribute, attributeEnd)) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short oid = derContentOffset(buffer, attribute, attributeEnd);
        if (oid >= attributeEnd || buffer[oid] != (byte) 0x06) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short oidEnd = derObjectEnd(buffer, oid, attributeEnd);
        validateOid(buffer, derContentOffset(buffer, oid, oidEnd), oidEnd);
        if (oidEnd >= attributeEnd) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        short valueEnd = derObjectEnd(buffer, oidEnd, attributeEnd);
        validateNameValue(buffer, oidEnd, valueEnd);
        if (valueEnd != attributeEnd) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        previousAttribute = attribute;
        attribute = attributeEnd;
      }
      cursor = setEnd;
    }
  }

  /**
   * Validates one DER Validity sequence and its chronological order.
   *
   * <p>RFC 5280, Section 4.1.2.5 requires UTCTime through 2049 and GeneralizedTime for 2050 or
   * later. Both values must use seconds and the {@code Z} form, and notBefore must not follow
   * notAfter.
   *
   * @param buffer input buffer
   * @param offset first DER octet
   * @param length number of input octets
   * @throws ISOException with {@link ISO7816#SW_WRONG_DATA} if validation fails
   */
  static void validateDerValidity(byte[] buffer, short offset, short length) {
    short contentOffset = validateSingleDerObject(buffer, offset, length, (byte) 0x30);
    short end = (short) (offset + length);
    short firstEnd = validateTime(buffer, contentOffset, end);
    short secondEnd = validateTime(buffer, firstEnd, end);
    if (secondEnd != end || compareTimes(buffer, contentOffset, firstEnd) > (short) 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
  }

  /**
   * Writes one RFC 5280 time value as fourteen ASCII digits {@code YYYYMMDDHHMMSS}.
   *
   * <p>RFC 5280, Section 4.1.2.5.1: &quot;Where YY is greater than or equal to 50, the year SHALL
   * be interpreted as 19YY; and Where YY is less than 50, the year SHALL be interpreted as
   * 20YY.&quot; GeneralizedTime digits are copied unchanged. The normalized form orders
   * chronologically as an unsigned octet string.
   *
   * @param buffer buffer containing the time object
   * @param offset first tag octet of a UTCTime or GeneralizedTime object
   * @param out destination buffer
   * @param outOffset first destination octet; fourteen octets are written
   * @return {@link #LENGTH_NORMALIZED_TIME}
   * @throws ISOException with {@link ISO7816#SW_WRONG_DATA} if the time object is invalid
   */
  static short normalizeTime(byte[] buffer, short offset, byte[] out, short outOffset) {
    short objectEnd = validateTime(buffer, offset, (short) buffer.length);
    short content = derContentOffset(buffer, offset, objectEnd);
    short digits = (short) (objectEnd - 1 - content);
    short cursor = outOffset;
    if (buffer[offset] == (byte) 0x17) {
      boolean twentiethCentury = buffer[content] >= (byte) '5';
      out[cursor++] = twentiethCentury ? (byte) '1' : (byte) '2';
      out[cursor++] = twentiethCentury ? (byte) '9' : (byte) '0';
    }
    for (short i = (short) 0; i < digits; i++) {
      out[cursor++] = buffer[(short) (content + i)];
    }
    return LENGTH_NORMALIZED_TIME;
  }

  /**
   * Validates one RFC 5280 UTCTime or GeneralizedTime value.
   *
   * @param buffer input buffer
   * @param offset first tag octet
   * @param end exclusive enclosing-object limit
   * @return exclusive end offset of the validated time object
   * @throws ISOException with {@link ISO7816#SW_WRONG_DATA} for a non-canonical or invalid value
   */
  static short validateTime(byte[] buffer, short offset, short end) {
    if (offset >= end) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    byte tag = buffer[offset];
    if (tag != (byte) 0x17 && tag != (byte) 0x18) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    short objectEnd = derObjectEnd(buffer, offset, end);
    short content = derContentOffset(buffer, offset, objectEnd);
    short expectedLength = tag == (byte) 0x17 ? (short) 13 : (short) 15;
    if ((short) (objectEnd - content) != expectedLength
        || buffer[(short) (objectEnd - 1)] != (byte) 'Z') {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    short yearDigits = tag == (byte) 0x17 ? (short) 2 : (short) 4;
    short digitEnd = (short) (objectEnd - 1);
    for (short i = content; i < digitEnd; i++) {
      if (buffer[i] < (byte) '0' || buffer[i] > (byte) '9') {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
    }

    short year = decimal(buffer, content, yearDigits);
    if (tag == (byte) 0x17) year = (short) (year >= 50 ? year + 1900 : year + 2000);
    if (tag == (byte) 0x18 && year < (short) 2050) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    short month = decimal(buffer, (short) (content + yearDigits), (short) 2);
    short day = decimal(buffer, (short) (content + yearDigits + 2), (short) 2);
    short hour = decimal(buffer, (short) (content + yearDigits + 4), (short) 2);
    short minute = decimal(buffer, (short) (content + yearDigits + 6), (short) 2);
    short second = decimal(buffer, (short) (content + yearDigits + 8), (short) 2);
    if (month < (short) 1
        || month > (short) 12
        || day < (short) 1
        || day > daysInMonth(year, month)
        || hour > (short) 23
        || minute > (short) 59
        || second > (short) 59) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    return objectEnd;
  }

  /**
   * Validates the base-128 contents of a DER OBJECT IDENTIFIER.
   *
   * <p>X.690, Section 8.19 defines base-128 subidentifier encoding. A subidentifier cannot start
   * with the redundant {@code 0x80} group, and its final octet must clear the continuation bit.
   *
   * @param buffer input buffer
   * @param offset first content octet
   * @param end exclusive content end
   */
  static void validateOid(byte[] buffer, short offset, short end) {
    if (offset >= end) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    boolean componentStart = true;
    for (short cursor = offset; cursor < end; cursor++) {
      byte value = buffer[cursor];
      if (componentStart && value == (byte) 0x80) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      componentStart = (value & (byte) 0x80) == (byte) 0;
    }
    if (!componentStart) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
  }

  /**
   * Validates the ASN.1 string value in an AttributeTypeAndValue.
   *
   * <p>RFC 5280, Section 4.1.2.4 uses the X.501 Name type. The accepted universal string tags are
   * checked for their defined code-unit encoding, and all other tag classes are rejected.
   *
   * @param buffer input buffer
   * @param offset first string tag octet
   * @param end exclusive end of the string object
   */
  static void validateNameValue(byte[] buffer, short offset, short end) {
    byte tag = buffer[offset];
    if (tag != (byte) 0x0C
        && tag != (byte) 0x12
        && tag != (byte) 0x13
        && tag != (byte) 0x16
        && tag != (byte) 0x1A
        && tag != (byte) 0x1C
        && tag != (byte) 0x1E) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    short content = derContentOffset(buffer, offset, end);
    if (content == end) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    short length = (short) (end - content);
    if ((tag == (byte) 0x1E && (length & (short) 1) != (short) 0)
        || (tag == (byte) 0x1C && (length & (short) 3) != (short) 0)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    if (tag == (byte) 0x0C) validateUtf8(buffer, content, end);
    else if (tag == (byte) 0x12) validateNumericString(buffer, content, end);
    else if (tag == (byte) 0x13) validatePrintableString(buffer, content, end);
    else if (tag == (byte) 0x16) validateAscii(buffer, content, end, (byte) 0x00, (byte) 0x7F);
    else if (tag == (byte) 0x1A) validateAscii(buffer, content, end, (byte) 0x20, (byte) 0x7E);
    else if (tag == (byte) 0x1C) validateUniversalString(buffer, content, end);
    else if (tag == (byte) 0x1E) validateBmpString(buffer, content, end);
  }

  /**
   * Compares two complete DER encodings as unsigned octet strings.
   *
   * <p>X.690, Section 11.6 requires SET OF components to &quot;appear in ascending order.&quot;
   * Equal values are accepted because a SET OF can contain equal component encodings.
   *
   * @return {@code true} if the left encoding sorts before or equal to the right encoding
   */
  private static boolean isDerOrdered(
      byte[] buffer, short left, short leftEnd, short right, short rightEnd) {
    while (left < leftEnd && right < rightEnd) {
      short leftByte = (short) (buffer[left++] & (short) 0xFF);
      short rightByte = (short) (buffer[right++] & (short) 0xFF);
      if (leftByte < rightByte) return true;
      if (leftByte > rightByte) return false;
    }
    return left == leftEnd;
  }

  /**
   * Compares two validated RFC 5280 time objects by calendar value.
   *
   * <p>The method expands UTCTime years according to the RFC 5280 1950-to-2049 window before it
   * compares the remaining month-through-second fields.
   *
   * @param buffer buffer that contains both objects
   * @param left offset of the first time object
   * @param right offset of the second time object
   * @return a negative value, zero, or a positive value when left is earlier, equal, or later
   */
  static short compareTimes(byte[] buffer, short left, short right) {
    short leftContent = derContentOffset(buffer, left, right);
    short rightEnd = derObjectEnd(buffer, right, (short) buffer.length);
    short rightContent = derContentOffset(buffer, right, rightEnd);
    short leftDigits = buffer[left] == (byte) 0x17 ? (short) 2 : (short) 4;
    short rightDigits = buffer[right] == (byte) 0x17 ? (short) 2 : (short) 4;
    short leftYear = decimal(buffer, leftContent, leftDigits);
    short rightYear = decimal(buffer, rightContent, rightDigits);
    if (leftDigits == (short) 2) {
      leftYear = (short) (leftYear >= 50 ? leftYear + 1900 : leftYear + 2000);
    }
    if (rightDigits == (short) 2) {
      rightYear = (short) (rightYear >= 50 ? rightYear + 1900 : rightYear + 2000);
    }
    if (leftYear != rightYear) return leftYear < rightYear ? (short) -1 : (short) 1;
    for (short field = (short) 0; field < (short) 5; field++) {
      short leftValue = decimal(buffer, (short) (leftContent + leftDigits + field * 2), (short) 2);
      short rightValue =
          decimal(buffer, (short) (rightContent + rightDigits + field * 2), (short) 2);
      if (leftValue != rightValue) return leftValue < rightValue ? (short) -1 : (short) 1;
    }
    return (short) 0;
  }

  /**
   * Validates a UTF-8 string without allocating a decoded character array.
   *
   * <p>The byte ranges reject truncated sequences, overlong forms, surrogate code points, and
   * values above U+10FFFF, as required by the UTF-8 definition used by ASN.1 UTF8String.
   *
   * @param buffer encoded string
   * @param offset first content octet
   * @param end exclusive content end
   */
  private static void validateUtf8(byte[] buffer, short offset, short end) {
    while (offset < end) {
      short first = (short) (buffer[offset++] & (short) 0xFF);
      if (first <= (short) 0x7F) continue;
      if (first >= (short) 0xC2 && first <= (short) 0xDF) {
        requireContinuation(buffer, offset++, end, (short) 0x80, (short) 0xBF);
      } else if (first >= (short) 0xE0 && first <= (short) 0xEF) {
        short minimum = first == (short) 0xE0 ? (short) 0xA0 : (short) 0x80;
        short maximum = first == (short) 0xED ? (short) 0x9F : (short) 0xBF;
        requireContinuation(buffer, offset++, end, minimum, maximum);
        requireContinuation(buffer, offset++, end, (short) 0x80, (short) 0xBF);
      } else if (first >= (short) 0xF0 && first <= (short) 0xF4) {
        short minimum = first == (short) 0xF0 ? (short) 0x90 : (short) 0x80;
        short maximum = first == (short) 0xF4 ? (short) 0x8F : (short) 0xBF;
        requireContinuation(buffer, offset++, end, minimum, maximum);
        requireContinuation(buffer, offset++, end, (short) 0x80, (short) 0xBF);
        requireContinuation(buffer, offset++, end, (short) 0x80, (short) 0xBF);
      } else {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
    }
  }

  /**
   * Validates one UTF-8 continuation octet against a context-specific range.
   *
   * @param buffer encoded string
   * @param offset continuation-octet offset
   * @param end exclusive content end
   * @param minimum smallest permitted unsigned octet value
   * @param maximum largest permitted unsigned octet value
   */
  private static void requireContinuation(
      byte[] buffer, short offset, short end, short minimum, short maximum) {
    if (offset >= end) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    short value = (short) (buffer[offset] & (short) 0xFF);
    if (value < minimum || value > maximum) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
  }

  /** Validates that an ASN.1 NumericString contains only digits and space characters. */
  private static void validateNumericString(byte[] buffer, short offset, short end) {
    while (offset < end) {
      byte value = buffer[offset++];
      if (value != (byte) ' ' && (value < (byte) '0' || value > (byte) '9')) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
    }
  }

  /** Validates every octet against the ASN.1 PrintableString character repertoire. */
  private static void validatePrintableString(byte[] buffer, short offset, short end) {
    while (offset < end) {
      byte value = buffer[offset++];
      boolean alphaNumeric =
          (value >= (byte) 'A' && value <= (byte) 'Z')
              || (value >= (byte) 'a' && value <= (byte) 'z')
              || (value >= (byte) '0' && value <= (byte) '9');
      boolean punctuation =
          value == (byte) ' '
              || value == (byte) '\''
              || value == (byte) '('
              || value == (byte) ')'
              || value == (byte) '+'
              || value == (byte) ','
              || value == (byte) '-'
              || value == (byte) '.'
              || value == (byte) '/'
              || value == (byte) ':'
              || value == (byte) '='
              || value == (byte) '?';
      if (!alphaNumeric && !punctuation) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
  }

  /**
   * Validates a single-octet ASN.1 string against an inclusive ASCII range.
   *
   * @param buffer encoded string
   * @param offset first content octet
   * @param end exclusive content end
   * @param minimum smallest permitted ASCII value
   * @param maximum largest permitted ASCII value
   */
  private static void validateAscii(
      byte[] buffer, short offset, short end, byte minimum, byte maximum) {
    while (offset < end) {
      byte value = buffer[offset++];
      if (value < minimum || value > maximum) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
  }

  /**
   * Validates a big-endian BMPString and rejects UTF-16 surrogate code units.
   *
   * <p>The caller has already confirmed that the content length is a multiple of two.
   */
  private static void validateBmpString(byte[] buffer, short offset, short end) {
    while (offset < end) {
      short high = (short) (buffer[offset] & (short) 0xFF);
      if (high >= (short) 0xD8 && high <= (short) 0xDF) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
      offset += (short) 2;
    }
  }

  /**
   * Validates big-endian UniversalString code points.
   *
   * <p>The caller has already confirmed four-octet alignment. Values above U+10FFFF and surrogate
   * code points are rejected.
   */
  private static void validateUniversalString(byte[] buffer, short offset, short end) {
    while (offset < end) {
      short first = (short) (buffer[offset] & (short) 0xFF);
      short second = (short) (buffer[(short) (offset + 1)] & (short) 0xFF);
      short third = (short) (buffer[(short) (offset + 2)] & (short) 0xFF);
      if (first != (short) 0
          || second > (short) 0x10
          || (second == (short) 0 && third >= (short) 0xD8 && third <= (short) 0xDF)) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
      offset += (short) 4;
    }
  }

  /**
   * Converts validated ASCII decimal digits to a non-negative short value.
   *
   * @param buffer buffer that contains digits
   * @param offset first digit
   * @param length number of digits
   * @return decoded value
   */
  static short decimal(byte[] buffer, short offset, short length) {
    short value = (short) 0;
    for (short i = (short) 0; i < length; i++) {
      value = (short) (value * 10 + buffer[(short) (offset + i)] - (byte) '0');
    }
    return value;
  }

  /** Returns the Gregorian number of days in a validated month and year. */
  private static short daysInMonth(short year, short month) {
    if (month == (short) 2) {
      boolean leap = (year % 4 == 0) && ((year % 100 != 0) || (year % 400 == 0));
      return leap ? (short) 29 : (short) 28;
    }
    return month == (short) 4 || month == (short) 6 || month == (short) 9 || month == (short) 11
        ? (short) 30
        : (short) 31;
  }

  /**
   * Confirms that an input slice contains exactly one DER object with the required tag.
   *
   * <p>RFC 5280, Section 4.1 requires DER certificate encoding. The complete-slice check prevents
   * accepted profile data from carrying an ignored trailing object.
   *
   * @return offset of the object's first content octet
   */
  static short validateSingleDerObject(byte[] buffer, short offset, short length, byte tag) {
    short end = (short) (offset + length);
    if (end < offset) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    if (length < (short) 0x02 || buffer[offset] != tag) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    short objectEnd = derObjectEnd(buffer, offset, end);
    if (objectEnd != end) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    return derContentOffset(buffer, offset, end);
  }

  /**
   * Returns the exclusive end of one strict DER object and normalizes parser errors.
   *
   * @throws ISOException with {@link ISO7816#SW_WRONG_DATA} for malformed or non-canonical DER
   */
  static short derObjectEnd(byte[] buffer, short offset, short limit) {
    try {
      return TLV.objectEnd(buffer, offset, limit, true);
    } catch (ISOException e) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return (short) 0x00;
    }
  }

  /**
   * Returns the first content octet of one strict DER object and normalizes parser errors.
   *
   * @throws ISOException with {@link ISO7816#SW_WRONG_DATA} for malformed or non-canonical DER
   */
  static short derContentOffset(byte[] buffer, short offset, short limit) {
    try {
      return TLV.dataOffset(buffer, offset, limit, true);
    } catch (ISOException e) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return (short) 0x00;
    }
  }
}
