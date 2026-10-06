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

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * Strict parser for the root-issued SAM certificate (LOAD SAM CERTIFICATE).
 *
 * <p>RFC 5280 Section 4.1 requires DER; any deviation from the profile below is {@link
 * ISO7816#SW_WRONG_DATA}. A certificate that satisfies the profile but whose signature does not
 * verify under the provisioned root key is {@link SamConst#SW_VERIFICATION_FAILED}.
 *
 * <ul>
 *   <li>One Certificate with no trailing octets; v3; serial 1..20 octets, positive and minimal.
 *   <li>tbs.signature and signatureAlgorithm are both exactly ecdsa-with-SHA256 without parameters.
 *   <li>Issuer and subject are valid Names; the subject is at most 128 octets and equals the
 *       provisioned expected subject when one was given.
 *   <li>The SubjectPublicKeyInfo byte-equals the SAM's own 91-octet SPKI; no unique identifiers.
 *   <li>Extensions: no duplicate OIDs; BasicConstraints critical with cA TRUE and pathLen exactly
 *       1; KeyUsage critical asserting keyCertSign; SubjectKeyIdentifier equal to the RFC 7093
 *       method 1 value of the SAM key; the batch extension equal to the stored parameters; any
 *       other critical extension is rejected.
 * </ul>
 */
final class SamCertificateParser {
  private static final byte SEEN_BASIC_CONSTRAINTS = (byte) 0x01;
  private static final byte SEEN_KEY_USAGE = (byte) 0x02;
  private static final byte SEEN_SKI = (byte) 0x04;
  private static final byte SEEN_BATCH = (byte) 0x08;
  private static final byte SEEN_REQUIRED = (byte) 0x0F;

  private final SamState state;
  private final SamCrypto crypto;
  private final byte[] scratch;

  // Results of the last successful parse, relative to the certificate's first octet.
  private short subjectOffset;
  private short subjectLength;

  SamCertificateParser(SamState state, SamCrypto crypto, byte[] scratch) {
    this.state = state;
    this.crypto = crypto;
    this.scratch = scratch;
  }

  short getSubjectOffset() {
    return subjectOffset;
  }

  short getSubjectLength() {
    return subjectLength;
  }

  /**
   * Parses and verifies the certificate in {@code cert[offset..offset+length)}.
   *
   * <p>On success the normalized notBefore and notAfter are at scratch {@link
   * SamConst#S_CERT_TIMES} and +14, and the subject position is available from the getters.
   */
  void parse(byte[] cert, short offset, short length) {
    short end = (short) (offset + length);
    if (length < (short) 2 || cert[offset] != (byte) 0x30) fail();
    if (DERValidator.derObjectEnd(cert, offset, end) != end) fail();
    short tbs = DERValidator.derContentOffset(cert, offset, end);
    if (tbs >= end || cert[tbs] != (byte) 0x30) fail();
    short tbsEnd = DERValidator.derObjectEnd(cert, tbs, end);
    short cursor = DERValidator.derContentOffset(cert, tbs, tbsEnd);

    // version [0] EXPLICIT v3
    cursor = expectBytes(cert, cursor, tbsEnd, SamConst.DER_VERSION_V3);

    // serialNumber: 1..20 content octets, positive, minimal
    if (cursor >= tbsEnd || cert[cursor] != TLV.ASN1_INTEGER) fail();
    short serialEnd = DERValidator.derObjectEnd(cert, cursor, tbsEnd);
    short serial = DERValidator.derContentOffset(cert, cursor, serialEnd);
    short serialLength = (short) (serialEnd - serial);
    if (serialLength < (short) 1 || serialLength > (short) 20) fail();
    if ((cert[serial] & (byte) 0x80) != (byte) 0) fail();
    if (serialLength > (short) 1
        && cert[serial] == (byte) 0x00
        && (cert[(short) (serial + 1)] & (byte) 0x80) == (byte) 0) {
      fail();
    }
    cursor = serialEnd;

    // signature
    cursor = expectBytes(cert, cursor, tbsEnd, SamConst.DER_ECDSA_WITH_SHA256);

    // issuer
    cursor = validateName(cert, cursor, tbsEnd);

    // validity, stored normalized
    if (cursor >= tbsEnd || cert[cursor] != (byte) 0x30) fail();
    short validityEnd = DERValidator.derObjectEnd(cert, cursor, tbsEnd);
    DERValidator.validateDerValidity(cert, cursor, (short) (validityEnd - cursor));
    short notBefore = DERValidator.derContentOffset(cert, cursor, validityEnd);
    short notAfter = DERValidator.derObjectEnd(cert, notBefore, validityEnd);
    DERValidator.normalizeTime(cert, notBefore, scratch, SamConst.S_CERT_TIMES);
    DERValidator.normalizeTime(
        cert, notAfter, scratch, (short) (SamConst.S_CERT_TIMES + SamConst.LENGTH_TIME));
    cursor = validityEnd;

    // subject
    short subject = cursor;
    cursor = validateName(cert, cursor, tbsEnd);
    short subjectLen = (short) (cursor - subject);
    if (subjectLen > SamConst.LENGTH_SAM_SUBJECT_MAX) fail();
    if (state.expectedSamSubjectLength != (short) 0
        && (subjectLen != state.expectedSamSubjectLength
            || Util.arrayCompare(cert, subject, state.expectedSamSubject, (short) 0, subjectLen)
                != (byte) 0)) {
      fail();
    }

    // subjectPublicKeyInfo == own SPKI
    short point =
        Util.arrayCopyNonAtomic(
            SamConst.DER_SPKI_P256_PREFIX,
            (short) 0,
            scratch,
            SamConst.S_CERT_SPKI,
            (short) SamConst.DER_SPKI_P256_PREFIX.length);
    crypto.samPublic.getW(scratch, point);
    if ((short) (tbsEnd - cursor) < SamConst.LENGTH_SPKI
        || Util.arrayCompare(cert, cursor, scratch, SamConst.S_CERT_SPKI, SamConst.LENGTH_SPKI)
            != (byte) 0) {
      fail();
    }
    cursor += SamConst.LENGTH_SPKI;

    // No issuerUniqueID [1] / subjectUniqueID [2]; extensions [3] are required.
    if (cursor >= tbsEnd || cert[cursor] != (byte) 0xA3) fail();
    short extensionsEnd = DERValidator.derObjectEnd(cert, cursor, tbsEnd);
    if (extensionsEnd != tbsEnd) fail();
    short list = DERValidator.derContentOffset(cert, cursor, extensionsEnd);
    if (list >= extensionsEnd || cert[list] != (byte) 0x30) fail();
    if (DERValidator.derObjectEnd(cert, list, extensionsEnd) != extensionsEnd) fail();
    parseExtensions(cert, DERValidator.derContentOffset(cert, list, extensionsEnd), extensionsEnd);

    // signatureAlgorithm and signatureValue
    cursor = expectBytes(cert, tbsEnd, end, SamConst.DER_ECDSA_WITH_SHA256);
    if (cursor >= end || cert[cursor] != TLV.ASN1_BIT_STRING) fail();
    if (DERValidator.derObjectEnd(cert, cursor, end) != end) fail();
    short bits = DERValidator.derContentOffset(cert, cursor, end);
    if ((short) (end - bits) < (short) 2 || cert[bits] != (byte) 0x00) fail();
    short sig = (short) (bits + 1);

    subjectOffset = (short) (subject - offset);
    subjectLength = subjectLen;

    if (!crypto.verify(
        crypto.rootPublic, cert, tbs, (short) (tbsEnd - tbs), cert, sig, (short) (end - sig))) {
      ISOException.throwIt(SamConst.SW_VERIFICATION_FAILED);
    }
  }

  private void parseExtensions(byte[] cert, short start, short end) {
    if (start >= end) fail();
    byte seen = (byte) 0;
    short cursor = start;
    while (cursor < end) {
      if (cert[cursor] != (byte) 0x30) fail();
      short extensionEnd = DERValidator.derObjectEnd(cert, cursor, end);
      short oid = DERValidator.derContentOffset(cert, cursor, extensionEnd);
      if (oid >= extensionEnd || cert[oid] != TLV.ASN1_OBJECT) fail();
      short oidEnd = DERValidator.derObjectEnd(cert, oid, extensionEnd);
      short oidValue = DERValidator.derContentOffset(cert, oid, oidEnd);
      DERValidator.validateOid(cert, oidValue, oidEnd);
      requireUniqueOid(cert, start, cursor, oid, oidEnd);

      short field = oidEnd;
      boolean critical = false;
      if (field < extensionEnd && cert[field] == TLV.ASN1_BOOLEAN) {
        // X.690 Section 11.5: DER omits a component equal to its DEFAULT, so an explicit FALSE
        // is not DER; Section 11.1 requires TRUE to be encoded as FF.
        short booleanEnd = DERValidator.derObjectEnd(cert, field, extensionEnd);
        short value = DERValidator.derContentOffset(cert, field, booleanEnd);
        if ((short) (booleanEnd - value) != (short) 1 || cert[value] != (byte) 0xFF) fail();
        critical = true;
        field = booleanEnd;
      }
      if (field >= extensionEnd || cert[field] != TLV.ASN1_OCTET_STRING) fail();
      if (DERValidator.derObjectEnd(cert, field, extensionEnd) != extensionEnd) fail();
      short value = DERValidator.derContentOffset(cert, field, extensionEnd);
      short valueLength = (short) (extensionEnd - value);

      if (oidEquals(cert, oid, oidEnd, SamConst.OID_BASIC_CONSTRAINTS)) {
        if (!critical
            || !regionEquals(cert, value, valueLength, SamConst.DER_SAM_BASIC_CONSTRAINTS_VALUE)) {
          fail();
        }
        seen |= SEEN_BASIC_CONSTRAINTS;
      } else if (oidEquals(cert, oid, oidEnd, SamConst.OID_KEY_USAGE)) {
        if (!critical || !isKeyCertSign(cert, value, extensionEnd)) fail();
        seen |= SEEN_KEY_USAGE;
      } else if (oidEquals(cert, oid, oidEnd, SamConst.OID_SUBJECT_KEY_IDENTIFIER)) {
        // RFC 5280 Section 4.2.1.2: "Conforming CAs MUST mark this extension as non-critical."
        if (critical || valueLength != (short) (2 + SamConst.LENGTH_SKI)) fail();
        if (cert[value] != TLV.ASN1_OCTET_STRING
            || cert[(short) (value + 1)] != (byte) SamConst.LENGTH_SKI
            || Util.arrayCompare(
                    cert, (short) (value + 2), state.samSki, (short) 0, SamConst.LENGTH_SKI)
                != (byte) 0) {
          fail();
        }
        seen |= SEEN_SKI;
      } else if (oidEquals(cert, oid, oidEnd, SamConst.OID_BATCH_EXTENSION)) {
        if (critical) fail();
        checkBatchExtension(cert, value, extensionEnd);
        seen |= SEEN_BATCH;
      } else if (critical) {
        // RFC 5280 Section 4.2: "A certificate-using system MUST reject the certificate if it
        // encounters a critical extension it does not recognize".
        fail();
      }
      cursor = extensionEnd;
    }
    if (seen != SEEN_REQUIRED) fail();
  }

  /** Rejects an extension whose OID equals that of any earlier extension in the list. */
  private static void requireUniqueOid(
      byte[] cert, short start, short current, short oid, short oidEnd) {
    short cursor = start;
    while (cursor < current) {
      short extensionEnd = DERValidator.derObjectEnd(cert, cursor, current);
      short other = DERValidator.derContentOffset(cert, cursor, extensionEnd);
      short otherEnd = DERValidator.derObjectEnd(cert, other, extensionEnd);
      short length = (short) (oidEnd - oid);
      if ((short) (otherEnd - other) == length
          && Util.arrayCompare(cert, other, cert, oid, length) == (byte) 0) {
        fail();
      }
      cursor = extensionEnd;
    }
  }

  /**
   * Checks a DER KeyUsage BIT STRING (X.690 Section 11.2.2: trailing zero bits of a named bit list
   * are removed) and returns whether keyCertSign (bit 5) is asserted.
   */
  private static boolean isKeyCertSign(byte[] cert, short value, short end) {
    if (value >= end || cert[value] != TLV.ASN1_BIT_STRING) return false;
    if (DERValidator.derObjectEnd(cert, value, end) != end) return false;
    short content = DERValidator.derContentOffset(cert, value, end);
    short length = (short) (end - content);
    if (length < (short) 2 || length > (short) 3) return false;
    short unused = cert[content];
    if (unused < (short) 0 || unused > (short) 7) return false;
    byte last = cert[(short) (end - 1)];
    if (last == (byte) 0) return false;
    // The lowest set bit of the last octet must sit exactly at position `unused`.
    if ((short) (last & (short) ((short) 1 << unused)) == (short) 0) return false;
    if ((short) (last & (short) ((short) ((short) 1 << unused) - 1)) != (short) 0) return false;
    return (cert[(short) (content + 1)] & (byte) 0x04) != (byte) 0;
  }

  /**
   * Checks the batch extension v3 value {@code SEQUENCE{version INTEGER 3, issuerId, batch,
   * initialQuota, initialTimestamp OCTET STRING(8), paramsDigest OCTET STRING(32), allocationSeq
   * INTEGER, registryHead OCTET STRING(32)}}: the first five fields must equal the stored
   * parameters; allocationSeq and registryHead are left in scratch at {@link
   * SamConst#S_CERT_ALLOCATION} and {@link SamConst#S_CERT_REGISTRY} for the caller to store.
   */
  private void checkBatchExtension(byte[] cert, short value, short end) {
    if (value >= end || cert[value] != (byte) 0x30) fail();
    if (DERValidator.derObjectEnd(cert, value, end) != end) fail();
    short cursor = DERValidator.derContentOffset(cert, value, end);
    short u32 = SamConst.S_CERT_U32;
    short work = SamConst.S_CERT_WORK;
    short digits = SamConst.S_CERT_DIGITS;

    cursor = U32.parseDerInteger(cert, cursor, end, scratch, u32);
    requireSmall(u32, (byte) 3);

    cursor = U32.parseDerInteger(cert, cursor, end, scratch, u32);
    if (!U32.toDecimal(scratch, u32, scratch, work, scratch, digits, SamConst.ISSUER_DIGITS)) {
      fail();
    }
    for (short i = 0; i < SamConst.ISSUER_DIGITS; i++) {
      if (scratch[(short) (digits + SamConst.ISSUER_DIGITS - 1 - i)] != state.issuerDigits[i]) {
        fail();
      }
    }

    cursor = U32.parseDerInteger(cert, cursor, end, scratch, u32);
    short b = SamConst.BATCH_DIGITS;
    if (!U32.toDecimal(scratch, u32, scratch, work, scratch, digits, b)) fail();
    for (short i = 0; i < b; i++) {
      if (scratch[(short) (digits + b - 1 - i)] != state.batchDigits[i]) fail();
    }

    cursor = U32.parseDerInteger(cert, cursor, end, scratch, u32);
    if (U32.compare(scratch, u32, state.quota, (short) 0, SamConst.LENGTH_U32) != (short) 0) {
      fail();
    }

    short ts =
        SamLedger.expectPrimitive(
            cert, cursor, end, TLV.ASN1_OCTET_STRING, SamConst.LENGTH_TIMESTAMP);
    if (Util.arrayCompare(cert, ts, state.lastTopUpTs, (short) 0, SamConst.LENGTH_TIMESTAMP)
        != (byte) 0) {
      fail();
    }
    cursor = (short) (ts + SamConst.LENGTH_TIMESTAMP);

    short digest =
        SamLedger.expectPrimitive(cert, cursor, end, TLV.ASN1_OCTET_STRING, SamConst.LENGTH_HASH);
    cursor = (short) (digest + SamConst.LENGTH_HASH);
    // paramsDigest v3 recorded at PUT PARAMETERS (it commits to the FF1 key through its KCV).
    if (Util.arrayCompare(cert, digest, state.paramsDigest, (short) 0, SamConst.LENGTH_HASH)
        != (byte) 0) {
      fail();
    }

    // allocationSeq and registryHead: recorded, not checked against SAM state.
    cursor = U32.parseDerInteger(cert, cursor, end, scratch, SamConst.S_CERT_ALLOCATION);
    short registry =
        SamLedger.expectPrimitive(cert, cursor, end, TLV.ASN1_OCTET_STRING, SamConst.LENGTH_HASH);
    if ((short) (registry + SamConst.LENGTH_HASH) != end) fail();
    Util.arrayCopyNonAtomic(
        cert, registry, scratch, SamConst.S_CERT_REGISTRY, SamConst.LENGTH_HASH);
  }

  private void requireSmall(short u32, byte expected) {
    if (scratch[u32] != (byte) 0
        || scratch[(short) (u32 + 1)] != (byte) 0
        || scratch[(short) (u32 + 2)] != (byte) 0
        || scratch[(short) (u32 + 3)] != expected) {
      fail();
    }
  }

  /** Validates a Name at {@code offset} and returns its end. */
  private static short validateName(byte[] cert, short offset, short limit) {
    if (offset >= limit || cert[offset] != (byte) 0x30) fail();
    short nameEnd = DERValidator.derObjectEnd(cert, offset, limit);
    DERValidator.validateDerName(cert, offset, (short) (nameEnd - offset));
    return nameEnd;
  }

  private static short expectBytes(byte[] cert, short offset, short limit, byte[] expected) {
    short length = (short) expected.length;
    if ((short) (limit - offset) < length
        || Util.arrayCompare(cert, offset, expected, (short) 0, length) != (byte) 0) {
      fail();
    }
    return (short) (offset + length);
  }

  private static boolean oidEquals(byte[] cert, short oid, short oidEnd, byte[] expected) {
    short value = DERValidator.derContentOffset(cert, oid, oidEnd);
    return regionEquals(cert, value, (short) (oidEnd - value), expected);
  }

  private static boolean regionEquals(byte[] buffer, short offset, short length, byte[] expected) {
    return length == (short) expected.length
        && Util.arrayCompare(buffer, offset, expected, (short) 0, length) == (byte) 0;
  }

  private static void fail() {
    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
  }
}
