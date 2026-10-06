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
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Personalization: PUT PARAMETERS, SET OPERATOR PIN, GENERATE SAM KEY, LOAD SAM CERTIFICATE and
 * LOCK.
 *
 * <p>The SAM never chooses its LCG parameters. The issuance software generates (a, c, x0) and the
 * batch identity, records them, and provisions them here; the SAM validates them completely before
 * writing anything, stores them, and binds them to the root-signed batch extension through
 * paramsDigest at LOAD SAM CERTIFICATE.
 *
 * <p>Each handler first demotes the lifecycle (a single atomic write), then writes its data fields,
 * then promotes the lifecycle in one transaction. A tear therefore leaves the SAM in an earlier
 * state whose data is re-provisioned by repeating the command, never in a later state with partial
 * data.
 */
final class SamPersonalization {
  private final SamState state;
  private final SamCrypto crypto;
  private final SamLedger ledger;
  private final SamCertificateParser parser;
  private final byte[] scratch;

  SamPersonalization(
      SamState state,
      SamCrypto crypto,
      SamLedger ledger,
      SamCertificateParser parser,
      byte[] scratch) {
    this.state = state;
    this.crypto = crypto;
    this.ledger = ledger;
    this.parser = parser;
    this.scratch = scratch;
  }

  /**
   * PUT PARAMETERS (IssuerSamParameters v5, DER only). One command carries every parameter,
   * including the FF1 key wrapped to the one-time transport key from GENERATE TRANSPORT KEY;
   * nothing is written until all of it validates and the key unwraps, and the lifecycle flips only
   * after every field and the derived jump maps are stored. The transport key is destroyed after a
   * successful command; the staged packet is zeroized by the caller.
   *
   * <pre>
   * IssuerSamParameters ::= SEQUENCE {
   *   type OBJECT IDENTIFIER   -- 1.3.6.1.4.1.57923.20.10.10.1
   *   version INTEGER (5),
   *   issue [16] IMPLICIT SEQUENCE { issuerId INTEGER(0..9999), batchNumber INTEGER(0..9999),
   *                                  initialQuota INTEGER(0..10^8) },
   *   lcg   [17] IMPLICIT SEQUENCE { seed INTEGER(0..10^8-1), modulus INTEGER(10^8),
   *                                  multiplier INTEGER, increment INTEGER },
   *   f9SubjectTemplate [20] EXPLICIT Name,
   *   samSubject        [21] EXPLICIT Name OPTIONAL,
   *   rootPublicKey     [22] IMPLICIT OCTET STRING (SIZE 65),
   *   initialTimestamp  [23] IMPLICIT OCTET STRING (SIZE 8),
   *   wrappedFpeKey     [24] IMPLICIT SEQUENCE {
   *     hostEphemeralPublicKey OCTET STRING (SIZE 65),
   *     wrappedKey             OCTET STRING (SIZE 40) } }   -- RFC 3394 AES-256 key wrap
   * </pre>
   */
  void putParameters(byte[] in, short offset, short length) {
    if (!crypto.hasTransportKey()) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    short end = (short) (offset + length);
    if (length < (short) 2 || in[offset] != (byte) 0x30) fail();
    if (DERValidator.derObjectEnd(in, offset, end) != end) fail();
    short cursor = DERValidator.derContentOffset(in, offset, end);

    // type
    short oid =
        SamLedger.expectPrimitive(
            in, cursor, end, TLV.ASN1_OBJECT, (short) SamConst.OID_PARAMETERS.length);
    if (Util.arrayCompare(
            in, oid, SamConst.OID_PARAMETERS, (short) 0, (short) SamConst.OID_PARAMETERS.length)
        != (byte) 0) {
      fail();
    }
    cursor = (short) (oid + SamConst.OID_PARAMETERS.length);

    // version 5
    short version = SamLedger.expectPrimitive(in, cursor, end, TLV.ASN1_INTEGER, (short) 1);
    if (in[version] != (byte) 0x05) fail();
    cursor = (short) (version + 1);

    // issue [16]
    if (cursor >= end || in[cursor] != (byte) 0xB0) fail();
    short issueEnd = DERValidator.derObjectEnd(in, cursor, end);
    short field = DERValidator.derContentOffset(in, cursor, issueEnd);
    field = U32.parseDerInteger(in, field, issueEnd, scratch, SamConst.S_PRM_ISSUER);
    field = U32.parseDerInteger(in, field, issueEnd, scratch, SamConst.S_PRM_BATCH);
    field = U32.parseDerInteger(in, field, issueEnd, scratch, SamConst.S_PRM_QUOTA);
    if (field != issueEnd) fail();
    cursor = issueEnd;

    // lcg [17]
    if (cursor >= end || in[cursor] != (byte) 0xB1) fail();
    short lcgEnd = DERValidator.derObjectEnd(in, cursor, end);
    field = DERValidator.derContentOffset(in, cursor, lcgEnd);
    field = U32.parseDerInteger(in, field, lcgEnd, scratch, SamConst.S_PRM_SEED);
    field = U32.parseDerInteger(in, field, lcgEnd, scratch, SamConst.S_PRM_MODULUS);
    field = U32.parseDerInteger(in, field, lcgEnd, scratch, SamConst.S_PRM_MULTIPLIER);
    field = U32.parseDerInteger(in, field, lcgEnd, scratch, SamConst.S_PRM_INCREMENT);
    if (field != lcgEnd) fail();
    cursor = lcgEnd;

    // f9SubjectTemplate [20]: RDN content <= 96 octets, an empty Name allowed, no serialNumber
    if (cursor >= end || in[cursor] != (byte) 0xB4) fail();
    short templateEnd = DERValidator.derObjectEnd(in, cursor, end);
    short template = DERValidator.derContentOffset(in, cursor, templateEnd);
    if (template >= templateEnd || in[template] != (byte) 0x30) fail();
    if (DERValidator.derObjectEnd(in, template, templateEnd) != templateEnd) fail();
    short templateContent = DERValidator.derContentOffset(in, template, templateEnd);
    short templateLength = (short) (templateEnd - templateContent);
    if (templateLength > SamConst.LENGTH_F9_TEMPLATE_MAX) fail();
    if (templateLength != (short) 0) {
      DERValidator.validateDerName(in, template, (short) (templateEnd - template));
      rejectSerialNumber(in, templateContent, templateEnd);
    }
    cursor = templateEnd;

    // samSubject [21] OPTIONAL: a Name of at most 128 octets
    short subject = (short) 0;
    short subjectLength = (short) 0;
    if (cursor < end && in[cursor] == (byte) 0xB5) {
      short subjectEnd = DERValidator.derObjectEnd(in, cursor, end);
      subject = DERValidator.derContentOffset(in, cursor, subjectEnd);
      subjectLength = (short) (subjectEnd - subject);
      if (subjectLength > SamConst.LENGTH_SAM_SUBJECT_MAX) fail();
      DERValidator.validateDerName(in, subject, subjectLength);
      cursor = subjectEnd;
    }

    // rootPublicKey [22], initialTimestamp [23] and wrappedFpeKey [24]
    short rootKey = SamLedger.expectPrimitive(in, cursor, end, (byte) 0x96, SamConst.LENGTH_POINT);
    cursor = (short) (rootKey + SamConst.LENGTH_POINT);
    short timestamp =
        SamLedger.expectPrimitive(in, cursor, end, (byte) 0x97, SamConst.LENGTH_TIMESTAMP);
    cursor = (short) (timestamp + SamConst.LENGTH_TIMESTAMP);
    if (cursor >= end || in[cursor] != (byte) 0xB8) fail();
    if (DERValidator.derObjectEnd(in, cursor, end) != end) fail();
    short wrappedEnd = end;
    short hostEph =
        SamLedger.expectPrimitive(
            in,
            DERValidator.derContentOffset(in, cursor, wrappedEnd),
            wrappedEnd,
            TLV.ASN1_OCTET_STRING,
            SamConst.LENGTH_POINT);
    short wrapped =
        SamLedger.expectPrimitive(
            in,
            (short) (hostEph + SamConst.LENGTH_POINT),
            wrappedEnd,
            TLV.ASN1_OCTET_STRING,
            SamConst.LENGTH_WRAPPED_KEY);
    if ((short) (wrapped + SamConst.LENGTH_WRAPPED_KEY) != end) fail();

    // IIN and batch: 4 digits each.
    short b = SamConst.BATCH_DIGITS;
    short k = SamConst.CIN_DIGITS;
    short work = SamConst.S_PRM_WORK;
    if (!U32.toDecimal(
        scratch,
        SamConst.S_PRM_ISSUER,
        scratch,
        work,
        scratch,
        SamConst.S_PRM_ISSUER_DIGITS,
        SamConst.ISSUER_DIGITS)) {
      fail();
    }
    if (!U32.toDecimal(
        scratch, SamConst.S_PRM_BATCH, scratch, work, scratch, SamConst.S_PRM_BATCH_DIGITS, b)) {
      fail();
    }

    // LCG: modulus == 10^8 exactly; x0, a and c below m; Hull-Dobell; a != 1.
    if (Util.arrayCompare(
            scratch, SamConst.S_PRM_MODULUS, SamConst.MODULUS, (short) 0, SamConst.LENGTH_U32)
        != (byte) 0) {
      fail();
    }
    if (!U32.toDecimal(
            scratch, SamConst.S_PRM_SEED, scratch, work, scratch, SamConst.S_PRM_X0_DIGITS, k)
        || !U32.toDecimal(
            scratch, SamConst.S_PRM_MULTIPLIER, scratch, work, scratch, SamConst.S_PRM_A_DIGITS, k)
        || !U32.toDecimal(
            scratch,
            SamConst.S_PRM_INCREMENT,
            scratch,
            work,
            scratch,
            SamConst.S_PRM_C_DIGITS,
            k)) {
      fail();
    }
    if (!DecimalLcg.isHullDobell(
        scratch, SamConst.S_PRM_A_DIGITS, scratch, SamConst.S_PRM_C_DIGITS, k)) {
      fail();
    }

    // Quota and root key.
    if (U32.compare(
            scratch, SamConst.S_PRM_QUOTA, scratch, SamConst.S_PRM_MODULUS, SamConst.LENGTH_U32)
        > (short) 0) {
      fail();
    }
    // The validator workspace is I/O buffer offsets 0..335; the packet is staged above it.
    if (!crypto.isValidPoint(in, rootKey, SamConst.LENGTH_POINT)) fail();

    // FF1 key: ECDH with the transport key, X9.63 KDF, RFC 3394 unwrap. An integrity failure is
    // 6A80 and nothing has been written yet.
    if (!crypto.isValidPoint(in, hostEph, SamConst.LENGTH_POINT)) fail();
    short iinAscii = (short) (SamConst.S_KW_BLOCK + 16);
    for (short i = 0; i < SamConst.ISSUER_DIGITS; i++) {
      scratch[(short) (iinAscii + i)] =
          (byte)
              (scratch[(short) (SamConst.S_PRM_ISSUER_DIGITS + SamConst.ISSUER_DIGITS - 1 - i)]
                  + (byte) '0');
    }
    if (!crypto.unwrapTransportedKey(in, hostEph, in, wrapped, scratch, iinAscii, scratch)) {
      Util.arrayFillNonAtomic(scratch, (short) 0, SamConst.LENGTH_SCRATCH, (byte) 0);
      fail();
    }

    // Everything validated: demote, write, promote.
    state.lifecycle = SamConst.LC_INSTALLED;
    for (short i = 0; i < SamConst.ISSUER_DIGITS; i++) {
      state.issuerDigits[i] =
          scratch[(short) (SamConst.S_PRM_ISSUER_DIGITS + SamConst.ISSUER_DIGITS - 1 - i)];
    }
    for (short i = 0; i < b; i++) {
      state.batchDigits[i] = scratch[(short) (SamConst.S_PRM_BATCH_DIGITS + b - 1 - i)];
    }
    copyDigits(SamConst.S_PRM_A_DIGITS, state.lcgA, k);
    copyDigits(SamConst.S_PRM_C_DIGITS, state.lcgC, k);
    copyDigits(SamConst.S_PRM_X0_DIGITS, state.lcgX0, k);
    copyDigits(SamConst.S_PRM_X0_DIGITS, state.lcgX, k);
    // DECIPHER jump maps M_j = f^(10^(j-1)), derived from the stored (a, c).
    DecimalLcg.jumpMaps(
        state.lcgA, state.lcgC, state.jumpA, state.jumpC, scratch, SamConst.S_JUMP_A);
    Util.arrayCopy(scratch, SamConst.S_PRM_QUOTA, state.quota, (short) 0, SamConst.LENGTH_U32);
    Util.arrayCopy(in, timestamp, state.lastTopUpTs, (short) 0, SamConst.LENGTH_TIMESTAMP);
    Util.arrayCopyNonAtomic(
        in, templateContent, state.f9SubjectTemplate, (short) 0, templateLength);
    state.f9SubjectTemplateLength = templateLength;
    if (subjectLength != (short) 0) {
      Util.arrayCopyNonAtomic(in, subject, state.expectedSamSubject, (short) 0, subjectLength);
    }
    state.expectedSamSubjectLength = subjectLength;
    crypto.rootPublic.setW(in, rootKey, SamConst.LENGTH_POINT);
    crypto.fpeKey.setKey(scratch, SamConst.S_KW_KEY);
    Util.arrayFillNonAtomic(scratch, SamConst.S_KW_KEY, SamConst.LENGTH_FPE_KEY, (byte) 0);
    // quota and lastTopUpTs still hold the initial values, so this is the root-bound digest.
    crypto.fpeKcv(scratch, SamConst.S_PRM_KCV);
    ledger.paramsDigest(
        scratch,
        SamConst.S_PARAMS_MESSAGE,
        scratch,
        SamConst.S_PRM_KCV,
        scratch,
        SamConst.S_PARAMS_DIGEST);
    Util.arrayCopyNonAtomic(
        scratch, SamConst.S_PARAMS_DIGEST, state.paramsDigest, (short) 0, SamConst.LENGTH_HASH);
    Util.arrayFillNonAtomic(scratch, (short) 0, SamConst.LENGTH_SCRATCH, (byte) 0);
    state.commitLifecycle(SamConst.LC_PARAMS_SET);
    crypto.clearTransportKey();
  }

  /**
   * GENERATE TRANSPORT KEY: a fresh one-time P-256 key pair for the next PUT PARAMETERS v5,
   * replacing any previous one.
   *
   * @return length of {@code 86 41 04XY} written at {@code out[offset]}
   */
  short generateTransportKey(byte[] out, short offset) {
    crypto.generateTransportKey();
    out[offset] = (byte) 0x86;
    out[(short) (offset + 1)] = (byte) SamConst.LENGTH_POINT;
    crypto.transportPublic.getW(out, (short) (offset + 2));
    return (short) (2 + SamConst.LENGTH_POINT);
  }

  /**
   * CHANGE OPERATOR PIN: {@code 80 L oldPIN | 81 L newPIN} (6..16 octets each), nothing trailing.
   * The old PIN is checked against the OwnerPIN retry counter (63Cx, 6983 when blocked) before the
   * new PIN is set.
   */
  void changeOperatorPin(byte[] in, short offset, short length) {
    short end = (short) (offset + length);
    if (length < (short) 2 || in[offset] != (byte) 0x80) fail();
    short oldEnd = DERValidator.derObjectEnd(in, offset, end);
    short oldPin = DERValidator.derContentOffset(in, offset, oldEnd);
    if (oldEnd >= end || in[oldEnd] != (byte) 0x81) fail();
    if (DERValidator.derObjectEnd(in, oldEnd, end) != end) fail();
    short newPin = DERValidator.derContentOffset(in, oldEnd, end);
    short oldLength = (short) (oldEnd - oldPin);
    short newLength = (short) (end - newPin);
    if (oldLength < SamConst.LENGTH_PIN_MIN
        || oldLength > SamConst.LENGTH_PIN_MAX
        || newLength < SamConst.LENGTH_PIN_MIN
        || newLength > SamConst.LENGTH_PIN_MAX) {
      fail();
    }
    if (state.operatorPin.getTriesRemaining() == (byte) 0) {
      ISOException.throwIt(ISO7816.SW_FILE_INVALID);
    }
    if (!state.operatorPin.check(in, oldPin, (byte) oldLength)) {
      ISOException.throwIt((short) (0x63C0 | state.operatorPin.getTriesRemaining()));
    }
    state.operatorPin.update(in, newPin, (byte) newLength);
  }

  /** SET OPERATOR PIN: 6..16 octets; resets the retry counter. */
  void setOperatorPin(byte[] in, short offset, short length) {
    if (length < SamConst.LENGTH_PIN_MIN || length > SamConst.LENGTH_PIN_MAX) fail();
    state.operatorPin.update(in, offset, (byte) length);
    state.pinSet = true;
  }

  /**
   * GENERATE SAM KEY. From CERT_LOADED the certificate is dropped and the SAM returns to
   * KEY_GENERATED with the new key.
   *
   * @return length of {@code 86 41 04XY} written at {@code out[offset]}
   */
  short generateKey(byte[] out, short offset) {
    state.lifecycle = SamConst.LC_PARAMS_SET;
    state.samCertLength = (short) 0;
    crypto.generateSamKey();
    out[offset] = (byte) 0x86;
    out[(short) (offset + 1)] = (byte) SamConst.LENGTH_POINT;
    short point = (short) (offset + 2);
    crypto.samPublic.getW(out, point);
    crypto.keyIdentifier(out, point, scratch, (short) 0, scratch, (short) 0);
    Util.arrayCopy(scratch, (short) 0, state.samSki, (short) 0, SamConst.LENGTH_SKI);
    state.commitLifecycle(SamConst.LC_KEY_GENERATED);
    return (short) (2 + SamConst.LENGTH_POINT);
  }

  /**
   * LOAD SAM CERTIFICATE: parses and verifies, then stores the certificate.
   *
   * @return length of {@code 8B 14 SKI} written at {@code out[outOffset]}
   */
  short loadCertificate(byte[] cert, short offset, short length, byte[] out, short outOffset) {
    if (length > SamConst.LENGTH_SAM_CERT_MAX) fail();
    parser.parse(cert, offset, length);
    state.lifecycle = SamConst.LC_KEY_GENERATED;
    Util.arrayCopyNonAtomic(cert, offset, state.samCert, (short) 0, length);
    Util.arrayCopyNonAtomic(
        scratch, SamConst.S_CERT_ALLOCATION, state.allocationSeq, (short) 0, SamConst.LENGTH_U32);
    Util.arrayCopyNonAtomic(
        scratch, SamConst.S_CERT_REGISTRY, state.registryHead, (short) 0, SamConst.LENGTH_HASH);
    Util.arrayCopyNonAtomic(
        scratch, SamConst.S_CERT_TIMES, state.samNotBefore, (short) 0, SamConst.LENGTH_TIME);
    Util.arrayCopyNonAtomic(
        scratch,
        (short) (SamConst.S_CERT_TIMES + SamConst.LENGTH_TIME),
        state.samNotAfter,
        (short) 0,
        SamConst.LENGTH_TIME);
    state.commitCertificate(length, parser.getSubjectOffset(), parser.getSubjectLength());
    out[outOffset] = (byte) 0x8B;
    out[(short) (outOffset + 1)] = (byte) SamConst.LENGTH_SKI;
    Util.arrayCopyNonAtomic(
        state.samSki, (short) 0, out, (short) (outOffset + 2), SamConst.LENGTH_SKI);
    return (short) (2 + SamConst.LENGTH_SKI);
  }

  /**
   * LOCK: requires the PIN to be set, the stored parameters to re-validate and at least 512 octets
   * of commit capacity; commits the genesis entry and enters OPERATIONAL.
   *
   * @return response length in the I/O buffer
   */
  short lock() {
    if (!state.pinSet) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    if (!revalidate()) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    if (JCSystem.getMaxCommitCapacity() < SamConst.MIN_COMMIT_CAPACITY) {
      ISOException.throwIt(SamConst.SW_EXHAUSTED);
    }
    return ledger.genesis();
  }

  /** Re-checks every stored parameter against the PUT PARAMETERS rules. */
  boolean revalidate() {
    short k = SamConst.CIN_DIGITS;
    if (!DecimalLcg.isDigits(state.issuerDigits, (short) 0, SamConst.ISSUER_DIGITS)
        || !DecimalLcg.isDigits(state.batchDigits, (short) 0, SamConst.BATCH_DIGITS)
        || !DecimalLcg.isDigits(state.lcgA, (short) 0, k)
        || !DecimalLcg.isDigits(state.lcgC, (short) 0, k)
        || !DecimalLcg.isDigits(state.lcgX0, (short) 0, k)) {
      return false;
    }
    if (!DecimalLcg.isHullDobell(state.lcgA, (short) 0, state.lcgC, (short) 0, k)) return false;
    if (U32.compare(state.quota, (short) 0, SamConst.MODULUS, (short) 0, SamConst.LENGTH_U32)
        > (short) 0) {
      return false;
    }
    return state.samCertLength > (short) 0
        && crypto.isSamKeyInitialized()
        && crypto.fpeKey.isInitialized();
  }

  private void copyDigits(short from, byte[] to, short k) {
    Util.arrayFillNonAtomic(to, (short) 0, SamConst.LENGTH_DIGITS, (byte) 0);
    Util.arrayCopyNonAtomic(scratch, from, to, (short) 0, k);
  }

  /** Rejects any AttributeTypeAndValue with type serialNumber (2.5.4.5) in validated RDNs. */
  private static void rejectSerialNumber(byte[] in, short cursor, short end) {
    while (cursor < end) {
      short setEnd = DERValidator.derObjectEnd(in, cursor, end);
      short attribute = DERValidator.derContentOffset(in, cursor, setEnd);
      while (attribute < setEnd) {
        short attributeEnd = DERValidator.derObjectEnd(in, attribute, setEnd);
        short oid = DERValidator.derContentOffset(in, attribute, attributeEnd);
        short oidEnd = DERValidator.derObjectEnd(in, oid, attributeEnd);
        short value = DERValidator.derContentOffset(in, oid, oidEnd);
        short length = (short) (oidEnd - value);
        if (length == (short) SamConst.OID_SERIAL_NUMBER.length
            && Util.arrayCompare(in, value, SamConst.OID_SERIAL_NUMBER, (short) 0, length)
                == (byte) 0) {
          fail();
        }
        attribute = attributeEnd;
      }
      cursor = setEnd;
    }
  }

  private static void fail() {
    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
  }
}
