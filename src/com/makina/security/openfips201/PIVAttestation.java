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
 * Maintains the F9 attestation authority profile and builds attestation certificates.
 *
 * <p>The F9 key material lives in the normal key store. This class owns the persistent issuer
 * subject (DER X.500 Name) and validity (DER), plus activation state. Certificates are built
 * directly into a caller-supplied response buffer (see {@link PIV#attest(byte)}) using the shared
 * PIV scratch for temporaries (serial, hash, signature) and handed to ChainBuffer with no
 * intermediate copy.
 *
 * <p>Subject/validity storage is allocated at installation because attestation is part of the
 * issuance lifecycle for every card. The profile is supplied over SCP-protected CHANGE REFERENCE
 * DATA (P1=0x11, P2=0xF9) in staged elements (86/87/92/93). A successful commit validates the F9
 * key pair and clears prior non-F9 key material and data object contents.
 *
 * <p>{@link PIV#attest(byte)} enforces the target slot's normal access rules before emitting a
 * simple v3 X.509 certificate (ECDSA-SHA256, fixed extensions, SPKI copied from the target) signed
 * by the active F9 authority.
 */
final class PIVAttestation {

  static final byte ID_KEY_ATTESTATION = (byte) 0xF9;
  // Response buffer budget for the worst supported certificate: maximum issuer subject (0x80) +
  // validity (0x40) + RSA-2048 SubjectPublicKeyInfo (about 0x126) + signature (about 0x50) +
  // version, serial, algorithm identifiers, subject CN, extensions, and DER staging overhead.
  // DERWriter fails closed with SW_FILE_FULL on overflow. ChainBuffer streams a complete response
  // from one buffer, so the worst-case certificate size is the floor for this value.
  static final short LENGTH_CERT_BUFFER = (short) 0x0300;
  // Issuer subject is capped below the full certificate budget (authority name only, not
  // cardholder data). Large target keys (RSA-2048 SPKI) are supported.
  static final short LENGTH_SUBJECT_MAX = (short) 0x80;
  static final short LENGTH_VALIDITY_MAX = (short) 0x40;
  static final byte ELEMENT_SUBJECT = (byte) 0x92;
  static final byte ELEMENT_VALIDITY = (byte) 0x93;
  static final byte ELEMENT_PUBLIC_KEY = (byte) 0x86;
  static final byte ELEMENT_PRIVATE_KEY = (byte) 0x87;
  private static final byte AUTHORITY_MECHANISM = PIV.ID_ALG_ECC_P256;
  private static final byte STAGED_PUBLIC_KEY = (byte) 0x01;
  private static final byte STAGED_PRIVATE_KEY = (byte) 0x02;
  private static final byte STAGED_KEYPAIR = (byte) (STAGED_PUBLIC_KEY | STAGED_PRIVATE_KEY);

  // Persistent issuer profile (subject DN and validity). Allocated at installation because
  // attestation is part of the issuance process for every card. The certificate itself is never
  // stored; it is built on demand into a caller-provided response buffer.
  private final byte[] subject;
  private final byte[] validity;
  private short subjectLength;
  private short validityLength;
  private byte stagedKeyElements;
  private boolean authorityActive;

  PIVAttestation() {
    subject = new byte[LENGTH_SUBJECT_MAX];
    validity = new byte[LENGTH_VALIDITY_MAX];
    subjectLength = (short) 0x00;
    validityLength = (short) 0x00;
    stagedKeyElements = (byte) 0x00;
    authorityActive = false;
  }

  static byte[] allocateResponseBuffer() {
    // Public response data. Prefer CLEAR_ON_DESELECT (JCRE zeroes on deselection). If the
    // platform cannot provide transient, fall back to persistent; attest() always passes the
    // buffer to ChainBuffer with clear-on-completion, so the contents are wiped after the
    // response is sent.
    try {
      return JCSystem.makeTransientByteArray(LENGTH_CERT_BUFFER, JCSystem.CLEAR_ON_DESELECT);
    } catch (SystemException e) {
      return new byte[LENGTH_CERT_BUFFER];
    }
  }

  void updateElement(byte element, byte[] buffer, short offset, short length) {
    switch (element) {
      case ELEMENT_SUBJECT:
        if (length > LENGTH_SUBJECT_MAX) ISOException.throwIt(ISO7816.SW_FILE_FULL);
        validateDerName(buffer, offset, length);
        Util.arrayCopyNonAtomic(buffer, offset, subject, (short) 0x00, length);
        if (length < subjectLength) {
          PIVSecurityProvider.zeroise(subject, length, (short) (subjectLength - length));
        }
        subjectLength = length;
        authorityActive = false;
        break;

      case ELEMENT_VALIDITY:
        if (length > LENGTH_VALIDITY_MAX) ISOException.throwIt(ISO7816.SW_FILE_FULL);
        validateDerValidity(buffer, offset, length);
        Util.arrayCopyNonAtomic(buffer, offset, validity, (short) 0x00, length);
        if (length < validityLength) {
          PIVSecurityProvider.zeroise(validity, length, (short) (validityLength - length));
        }
        validityLength = length;
        authorityActive = false;
        break;

      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        break;
    }
  }

  void deactivateAuthority() {
    authorityActive = false;
  }

  void noteKeyElementUpdated(byte element) {
    if (element == ELEMENT_PUBLIC_KEY) {
      stagedKeyElements |= STAGED_PUBLIC_KEY;
    } else if (element == ELEMENT_PRIVATE_KEY) {
      stagedKeyElements |= STAGED_PRIVATE_KEY;
    }
    authorityActive = false;
  }

  boolean isAuthorityActive() {
    return authorityActive;
  }

  boolean isAuthorityComplete(PIVKeyObjectECC authority) {
    return authority != null
        && authority.isInitialised()
        && subjectLength != (short) 0x00
        && validityLength != (short) 0x00;
  }

  boolean isAuthorityReadyToCommit(PIVKeyObjectECC authority) {
    if (!isAuthorityComplete(authority)) return false;
    return stagedKeyElements == (byte) 0x00 || stagedKeyElements == STAGED_KEYPAIR;
  }

  void validateAuthority(PIVKeyObjectECC authority, byte[] scratch) {
    if (!isAuthorityComplete(authority)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    validateAuthorityMechanism(authority);
    // Public/private consistency is the last commit gate before destructive wipe. This catches
    // swapped or mismatched F9 components without activating the new trust root.
    if ((short) (ATTESTATION_ACTIVATE_SIGNATURE_OFFSET + ATTESTATION_ACTIVATE_SIGNATURE_MAX)
        > PIV.LENGTH_SCRATCH) {
      ISOException.throwIt(ISO7816.SW_FILE_FULL);
    }
    Util.arrayFillNonAtomic(
        scratch, ATTESTATION_ACTIVATE_HASH_OFFSET, HASH_SHA256_LENGTH, (byte) 0xA5);
    short signatureLength =
        authority.sign(
            scratch,
            ATTESTATION_ACTIVATE_HASH_OFFSET,
            HASH_SHA256_LENGTH,
            scratch,
            ATTESTATION_ACTIVATE_SIGNATURE_OFFSET);
    if (!authority.verify(
        scratch,
        ATTESTATION_ACTIVATE_HASH_OFFSET,
        HASH_SHA256_LENGTH,
        scratch,
        ATTESTATION_ACTIVATE_SIGNATURE_OFFSET,
        signatureLength)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
  }

  void markAuthorityActive() {
    stagedKeyElements = (byte) 0x00;
    authorityActive = true;
  }

  void clearProfile() {
    PIVSecurityProvider.zeroise(subject, (short) 0x00, subjectLength);
    PIVSecurityProvider.zeroise(validity, (short) 0x00, validityLength);
    subjectLength = (short) 0x00;
    validityLength = (short) 0x00;
    stagedKeyElements = (byte) 0x00;
    authorityActive = false;
  }

  short buildCertificate(
      PIVKeyObjectECC authority,
      PIVKeyObjectPKI target,
      byte slot,
      byte[] scratch,
      byte[] out,
      short outOffset)
      throws ISOException {
    if (authority == null || !authority.isInitialised() || !authorityActive) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    validateAuthorityMechanism(authority);
    if (target == null || !target.isInitialised() || !target.isGenerated()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    // Build the certificate directly into the caller-provided response buffer. The TBS certificate
    // remains contiguous in that buffer so it can be hashed in place before the signature is
    // appended.
    DERWriter writer = DERWriter.getInstance();
    writer.init(out, outOffset);
    writer.begin((byte) 0x30);

    short tbsOffset = writer.getOffset();
    writer.begin((byte) 0x30);
    writer.write((byte) 0xA0);
    writer.write((byte) 0x03);
    writer.writeIntegerByte((byte) 0x02);

    writeRandomSerial(writer, scratch);

    writeEcdsaSha256Algorithm(writer);
    writer.write(subject, (short) 0x00, subjectLength);
    writer.write(validity, (short) 0x00, validityLength);
    writeSubjectName(writer, slot);

    short spkiOffset = writer.getOffset();
    short spkiLength = target.writeSubjectPublicKeyInfo(out, spkiOffset);
    writer.setOffset((short) (spkiOffset + spkiLength));
    writeBasicExtensions(writer);
    writer.end();

    short tbsLength = (short) (writer.getOffset() - tbsOffset);
    PIVCrypto.doSha256(out, tbsOffset, tbsLength, scratch, CERT_HASH_OFFSET);
    short signatureLength =
        authority.sign(
            scratch, CERT_HASH_OFFSET, HASH_SHA256_LENGTH, scratch, CERT_SIGNATURE_OFFSET);

    writeEcdsaSha256Algorithm(writer);
    writer.write((byte) 0x03);
    writer.writeLength((short) (signatureLength + 1));
    writer.write((byte) 0x00);
    writer.write(scratch, CERT_SIGNATURE_OFFSET, signatureLength);
    writer.end();
    return writer.getOffset();
  }

  private static void validateAuthorityMechanism(PIVKeyObjectECC authority) {
    // F9 is defined as a P-256 ECDSA-with-SHA256 authority. Keep the certificate signature OID and
    // hash sizing tied to that mechanism.
    if (authority.getMechanism() != AUTHORITY_MECHANISM) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  private static void writeRandomSerial(DERWriter writer, byte[] scratch) {
    PIVCrypto.doGenerateRandom(scratch, SERIAL_OFFSET, SERIAL_RANDOM_LENGTH);
    scratch[SERIAL_OFFSET] &= (byte) 0x7F;

    short serialOffset = SERIAL_OFFSET;
    short serialEnd = (short) (SERIAL_OFFSET + SERIAL_RANDOM_LENGTH);
    while (serialOffset < (short) (serialEnd - 1) && scratch[serialOffset] == (byte) 0x00) {
      serialOffset++;
    }
    if (scratch[serialOffset] == (byte) 0x00) {
      scratch[serialOffset] = (byte) 0x01;
    }

    // DER INTEGER is signed, so writePositiveInteger adds a leading 00 only when the first
    // remaining random byte would otherwise make the serial negative.
    writer.writePositiveInteger(scratch, serialOffset, (short) (serialEnd - serialOffset));
  }

  private static void writeSubjectName(DERWriter writer, byte slot) {
    writer.begin((byte) 0x30);
    writer.begin((byte) 0x31);
    writer.begin((byte) 0x30);
    writer.writeTlv((byte) 0x06, OID_COMMON_NAME, (short) 0x00, (short) OID_COMMON_NAME.length);
    writer.write((byte) 0x0C);
    writer.writeLength((short) (SUBJECT_PREFIX.length + 2));
    writer.write(SUBJECT_PREFIX, (short) 0x00, (short) SUBJECT_PREFIX.length);
    writer.write(toHex((byte) ((slot >> 4) & 0x0F)));
    writer.write(toHex((byte) (slot & 0x0F)));
    writer.end();
    writer.end();
    writer.end();
  }

  private static byte toHex(byte value) {
    return value < (byte) 10 ? (byte) ('0' + value) : (byte) ('A' + value - 10);
  }

  private static void writeBasicExtensions(DERWriter writer) {
    writer.begin((byte) 0xA3);
    writer.begin((byte) 0x30);
    writer.begin((byte) 0x30);
    writer.writeTlv(
        (byte) 0x06, OID_BASIC_CONSTRAINTS, (short) 0x00, (short) OID_BASIC_CONSTRAINTS.length);
    writer.writeTlv(
        (byte) 0x04,
        DER_BASIC_CONSTRAINTS_CA_FALSE,
        (short) 0x00,
        (short) DER_BASIC_CONSTRAINTS_CA_FALSE.length);
    writer.end();
    writer.begin((byte) 0x30);
    writer.writeTlv((byte) 0x06, OID_KEY_USAGE, (short) 0x00, (short) OID_KEY_USAGE.length);
    writer.writeTlv(
        (byte) 0x04,
        DER_KEY_USAGE_DIGITAL_SIGNATURE,
        (short) 0x00,
        (short) DER_KEY_USAGE_DIGITAL_SIGNATURE.length);
    writer.end();
    writer.end();
    writer.end();
  }

  private static void writeEcdsaSha256Algorithm(DERWriter writer) {
    writer.begin((byte) 0x30);
    writer.writeTlv(
        (byte) 0x06, OID_ECDSA_WITH_SHA256, (short) 0x00, (short) OID_ECDSA_WITH_SHA256.length);
    writer.end();
  }

  static void validateDerName(byte[] buffer, short offset, short length) {
    validateSingleDerObject(buffer, offset, length, (byte) 0x30);
  }

  static void validateDerValidity(byte[] buffer, short offset, short length) {
    // Keep validation structural: the card needs DER boundaries and Time tags, while date policy
    // remains with the provisioning system and relying-party validator.
    short contentOffset = validateSingleDerObject(buffer, offset, length, (byte) 0x30);
    short end = (short) (offset + length);
    short firstEnd = validateTime(buffer, contentOffset, end);
    short secondEnd = validateTime(buffer, firstEnd, end);
    if (secondEnd != end) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
  }

  private static short validateTime(byte[] buffer, short offset, short end) {
    if (offset >= end) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    byte tag = buffer[offset];
    if (tag != (byte) 0x17 && tag != (byte) 0x18) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    return derObjectEnd(buffer, offset, end);
  }

  private static short validateSingleDerObject(
      byte[] buffer, short offset, short length, byte tag) {
    short end = (short) (offset + length);
    if (end < offset) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    if (length < (short) 0x02 || buffer[offset] != tag) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    short objectEnd = derObjectEnd(buffer, offset, end);
    if (objectEnd != end) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    return derContentOffset(buffer, offset, end);
  }

  private static short derObjectEnd(byte[] buffer, short offset, short limit) {
    short contentOffset = derContentOffset(buffer, offset, limit);
    short length = derLength(buffer, offset, limit);
    short end = (short) (contentOffset + length);
    if (end > limit || end < contentOffset) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    return end;
  }

  private static short derContentOffset(byte[] buffer, short offset, short limit) {
    short lengthOffset = (short) (offset + 1);
    if (lengthOffset >= limit) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    byte lengthByte = buffer[lengthOffset];
    if ((lengthByte & (byte) 0x80) == (byte) 0) return (short) (lengthOffset + 1);
    byte count = (byte) (lengthByte & (byte) 0x7F);
    if (count == (byte) 0 || count > (byte) 2) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    short contentOffset = (short) (lengthOffset + 1 + count);
    if (contentOffset > limit || contentOffset < lengthOffset) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    return contentOffset;
  }

  private static short derLength(byte[] buffer, short offset, short limit) {
    short lengthOffset = (short) (offset + 1);
    if (lengthOffset >= limit) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    byte lengthByte = buffer[lengthOffset];
    if ((lengthByte & (byte) 0x80) == (byte) 0) return (short) (lengthByte & 0x7F);
    byte count = (byte) (lengthByte & (byte) 0x7F);
    short valueOffset = (short) (lengthOffset + 1);
    short valueEnd = (short) (valueOffset + count);
    if (count == (byte) 0 || count > (byte) 2 || valueEnd > limit || valueEnd < valueOffset) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    if (count == (byte) 1) return (short) (buffer[valueOffset] & 0xFF);
    if (count == (byte) 2) return Util.getShort(buffer, valueOffset);
    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    return (short) 0x00;
  }

  // Certificate profile, mirrored from docs/ATTESTATION.md:
  // - issuer and validity are the committed F9 profile values
  // - subject is CN=PIV Attestation <slot>
  // - signatureAlgorithm is ecdsa-with-SHA256 because F9 is fixed to P-256
  // - BasicConstraints is CA=false and KeyUsage is digitalSignature
  private static final byte[] OID_ECDSA_WITH_SHA256 = {
    (byte) 0x2A,
    (byte) 0x86,
    (byte) 0x48,
    (byte) 0xCE,
    (byte) 0x3D,
    (byte) 0x04,
    (byte) 0x03,
    (byte) 0x02
  };
  private static final byte[] OID_COMMON_NAME = {(byte) 0x55, (byte) 0x04, (byte) 0x03};
  private static final byte[] SUBJECT_PREFIX = {
    (byte) 'P',
    (byte) 'I',
    (byte) 'V',
    (byte) ' ',
    (byte) 'A',
    (byte) 't',
    (byte) 't',
    (byte) 'e',
    (byte) 's',
    (byte) 't',
    (byte) 'a',
    (byte) 't',
    (byte) 'i',
    (byte) 'o',
    (byte) 'n',
    (byte) ' '
  };
  private static final byte[] OID_BASIC_CONSTRAINTS = {(byte) 0x55, (byte) 0x1D, (byte) 0x13};
  private static final byte[] OID_KEY_USAGE = {(byte) 0x55, (byte) 0x1D, (byte) 0x0F};
  private static final byte[] DER_BASIC_CONSTRAINTS_CA_FALSE = {(byte) 0x30, (byte) 0x00};
  private static final byte[] DER_KEY_USAGE_DIGITAL_SIGNATURE = {
    (byte) 0x03, (byte) 0x02, (byte) 0x07, (byte) 0x80
  };
  private static final short HASH_SHA256_LENGTH = (short) 0x20;
  private static final short CERT_HASH_OFFSET = (short) 0x00;
  private static final short CERT_SIGNATURE_OFFSET =
      (short) (CERT_HASH_OFFSET + HASH_SHA256_LENGTH);
  private static final short SERIAL_OFFSET = (short) 0x00;
  private static final short SERIAL_RANDOM_LENGTH = (short) 0x10;
  private static final short ATTESTATION_ACTIVATE_HASH_OFFSET = (short) 0xB4;
  private static final short ATTESTATION_ACTIVATE_SIGNATURE_OFFSET =
      (short) (ATTESTATION_ACTIVATE_HASH_OFFSET + HASH_SHA256_LENGTH);
  private static final short ATTESTATION_ACTIVATE_SIGNATURE_MAX = (short) 0x48;
}
