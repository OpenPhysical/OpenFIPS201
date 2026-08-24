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

// #if ATTESTATION_ENABLED
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

  // Response buffer budget for the worst supported certificate: maximum issuer subject (0x80) +
  // validity (0x40) + RSA-3072 SubjectPublicKeyInfo (about 0x1A6) + signature (about 0x50) +
  // version, serial, algorithm identifiers, subject CN, extensions, and DER staging overhead.
  // DERWriter fails closed with SW_FILE_FULL on overflow. ChainBuffer streams a complete response
  // from one buffer, so the worst-case certificate size is the floor for this value.
  // RSA-3072 SPKI plus the maximum accepted issuer profile exceeds 768 bytes.
  static final short LENGTH_CERT_BUFFER = (short) 0x0400;
  // Issuer subject is capped below the full certificate budget (authority name only, not
  // cardholder data). Large target keys (RSA-3072 SPKI) are supported.
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
  private byte[] subject;
  private byte[] subjectStaging;
  private byte[] validity;
  private byte[] validityStaging;
  private short subjectLength;
  private short validityLength;
  private byte stagedKeyElements;
  private boolean authorityActive;
  private boolean authorityActivationPending;

  /** Allocates the active and staging buffers that make profile updates atomic. */
  PIVAttestation() {
    subject = new byte[LENGTH_SUBJECT_MAX];
    subjectStaging = new byte[LENGTH_SUBJECT_MAX];
    validity = new byte[LENGTH_VALIDITY_MAX];
    validityStaging = new byte[LENGTH_VALIDITY_MAX];
    subjectLength = (short) 0x00;
    validityLength = (short) 0x00;
    stagedKeyElements = (byte) 0x00;
    authorityActive = false;
    authorityActivationPending = false;
  }

  /**
   * Allocates the certificate response buffer and prefers deselection-cleared transient memory.
   *
   * @return buffer large enough for the largest supported attestation certificate
   */
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

  /**
   * Validates and atomically publishes one issuer-profile element.
   *
   * <p>RFC 5280 controls the DER issuer Name and Validity encodings. A successful update
   * deactivates F9 until the complete profile and key pair pass activation checks.
   *
   * @param element issuer name or validity selector
   * @param buffer input buffer
   * @param offset first input octet
   * @param length input length
   */
  void updateElement(byte element, byte[] buffer, short offset, short length) {
    switch (element) {
      case ELEMENT_SUBJECT:
        if (length > LENGTH_SUBJECT_MAX) ISOException.throwIt(ISO7816.SW_FILE_FULL);
        validateDerName(buffer, offset, length);
        Util.arrayCopyNonAtomic(buffer, offset, subjectStaging, (short) 0x00, length);
        PIVSecurityProvider.zeroise(
            subjectStaging, length, (short) (subjectStaging.length - length));
        commitSubject(length);
        break;

      case ELEMENT_VALIDITY:
        if (length > LENGTH_VALIDITY_MAX) ISOException.throwIt(ISO7816.SW_FILE_FULL);
        validateDerValidity(buffer, offset, length);
        Util.arrayCopyNonAtomic(buffer, offset, validityStaging, (short) 0x00, length);
        PIVSecurityProvider.zeroise(
            validityStaging, length, (short) (validityStaging.length - length));
        commitValidity(length);
        break;

      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        break;
    }
  }

  /**
   * Publishes the staged issuer name with a transactional buffer swap.
   *
   * <p>The transaction changes only references, length, and activation state. The method erases the
   * inactive buffer after the transaction because a full-buffer erase can exceed the Java Card
   * transaction-log capacity.
   *
   * @param length validated DER length in {@code subjectStaging}
   */
  private void commitSubject(short length) {
    byte[] previous = subject;
    JCSystem.beginTransaction();
    try {
      subject = subjectStaging;
      subjectStaging = previous;
      subjectLength = length;
      authorityActive = false;
      JCSystem.commitTransaction();
    } finally {
      if (JCSystem.getTransactionDepth() != (byte) 0) JCSystem.abortTransaction();
    }
    PIVSecurityProvider.zeroise(subjectStaging, (short) 0x00, (short) subjectStaging.length);
  }

  /**
   * Publishes the staged certificate-validity value with a transactional buffer swap.
   *
   * <p>The transaction makes the new value and its length visible together and deactivates the
   * authority until the complete profile passes activation checks. The inactive buffer is erased
   * outside the transaction to bound transaction-log use.
   *
   * @param length validated DER length in {@code validityStaging}
   */
  private void commitValidity(short length) {
    byte[] previous = validity;
    JCSystem.beginTransaction();
    try {
      validity = validityStaging;
      validityStaging = previous;
      validityLength = length;
      authorityActive = false;
      JCSystem.commitTransaction();
    } finally {
      if (JCSystem.getTransactionDepth() != (byte) 0) JCSystem.abortTransaction();
    }
    PIVSecurityProvider.zeroise(validityStaging, (short) 0x00, (short) validityStaging.length);
  }

  /** Deactivates F9 without erasing its staged or active profile material. */
  void deactivateAuthority() {
    authorityActive = false;
  }

  /**
   * Records an imported F9 key component and requires reactivation.
   *
   * @param element public- or private-key element selector
   */
  void noteKeyElementUpdated(byte element) {
    if (element == ELEMENT_PUBLIC_KEY) {
      stagedKeyElements |= STAGED_PUBLIC_KEY;
    } else if (element == ELEMENT_PRIVATE_KEY) {
      stagedKeyElements |= STAGED_PRIVATE_KEY;
    }
    authorityActive = false;
  }

  /** Returns whether the complete F9 profile is authorized to issue attestation certificates. */
  boolean isAuthorityActive() {
    return authorityActive;
  }

  /**
   * Reports whether F9 has key material, an issuer Name, and a Validity value.
   *
   * @param authority candidate F9 key object
   */
  boolean isAuthorityComplete(PIVKeyObjectECC authority) {
    return authority != null
        && authority.isInitialised()
        && subjectLength != (short) 0x00
        && validityLength != (short) 0x00;
  }

  /**
   * Reports whether activation can commit a complete and consistently staged F9 profile.
   *
   * <p>An imported key must supply both public and private components before activation. A
   * generated pair is already internally consistent and has no staged-component marker.
   *
   * @param authority candidate F9 key object
   */
  boolean isAuthorityReadyToCommit(PIVKeyObjectECC authority) {
    if (!isAuthorityComplete(authority)) return false;
    return stagedKeyElements == (byte) 0x00 || stagedKeyElements == STAGED_KEYPAIR;
  }

  /**
   * Validates the F9 mechanism and proves that its public and private components match.
   *
   * <p>The proof signs and verifies a fixed 256-bit challenge in card memory. Failure leaves the
   * authority inactive and prevents destructive rotation.
   *
   * @param authority candidate F9 key object
   * @param scratch applet scratch buffer for the challenge and signature
   */
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

  /** Marks a validated authority active when no destructive recovery phase is required. */
  void markAuthorityActive() {
    stagedKeyElements = (byte) 0x00;
    authorityActive = true;
    authorityActivationPending = false;
  }

  /**
   * Records the durable first phase of destructive authority activation.
   *
   * <p>The active flag is cleared in the same transaction that sets the pending flag. Selection
   * recovery can therefore repeat destructive cleanup without exposing a partly rotated profile.
   */
  void beginAuthorityActivation() {
    JCSystem.beginTransaction();
    try {
      authorityActive = false;
      authorityActivationPending = true;
      JCSystem.commitTransaction();
    } finally {
      if (JCSystem.getTransactionDepth() != (byte) 0) JCSystem.abortTransaction();
    }
  }

  /** Returns whether selection must complete destructive authority activation. */
  boolean isAuthorityActivationPending() {
    return authorityActivationPending;
  }

  /**
   * Atomically publishes the validated authority after destructive cleanup completes.
   *
   * <p>The staged-key marker, active flag, and recovery flag change in one Java Card transaction.
   */
  void completeAuthorityActivation() {
    JCSystem.beginTransaction();
    try {
      stagedKeyElements = (byte) 0x00;
      authorityActive = true;
      authorityActivationPending = false;
      JCSystem.commitTransaction();
    } finally {
      if (JCSystem.getTransactionDepth() != (byte) 0) JCSystem.abortTransaction();
    }
  }

  /** Erases all active and staged issuer-profile data and deactivates F9. */
  void clearProfile() {
    PIVSecurityProvider.zeroise(subject, (short) 0x00, (short) subject.length);
    PIVSecurityProvider.zeroise(subjectStaging, (short) 0x00, (short) subjectStaging.length);
    PIVSecurityProvider.zeroise(validity, (short) 0x00, (short) validity.length);
    PIVSecurityProvider.zeroise(validityStaging, (short) 0x00, (short) validityStaging.length);
    subjectLength = (short) 0x00;
    validityLength = (short) 0x00;
    stagedKeyElements = (byte) 0x00;
    authorityActive = false;
    authorityActivationPending = false;
  }

  /**
   * Builds and signs an RFC 5280 attestation certificate for a generated target key.
   *
   * <p>The certificate is written directly into the caller's response buffer. It uses the active
   * issuer profile, a random positive serial number, the target SubjectPublicKeyInfo, and an
   * ecdsa-with-SHA256 signature made by F9.
   *
   * @param authority active F9 signing key
   * @param target generated target key
   * @param slot target PIV key reference
   * @param scratch scratch buffer for serial, hash, and signature data
   * @param out output buffer
   * @param outOffset first output octet
   * @return complete certificate length
   */
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

  /**
   * Confirms that the attestation authority uses the fixed P-256 signing profile.
   *
   * @param authority candidate authority key
   * @throws ISOException if the key mechanism cannot produce the documented certificate profile
   */
  private static void validateAuthorityMechanism(PIVKeyObjectECC authority) {
    // F9 is defined as a P-256 ECDSA-with-SHA256 authority. Keep the certificate signature OID and
    // hash sizing tied to that mechanism.
    if (authority.getMechanism() != AUTHORITY_MECHANISM) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  /**
   * Writes a positive, non-zero 128-bit certificate serial number.
   *
   * <p>RFC 5280, Section 4.1.2.2 requires the serial number to be a positive integer assigned by
   * the issuing CA. A leading zero octet preserves a positive ASN.1 INTEGER value.
   *
   * @param writer certificate writer
   * @param scratch temporary random-number buffer
   */
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

  /**
   * Writes the deterministic subject name for one attested key slot.
   *
   * @param writer certificate writer
   * @param slot PIV key-reference byte appended to the common name as two hexadecimal digits
   */
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

  /** Returns the uppercase hexadecimal character for a value in the range 0 through 15. */
  private static byte toHex(byte value) {
    return value < (byte) 10 ? (byte) ('0' + value) : (byte) ('A' + value - 10);
  }

  /**
   * Writes the non-CA Basic Constraints and digitalSignature Key Usage extensions.
   *
   * <p>RFC 5280, Sections 4.2.1.3 and 4.2.1.9 define these extension values. The generated
   * certificate identifies an attested end-entity key and does not authorize certificate signing.
   *
   * @param writer certificate writer
   */
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

  /**
   * Writes the ecdsa-with-SHA256 AlgorithmIdentifier without parameters.
   *
   * <p>RFC 5758, Section 3.2 states that ECDSA signature AlgorithmIdentifier parameters &quot;MUST
   * be absent.&quot;
   *
   * @param writer certificate writer
   */
  private static void writeEcdsaSha256Algorithm(DERWriter writer) {
    writer.begin((byte) 0x30);
    writer.writeTlv(
        (byte) 0x06, OID_ECDSA_WITH_SHA256, (short) 0x00, (short) OID_ECDSA_WITH_SHA256.length);
    writer.end();
  }

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
   * Validates one RFC 5280 UTCTime or GeneralizedTime value.
   *
   * @param buffer input buffer
   * @param offset first tag octet
   * @param end exclusive enclosing-object limit
   * @return exclusive end offset of the validated time object
   * @throws ISOException with {@link ISO7816#SW_WRONG_DATA} for a non-canonical or invalid value
   */
  private static short validateTime(byte[] buffer, short offset, short end) {
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
  private static void validateOid(byte[] buffer, short offset, short end) {
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
  private static void validateNameValue(byte[] buffer, short offset, short end) {
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
  private static short compareTimes(byte[] buffer, short left, short right) {
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
  private static short decimal(byte[] buffer, short offset, short length) {
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
  private static short validateSingleDerObject(
      byte[] buffer, short offset, short length, byte tag) {
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
  private static short derObjectEnd(byte[] buffer, short offset, short limit) {
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
  private static short derContentOffset(byte[] buffer, short offset, short limit) {
    try {
      return TLV.dataOffset(buffer, offset, limit, true);
    } catch (ISOException e) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return (short) 0x00;
    }
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
// #endif
