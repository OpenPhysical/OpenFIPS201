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
import org.globalplatform.GPSystem;

/**
 * Maintains the on-card F9 attestation authority and builds attestation certificates.
 *
 * <p>The F9 key pair is generated on the card and lives in the normal key store. This class owns
 * the authority lifecycle and the issuer-signed F9 certificate:
 *
 * <ul>
 *   <li>{@link #STATE_NONE}: no usable authority.
 *   <li>{@link #STATE_GENERATED}: F9 was generated on the card and may prove possession of its
 *       private key and accept its certificate.
 *   <li>{@link #STATE_ACTIVATING}: a validated certificate is stored and the destructive activation
 *       wipe may still be incomplete; selection resumes it.
 *   <li>{@link #STATE_ACTIVE}: the authority issues attestation certificates. F9, its certificate,
 *       and the card OPID are immutable until the applet instance is deleted.
 * </ul>
 *
 * <p>The certificate is stored inside a persistent PIV certificate container {@code 53 82 LL LL 70
 * 82 LL LL <cert> 71 01 00 FE 00} so the same bytes serve both {@code 00 F9 F9 00} and the
 * read-only data object 5FFF01. Attestation certificates are built directly into the transient
 * response buffer owned by this class, which also serves as workspace while a certificate is
 * loaded.
 */
final class PIVAttestation {

  // Response buffer budget for the worst supported attestation certificate: issuer subject (0x80)
  // + validity (0x22) + RSA-3072 SubjectPublicKeyInfo (about 0x1A6) + signature (about 0x50) +
  // version, serial, algorithm identifiers, subject CN, extensions (including the 32-octet
  // platform identifier) and DER staging overhead. DERWriter fails closed with SW_FILE_FULL on
  // overflow. The same buffer is the workspace for certificate loading (see WORK_* offsets).
  static final short LENGTH_CERT_BUFFER = (short) 0x0400;
  // The F9 subject is the issuer of every attestation certificate and is capped accordingly.
  static final short LENGTH_SUBJECT_MAX = (short) 0x80;
  // Largest accepted issuer-signed F9 certificate.
  static final short LENGTH_AUTHORITY_CERT_MAX = (short) 0x02E0;
  // Smallest certificate that the fixed two-octet container lengths can encode as DER.
  private static final short LENGTH_AUTHORITY_CERT_MIN = (short) 0x0100;

  static final byte ELEMENT_CERTIFICATE = (byte) 0x70;
  static final byte ELEMENT_PUBLIC_KEY = (byte) 0x86;
  static final byte ELEMENT_PRIVATE_KEY = (byte) 0x87;

  static final byte STATE_NONE = (byte) 0x00;
  static final byte STATE_GENERATED = (byte) 0x01;
  static final byte STATE_ACTIVATING = (byte) 0x02;
  static final byte STATE_ACTIVE = (byte) 0x03;

  // Container layout: 53 82 LL LL | 70 82 LL LL | certificate | 71 01 00 | FE 00
  static final short CERT_STORE_OFFSET = (short) 0x08;
  private static final short LENGTH_CONTAINER_TRAILER = (short) 0x05;
  private static final short LENGTH_CONTAINER_OVERHEAD =
      (short) (CERT_STORE_OFFSET + LENGTH_CONTAINER_TRAILER);

  static final short LENGTH_KEY_IDENTIFIER = (short) 0x14;
  static final short LENGTH_OPID = (short) 17;
  static final short LENGTH_POP_NONCE_MIN = (short) 16;
  static final short LENGTH_POP_NONCE_MAX = (short) 64;

  private static final byte AUTHORITY_MECHANISM = PIV.ID_ALG_ECC_P256;
  private static final short LENGTH_P256_POINT = (short) 65;
  private static final short LENGTH_P256_SPKI = (short) 91;

  // parseAuthorityCertificate output: big-endian shorts relative to the work offset. Offsets are
  // absolute positions in the certificate input buffer.
  static final short PARSE_SUBJECT_OFFSET = (short) 0x00;
  static final short PARSE_SUBJECT_LENGTH = (short) 0x02;
  static final short PARSE_VALIDITY_OFFSET = (short) 0x04;
  static final short PARSE_VALIDITY_LENGTH = (short) 0x06;
  static final short PARSE_OPID_OFFSET = (short) 0x08;
  static final short PARSE_OPID_LENGTH = (short) 0x0A;
  static final short PARSE_SPKI_OFFSET = (short) 0x0C;
  static final short PARSE_SPKI_LENGTH = (short) 0x0E;
  static final short PARSE_KEY_ID_OFFSET = (short) 0x10;
  static final short LENGTH_PARSE_RESULT = (short) 0x12;

  // Load workspace inside the response buffer.
  private static final short WORK_SPKI = (short) 0x20;
  private static final short WORK_KEY_ID = (short) 0x80;
  private static final short WORK_PROOF_HASH = (short) 0xA0;
  private static final short WORK_PROOF_SIGNATURE = (short) 0xC0;
  private static final short LENGTH_SIGNATURE_MAX = (short) 0x48;
  private static final short LENGTH_WORK = (short) (WORK_PROOF_SIGNATURE + LENGTH_SIGNATURE_MAX);

  // Possession-proof layout in the caller's scratch buffer: M = "OPF9POP" || N || F9pub.
  private static final short POP_HASH_OFFSET = (short) 0x88;
  private static final short POP_SIGNATURE_OFFSET = (short) 0xA8;
  private static final short LENGTH_POP_WORK =
      (short) (POP_SIGNATURE_OFFSET + LENGTH_SIGNATURE_MAX);

  private final byte[] authorityCertificate;
  private final byte[] responseBuffer;
  private byte authorityState;
  private short certificateLength;
  private short subjectOffset;
  private short subjectLength;
  private short validityOffset;
  private short validityLength;
  private short opidOffset;
  private short opidLength;
  private short keyIdOffset;

  /** Allocates the persistent certificate container and the certificate response buffer. */
  PIVAttestation() {
    authorityCertificate =
        new byte[(short) (LENGTH_AUTHORITY_CERT_MAX + LENGTH_CONTAINER_OVERHEAD)];
    responseBuffer = allocateResponseBuffer();
    authorityState = STATE_NONE;
  }

  /**
   * Allocates the certificate response buffer and prefers deselection-cleared transient memory.
   *
   * @return buffer large enough for the largest supported attestation certificate
   */
  private static byte[] allocateResponseBuffer() {
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

  /** Returns the attestation response buffer, also used as certificate-load workspace. */
  byte[] getResponseBuffer() {
    return responseBuffer;
  }

  /** Returns the current authority lifecycle state. */
  byte getAuthorityState() {
    return authorityState;
  }

  /** Returns whether the authority is authorized to issue attestation certificates. */
  boolean isAuthorityActive() {
    return authorityState == STATE_ACTIVE;
  }

  /** Returns whether selection must complete destructive authority activation. */
  boolean isAuthorityActivationPending() {
    return authorityState == STATE_ACTIVATING;
  }

  /** Returns the persistent container {@code 53 .. 70 <cert> 71 01 00 FE 00}. */
  byte[] getAuthorityContainer() {
    return authorityCertificate;
  }

  /** Returns the complete container length, or zero when no certificate is stored. */
  short getAuthorityContainerLength() {
    if (certificateLength == (short) 0) return (short) 0;
    return (short) (certificateLength + LENGTH_CONTAINER_OVERHEAD);
  }

  /** Returns the stored certificate length; the certificate begins at CERT_STORE_OFFSET. */
  short getCertificateLength() {
    return certificateLength;
  }

  /** Returns the container offset of the subject serialNumber (OPID) value. */
  short getOpidOffset() {
    return opidOffset;
  }

  /** Returns the length of the OPID value. */
  short getOpidLength() {
    return opidLength;
  }

  /** Returns the container offset of the 20-octet F9 subject key identifier. */
  short getKeyIdOffset() {
    return keyIdOffset;
  }

  /**
   * Requires that F9 may still be generated, proven, or certified.
   *
   * <p>The authority is immutable once a certificate has been accepted (ACTIVATING or ACTIVE) and
   * after the applet leaves the GlobalPlatform SELECTABLE lifecycle state. Callers complete any
   * pending activation first so the recovery wipe is never skipped.
   *
   * @throws ISOException with {@link ISO7816#SW_CONDITIONS_NOT_SATISFIED} otherwise
   */
  void requireAuthorityProvisionable() {
    if (authorityState == STATE_ACTIVATING
        || authorityState == STATE_ACTIVE
        || GPSystem.getCardContentState() != GPSystem.APPLICATION_SELECTABLE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  /**
   * Discards any previous F9 profile before a new key pair is generated.
   *
   * <p>State, certificate length and every stored offset change in one transaction. A tear during
   * or after the following key generation leaves the authority in {@link #STATE_NONE}.
   */
  void beginAuthorityGeneration() {
    JCSystem.beginTransaction();
    try {
      authorityState = STATE_NONE;
      certificateLength = (short) 0;
      subjectOffset = (short) 0;
      subjectLength = (short) 0;
      validityOffset = (short) 0;
      validityLength = (short) 0;
      opidOffset = (short) 0;
      opidLength = (short) 0;
      keyIdOffset = (short) 0;
      JCSystem.commitTransaction();
    } finally {
      if (JCSystem.getTransactionDepth() != (byte) 0) JCSystem.abortTransaction();
    }
  }

  /**
   * Records a generated F9 key pair that passed its pairwise consistency test.
   *
   * <p>A single persistent byte write is atomic, so no transaction is required.
   */
  void completeAuthorityGeneration() {
    authorityState = STATE_GENERATED;
  }

  /**
   * Signs the F9 proof-of-possession message.
   *
   * <p>The message is {@code M = "OPF9POP" || N || F9pub}, where N is the issuer nonce and F9pub is
   * the 65-octet uncompressed P-256 point. The signature is ECDSA over SHA-256(M) and is returned
   * as a DER ECDSA-Sig-Value at {@code scratch[0]}. Every other workspace octet is zeroised.
   *
   * @param authority generated F9 key pair
   * @param nonce buffer holding N
   * @param nonceOffset first octet of N
   * @param nonceLength length of N, 16 through 64 octets
   * @param scratch workspace of at least {@code 0xF0} octets
   * @return signature length
   */
  short signPossessionProof(
      PIVKeyObjectECC authority,
      byte[] nonce,
      short nonceOffset,
      short nonceLength,
      byte[] scratch) {
    if (nonceLength < LENGTH_POP_NONCE_MIN || nonceLength > LENGTH_POP_NONCE_MAX) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    requireGeneratedAuthority(authority);

    short signatureLength = (short) 0;
    try {
      short cursor =
          Util.arrayCopyNonAtomic(
              POP_PREFIX, (short) 0, scratch, (short) 0, (short) POP_PREFIX.length);
      cursor = Util.arrayCopyNonAtomic(nonce, nonceOffset, scratch, cursor, nonceLength);
      cursor = (short) (cursor + authority.getPublicPoint(scratch, cursor));
      PIVCrypto.doSha256(scratch, (short) 0, cursor, scratch, POP_HASH_OFFSET);
      signatureLength =
          authority.sign(
              scratch, POP_HASH_OFFSET, HASH_SHA256_LENGTH, scratch, POP_SIGNATURE_OFFSET);
      Util.arrayCopyNonAtomic(scratch, POP_SIGNATURE_OFFSET, scratch, (short) 0, signatureLength);
    } finally {
      PIVSecurityProvider.zeroise(
          scratch, signatureLength, (short) (LENGTH_POP_WORK - signatureLength));
    }
    return signatureLength;
  }

  /**
   * Validates an issuer-signed F9 certificate and stores it as the authority profile.
   *
   * <p>The certificate must satisfy {@link #parseAuthorityCertificate}, carry this card's F9
   * SubjectPublicKeyInfo, and carry the RFC 7093 Section 2 method 1 key identifier: &quot;the
   * keyIdentifier is composed of the leftmost 160-bits of the SHA-256 hash of the value of the BIT
   * STRING subjectPublicKey&quot;. The F9 pair must also sign and verify a fixed challenge. On
   * success the certificate is stored and the authority moves to {@link #STATE_ACTIVATING}; the
   * caller then completes the destructive activation wipe and calls {@link
   * #completeAuthorityActivation()}.
   *
   * @param authority generated F9 key pair
   * @param certificate buffer holding the certificate
   * @param offset first certificate octet
   * @param length certificate length
   * @throws ISOException {@code 6985} for a wrong state, {@code 6A84} for an oversize certificate
   *     or subject, and {@code 6A80} for any profile or binding failure
   */
  void loadAuthorityCertificate(
      PIVKeyObjectECC authority, byte[] certificate, short offset, short length) {
    requireGeneratedAuthority(authority);
    if (length > LENGTH_AUTHORITY_CERT_MAX) ISOException.throwIt(ISO7816.SW_FILE_FULL);
    if (length < LENGTH_AUTHORITY_CERT_MIN) ISOException.throwIt(ISO7816.SW_WRONG_DATA);

    byte[] work = responseBuffer;
    try {
      parseAuthorityCertificate(certificate, offset, length, work, (short) 0);

      // The certificate must certify this card's F9 public key and nothing else.
      short spkiOffset = Util.getShort(work, PARSE_SPKI_OFFSET);
      short spkiLength = Util.getShort(work, PARSE_SPKI_LENGTH);
      short ownLength = authority.writeSubjectPublicKeyInfo(work, WORK_SPKI);
      if (ownLength != LENGTH_P256_SPKI
          || spkiLength != ownLength
          || Util.arrayCompare(certificate, spkiOffset, work, WORK_SPKI, ownLength) != (byte) 0) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      short pointOffset = (short) (WORK_SPKI + LENGTH_P256_SPKI - LENGTH_P256_POINT);
      PIVCrypto.doSha256(work, pointOffset, LENGTH_P256_POINT, work, WORK_KEY_ID);
      if (Util.arrayCompare(
              certificate,
              Util.getShort(work, PARSE_KEY_ID_OFFSET),
              work,
              WORK_KEY_ID,
              LENGTH_KEY_IDENTIFIER)
          != (byte) 0) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      validateAuthority(authority, work);

      // State is GENERATED with a zero certificate length, so a tear during this copy leaves no
      // visible certificate.
      short delta = (short) (CERT_STORE_OFFSET - offset);
      Util.arrayCopyNonAtomic(certificate, offset, authorityCertificate, CERT_STORE_OFFSET, length);
      short trailer = (short) (CERT_STORE_OFFSET + length);
      Util.arrayCopyNonAtomic(
          CONTAINER_TRAILER,
          (short) 0,
          authorityCertificate,
          trailer,
          (short) CONTAINER_TRAILER.length);
      authorityCertificate[0] = PIV.CONST_TAG_DATA;
      authorityCertificate[1] = (byte) 0x82;
      authorityCertificate[4] = ELEMENT_CERTIFICATE;
      authorityCertificate[5] = (byte) 0x82;

      JCSystem.beginTransaction();
      try {
        Util.setShort(
            authorityCertificate, (short) 2, (short) (length + LENGTH_CONTAINER_OVERHEAD - 4));
        Util.setShort(authorityCertificate, (short) 6, length);
        certificateLength = length;
        subjectOffset = (short) (Util.getShort(work, PARSE_SUBJECT_OFFSET) + delta);
        subjectLength = Util.getShort(work, PARSE_SUBJECT_LENGTH);
        validityOffset = (short) (Util.getShort(work, PARSE_VALIDITY_OFFSET) + delta);
        validityLength = Util.getShort(work, PARSE_VALIDITY_LENGTH);
        opidOffset = (short) (Util.getShort(work, PARSE_OPID_OFFSET) + delta);
        opidLength = Util.getShort(work, PARSE_OPID_LENGTH);
        keyIdOffset = (short) (Util.getShort(work, PARSE_KEY_ID_OFFSET) + delta);
        authorityState = STATE_ACTIVATING;
        JCSystem.commitTransaction();
      } finally {
        if (JCSystem.getTransactionDepth() != (byte) 0) JCSystem.abortTransaction();
      }
    } finally {
      PIVSecurityProvider.zeroise(work, (short) 0, LENGTH_WORK);
    }
  }

  /** Publishes the authority after the activation wipe completes. */
  void completeAuthorityActivation() {
    JCSystem.beginTransaction();
    try {
      authorityState = STATE_ACTIVE;
      JCSystem.commitTransaction();
    } finally {
      if (JCSystem.getTransactionDepth() != (byte) 0) JCSystem.abortTransaction();
    }
  }

  /**
   * Requires a GENERATED authority whose F9 pair was generated on the card.
   *
   * @throws ISOException with {@link ISO7816#SW_CONDITIONS_NOT_SATISFIED} otherwise
   */
  private void requireGeneratedAuthority(PIVKeyObjectECC authority) {
    if (authorityState != STATE_GENERATED
        || authority == null
        || !authority.isGenerated()
        || !authority.isInitialised()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    validateAuthorityMechanism(authority);
  }

  /**
   * Proves that the F9 public and private components match.
   *
   * <p>The proof signs and verifies a fixed 256-bit challenge at work offsets {@code 0xA0} and
   * above. Failure leaves the authority inactive and prevents the destructive activation wipe.
   *
   * @param authority candidate F9 key object
   * @param work workspace of at least {@code LENGTH_WORK} octets
   */
  private static void validateAuthority(PIVKeyObjectECC authority, byte[] work) {
    Util.arrayFillNonAtomic(work, WORK_PROOF_HASH, HASH_SHA256_LENGTH, (byte) 0xA5);
    short signatureLength =
        authority.sign(work, WORK_PROOF_HASH, HASH_SHA256_LENGTH, work, WORK_PROOF_SIGNATURE);
    if (!authority.verify(
        work, WORK_PROOF_HASH, HASH_SHA256_LENGTH, work, WORK_PROOF_SIGNATURE, signatureLength)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
  }

  /**
   * Parses and validates the issuer-signed F9 certificate profile.
   *
   * <p>RFC 5280, Section 4.1 requires DER. The accepted profile is a v3 certificate whose
   * tbsCertificate signature AlgorithmIdentifier equals signatureAlgorithm (Section 4.1.2.3: the
   * field &quot;MUST contain the same algorithm identifier as the signatureAlgorithm field&quot;)
   * and is exactly ecdsa-with-SHA256 without parameters, a positive minimal serial of at most 20
   * octets (Section 4.1.2.2), DER issuer and subject Names, a DER Validity, no unique identifiers,
   * and extensions containing exactly one each of:
   *
   * <ul>
   *   <li>critical basicConstraints {@code cA TRUE, pathLenConstraint 0};
   *   <li>critical keyUsage {@code keyCertSign} only;
   *   <li>non-critical subjectKeyIdentifier of 20 octets;
   *   <li>non-critical authorityKeyIdentifier.
   * </ul>
   *
   * <p>Any other critical extension is rejected. The subject must differ from the issuer and carry
   * exactly one serialNumber (2.5.4.5) PrintableString attribute, alone in its RDN, whose value is
   * a canonical OPID (see {@link #validateOpid}). The signature value itself is verified by the
   * issuance host, not by the card.
   *
   * @param cert buffer holding the certificate
   * @param offset first certificate octet
   * @param length certificate length
   * @param work output buffer for the PARSE_* fields
   * @param workOffset first output octet
   * @throws ISOException {@code 6A84} for a subject above {@link #LENGTH_SUBJECT_MAX}, otherwise
   *     {@code 6A80}
   */
  static void parseAuthorityCertificate(
      byte[] cert, short offset, short length, byte[] work, short workOffset) {
    short end = (short) (offset + length);
    short tbs = DERValidator.validateSingleDerObject(cert, offset, length, (byte) 0x30);

    short tbsEnd = requireObject(cert, tbs, end, (byte) 0x30);
    short signatureAlgorithm = tbsEnd;
    short signatureAlgorithmEnd = requireObject(cert, signatureAlgorithm, end, (byte) 0x30);
    validateAlgorithmIdentifier(cert, signatureAlgorithm, signatureAlgorithmEnd);
    short signatureEnd = requireObject(cert, signatureAlgorithmEnd, end, (byte) 0x03);
    if (signatureEnd != end) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    short signatureContent = DERValidator.derContentOffset(cert, signatureAlgorithmEnd, end);
    if ((short) (signatureEnd - signatureContent) < (short) 2
        || cert[signatureContent] != (byte) 0x00) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    short cursor = DERValidator.derContentOffset(cert, tbs, tbsEnd);

    // version [0] EXPLICIT INTEGER v3(2)
    if ((short) (tbsEnd - cursor) < (short) DER_VERSION_V3.length
        || Util.arrayCompare(cert, cursor, DER_VERSION_V3, (short) 0, (short) DER_VERSION_V3.length)
            != (byte) 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    cursor += (short) DER_VERSION_V3.length;

    cursor = validateSerialNumber(cert, cursor, tbsEnd);

    short innerAlgorithmEnd = requireObject(cert, cursor, tbsEnd, (byte) 0x30);
    short algorithmLength = (short) (signatureAlgorithmEnd - signatureAlgorithm);
    if ((short) (innerAlgorithmEnd - cursor) != algorithmLength
        || Util.arrayCompare(cert, cursor, cert, signatureAlgorithm, algorithmLength) != (byte) 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    cursor = innerAlgorithmEnd;

    short issuer = cursor;
    short issuerEnd = requireObject(cert, issuer, tbsEnd, (byte) 0x30);
    short issuerLength = (short) (issuerEnd - issuer);
    DERValidator.validateDerName(cert, issuer, issuerLength);

    short validity = issuerEnd;
    short validityEnd = requireObject(cert, validity, tbsEnd, (byte) 0x30);
    DERValidator.validateDerValidity(cert, validity, (short) (validityEnd - validity));

    short subject = validityEnd;
    short subjectEnd = requireObject(cert, subject, tbsEnd, (byte) 0x30);
    short subjectLen = (short) (subjectEnd - subject);
    if (subjectLen > LENGTH_SUBJECT_MAX) ISOException.throwIt(ISO7816.SW_FILE_FULL);
    DERValidator.validateDerName(cert, subject, subjectLen);
    if (subjectLen == issuerLength
        && Util.arrayCompare(cert, subject, cert, issuer, subjectLen) == (byte) 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    findOpid(cert, subject, subjectEnd, work, workOffset);

    short spki = subjectEnd;
    short spkiEnd = requireObject(cert, spki, tbsEnd, (byte) 0x30);

    // issuerUniqueID [1] and subjectUniqueID [2] are not part of the profile; extensions [3] are
    // mandatory and must close the tbsCertificate.
    short extensionsEnd = requireObject(cert, spkiEnd, tbsEnd, (byte) 0xA3);
    if (extensionsEnd != tbsEnd) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    short extensions = DERValidator.derContentOffset(cert, spkiEnd, extensionsEnd);
    if (requireObject(cert, extensions, extensionsEnd, (byte) 0x30) != extensionsEnd) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    parseExtensions(
        cert,
        DERValidator.derContentOffset(cert, extensions, extensionsEnd),
        extensionsEnd,
        work,
        workOffset);

    Util.setShort(work, (short) (workOffset + PARSE_SUBJECT_OFFSET), subject);
    Util.setShort(work, (short) (workOffset + PARSE_SUBJECT_LENGTH), subjectLen);
    Util.setShort(work, (short) (workOffset + PARSE_VALIDITY_OFFSET), validity);
    Util.setShort(
        work, (short) (workOffset + PARSE_VALIDITY_LENGTH), (short) (validityEnd - validity));
    Util.setShort(work, (short) (workOffset + PARSE_SPKI_OFFSET), spki);
    Util.setShort(work, (short) (workOffset + PARSE_SPKI_LENGTH), (short) (spkiEnd - spki));
  }

  /**
   * Requires one strict DER object with a given tag inside an enclosing limit.
   *
   * @return exclusive end of the object
   */
  private static short requireObject(byte[] buffer, short offset, short limit, byte tag) {
    if (offset >= limit || buffer[offset] != tag) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    return DERValidator.derObjectEnd(buffer, offset, limit);
  }

  /**
   * Requires the AlgorithmIdentifier to be exactly ecdsa-with-SHA256 without parameters.
   *
   * <p>The issuing SAM signs with P-256 and SHA-256. RFC 5758, Section 3.2: for ecdsa-with-SHA256
   * &quot;the encoding MUST omit the parameters field&quot;.
   */
  private static void validateAlgorithmIdentifier(byte[] buffer, short offset, short end) {
    if ((short) (end - offset) != (short) DER_ECDSA_WITH_SHA256_ALGORITHM.length
        || Util.arrayCompare(
                buffer,
                offset,
                DER_ECDSA_WITH_SHA256_ALGORITHM,
                (short) 0,
                (short) DER_ECDSA_WITH_SHA256_ALGORITHM.length)
            != (byte) 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
  }

  /**
   * Validates the certificate serialNumber.
   *
   * <p>RFC 5280, Section 4.1.2.2: &quot;The serial number MUST be a positive integer&quot; and
   * &quot;Conforming CAs MUST NOT use serialNumber values longer than 20 octets.&quot; X.690,
   * Section 8.3.2 forbids redundant leading octets.
   *
   * @return exclusive end of the INTEGER
   */
  private static short validateSerialNumber(byte[] buffer, short offset, short limit) {
    short serialEnd = requireObject(buffer, offset, limit, (byte) 0x02);
    short content = DERValidator.derContentOffset(buffer, offset, serialEnd);
    short length = (short) (serialEnd - content);
    if (length < (short) 1 || length > (short) 20 || (buffer[content] & (byte) 0x80) != 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    if (length == (short) 1 && buffer[content] == (byte) 0x00) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    if (length > (short) 1
        && buffer[content] == (byte) 0x00
        && (buffer[(short) (content + 1)] & (byte) 0x80) == 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    return serialEnd;
  }

  /**
   * Locates the single subject serialNumber attribute and validates its OPID value.
   *
   * <p>The subject has already passed {@link DERValidator#validateDerName}. The serialNumber
   * attribute (2.5.4.5) must occur exactly once, alone in its RelativeDistinguishedName, as a
   * PrintableString.
   */
  private static void findOpid(
      byte[] buffer, short subject, short subjectEnd, byte[] work, short workOffset) {
    short found = (short) -1;
    short foundLength = (short) 0;
    short cursor = DERValidator.derContentOffset(buffer, subject, subjectEnd);
    while (cursor < subjectEnd) {
      short setEnd = DERValidator.derObjectEnd(buffer, cursor, subjectEnd);
      short attribute = DERValidator.derContentOffset(buffer, cursor, setEnd);
      short firstAttributeEnd = DERValidator.derObjectEnd(buffer, attribute, setEnd);
      while (attribute < setEnd) {
        short attributeEnd = DERValidator.derObjectEnd(buffer, attribute, setEnd);
        short oid = DERValidator.derContentOffset(buffer, attribute, attributeEnd);
        short oidEnd = DERValidator.derObjectEnd(buffer, oid, attributeEnd);
        short oidContent = DERValidator.derContentOffset(buffer, oid, oidEnd);
        if (isOid(buffer, oidContent, oidEnd, OID_SERIAL_NUMBER)) {
          if (found >= (short) 0 || firstAttributeEnd != setEnd || buffer[oidEnd] != (byte) 0x13) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
          }
          found = DERValidator.derContentOffset(buffer, oidEnd, attributeEnd);
          foundLength = (short) (attributeEnd - found);
        }
        attribute = attributeEnd;
      }
      cursor = setEnd;
    }
    if (found < (short) 0) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    validateOpid(buffer, found, foundLength);
    Util.setShort(work, (short) (workOffset + PARSE_OPID_OFFSET), found);
    Util.setShort(work, (short) (workOffset + PARSE_OPID_LENGTH), foundLength);
  }

  /**
   * Validates the canonical OPID {@code IIII || E || L}.
   *
   * <p>The value is exactly 17 ASCII digits: the 4-digit issuer identifier, the 12 enciphered
   * digits, and the Luhn mod-10 check digit L computed over the 16 preceding digits, so the Luhn
   * sum over all 17 digits is a multiple of ten. The card does not decipher E.
   *
   * @param buffer buffer holding the OPID
   * @param offset first digit
   * @param length number of digits
   * @throws ISOException with {@link ISO7816#SW_WRONG_DATA} if any rule fails
   */
  static void validateOpid(byte[] buffer, short offset, short length) {
    if (length != LENGTH_OPID) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    for (short i = (short) 0; i < length; i++) {
      byte value = buffer[(short) (offset + i)];
      if (value < (byte) '0' || value > (byte) '9') ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    short sum = (short) 0;
    boolean doubled = false;
    for (short i = (short) (length - 1); i >= (short) 0; i--) {
      short digit = (short) (buffer[(short) (offset + i)] - (byte) '0');
      if (doubled) {
        digit = (short) (digit * 2);
        if (digit > (short) 9) digit = (short) (digit - 9);
      }
      sum = (short) (sum + digit);
      doubled = !doubled;
    }
    if ((short) (sum % 10) != (short) 0) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
  }

  /**
   * Validates the F9 certificate extensions and records the subject key identifier offset.
   *
   * <p>Each Extension is {@code SEQUENCE {extnID, critical BOOLEAN DEFAULT FALSE, extnValue}}.
   * X.690, Section 11.5 requires DER to omit a value equal to its DEFAULT, so an explicit FALSE is
   * rejected. RFC 5280, Section 4.2: &quot;A certificate-using system MUST reject the certificate
   * if it encounters a critical extension it does not recognize&quot;.
   */
  private static void parseExtensions(
      byte[] buffer, short cursor, short end, byte[] work, short workOffset) {
    if (cursor >= end) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    byte seen = (byte) 0;
    while (cursor < end) {
      short extensionEnd = requireObject(buffer, cursor, end, (byte) 0x30);
      short element = DERValidator.derContentOffset(buffer, cursor, extensionEnd);
      short oidEnd = requireObject(buffer, element, extensionEnd, (byte) 0x06);
      short oid = DERValidator.derContentOffset(buffer, element, oidEnd);
      DERValidator.validateOid(buffer, oid, oidEnd);
      element = oidEnd;

      boolean critical = false;
      if (element < extensionEnd && buffer[element] == (byte) 0x01) {
        if ((short) (extensionEnd - element) < (short) 3
            || buffer[(short) (element + 1)] != (byte) 0x01
            || buffer[(short) (element + 2)] != (byte) 0xFF) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        critical = true;
        element += (short) 3;
      }
      short valueEnd = requireObject(buffer, element, extensionEnd, (byte) 0x04);
      if (valueEnd != extensionEnd) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      short value = DERValidator.derContentOffset(buffer, element, valueEnd);
      short valueLength = (short) (valueEnd - value);

      byte bit;
      if (isOid(buffer, oid, oidEnd, OID_BASIC_CONSTRAINTS)) {
        bit = SEEN_BASIC_CONSTRAINTS;
        requireValue(critical, buffer, value, valueLength, DER_BASIC_CONSTRAINTS_CA_PATHLEN_0);
      } else if (isOid(buffer, oid, oidEnd, OID_KEY_USAGE)) {
        bit = SEEN_KEY_USAGE;
        requireValue(critical, buffer, value, valueLength, DER_KEY_USAGE_KEY_CERT_SIGN);
      } else if (isOid(buffer, oid, oidEnd, OID_SUBJECT_KEY_IDENTIFIER)) {
        // RFC 5280, Section 4.2.1.2: "Conforming CAs MUST mark this extension as non-critical."
        bit = SEEN_SUBJECT_KEY_IDENTIFIER;
        if (critical
            || valueLength != (short) (2 + LENGTH_KEY_IDENTIFIER)
            || buffer[value] != (byte) 0x04
            || buffer[(short) (value + 1)] != (byte) LENGTH_KEY_IDENTIFIER) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        Util.setShort(work, (short) (workOffset + PARSE_KEY_ID_OFFSET), (short) (value + 2));
      } else if (isOid(buffer, oid, oidEnd, OID_AUTHORITY_KEY_IDENTIFIER)) {
        // RFC 5280, Section 4.2.1.1: "Conforming CAs MUST mark this extension as non-critical."
        bit = SEEN_AUTHORITY_KEY_IDENTIFIER;
        if (critical) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        validateAuthorityKeyIdentifier(buffer, value, valueLength);
      } else {
        if (critical) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        bit = (byte) 0;
      }
      if ((seen & bit) != (byte) 0) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      seen |= bit;
      cursor = extensionEnd;
    }
    if (seen != SEEN_ALL) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
  }

  /** Requires a critical extension whose extnValue equals an exact DER encoding. */
  private static void requireValue(
      boolean critical, byte[] buffer, short value, short length, byte[] expected) {
    if (!critical
        || length != (short) expected.length
        || Util.arrayCompare(buffer, value, expected, (short) 0, length) != (byte) 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
  }

  /**
   * Validates AuthorityKeyIdentifier {@code SEQUENCE {[0] keyIdentifier OPTIONAL, [1]
   * authorityCertIssuer OPTIONAL, [2] authorityCertSerialNumber OPTIONAL}} with a mandatory
   * keyIdentifier, as RFC 5280, Section 4.2.1.1 requires for certificates generated by conforming
   * CAs.
   */
  private static void validateAuthorityKeyIdentifier(byte[] buffer, short value, short length) {
    short content = DERValidator.validateSingleDerObject(buffer, value, length, (byte) 0x30);
    short end = (short) (value + length);
    short keyIdEnd = requireObject(buffer, content, end, (byte) 0x80);
    if (keyIdEnd == DERValidator.derContentOffset(buffer, content, keyIdEnd)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    short cursor = keyIdEnd;
    if (cursor < end && buffer[cursor] == (byte) 0xA1) {
      cursor = DERValidator.derObjectEnd(buffer, cursor, end);
      if (cursor >= end || buffer[cursor] != (byte) 0x82) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
      cursor = DERValidator.derObjectEnd(buffer, cursor, end);
    }
    if (cursor != end) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
  }

  /** Returns whether OID content octets equal an expected encoding. */
  private static boolean isOid(byte[] buffer, short offset, short end, byte[] expected) {
    return (short) (end - offset) == (short) expected.length
        && Util.arrayCompare(buffer, offset, expected, (short) 0, (short) expected.length)
            == (byte) 0;
  }

  /**
   * Builds and signs an RFC 5280 attestation certificate for a generated target key.
   *
   * <p>The certificate is written directly into the caller's response buffer. Its issuer and
   * validity are the subject and validity of the stored F9 certificate, so the certificate chains
   * to F9 and inherits the F9 window. It carries a random positive serial number, the target
   * SubjectPublicKeyInfo, the extensions written by {@link #writeExtensions}, and an
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
    if (authorityState != STATE_ACTIVE
        || authority == null
        || !authority.isInitialised()
        || !authority.isGenerated()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    validateAuthorityMechanism(authority);
    if (target == null || !target.isInitialised() || !target.isGenerated()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    byte[] keyUsage = keyUsageFor(target);

    // Build the certificate directly into the caller-provided response buffer. The TBS certificate
    // remains contiguous in that buffer so it can be hashed in place before the signature is
    // appended.
    DERWriter writer = DERWriter.getInstance();
    writer.init(out, outOffset);
    writer.begin((byte) 0x30);

    short tbsOffset = writer.getOffset();
    writer.begin((byte) 0x30);
    writer.write(DER_VERSION_V3, (short) 0x00, (short) DER_VERSION_V3.length);

    writeRandomSerial(writer, scratch);

    writeEcdsaSha256Algorithm(writer);
    writer.write(authorityCertificate, subjectOffset, subjectLength);
    writer.write(authorityCertificate, validityOffset, validityLength);
    writeSubjectName(writer, slot);

    short spkiOffset = writer.getOffset();
    short spkiLength = target.writeSubjectPublicKeyInfo(out, spkiOffset);
    writer.setOffset((short) (spkiOffset + spkiLength));
    writeExtensions(writer, target, slot, keyUsage);
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
   * Selects the leaf keyUsage from the target role, in GENERAL AUTHENTICATE dispatch order.
   *
   * <p>RFC 5280, Section 4.2.1.3: digitalSignature for signing keys, keyEncipherment for RSA key
   * transport, and keyAgreement for ECDH key establishment.
   *
   * @throws ISOException with {@link ISO7816#SW_CONDITIONS_NOT_SATISFIED} for any other role
   */
  private static byte[] keyUsageFor(PIVKeyObjectPKI target) {
    if (target.hasRole(PIVKeyObject.ROLE_SIGN)) return DER_KEY_USAGE_DIGITAL_SIGNATURE;
    if (target.hasRole(PIVKeyObject.ROLE_KEY_ESTABLISH)) {
      return target instanceof PIVKeyObjectRSA
          ? DER_KEY_USAGE_KEY_ENCIPHERMENT
          : DER_KEY_USAGE_KEY_AGREEMENT;
    }
    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    return null;
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
   * the issuing CA. {@link DERWriter#writePositiveInteger} produces the minimal DER encoding.
   *
   * @param writer certificate writer
   * @param scratch temporary random-number buffer
   */
  private static void writeRandomSerial(DERWriter writer, byte[] scratch) {
    PIVCrypto.doGenerateRandom(scratch, SERIAL_OFFSET, SERIAL_RANDOM_LENGTH);
    scratch[SERIAL_OFFSET] &= (byte) 0x7F;
    short last = (short) (SERIAL_OFFSET + SERIAL_RANDOM_LENGTH - 1);
    short cursor = SERIAL_OFFSET;
    while (cursor < last && scratch[cursor] == (byte) 0x00) cursor++;
    if (scratch[cursor] == (byte) 0x00) scratch[last] = (byte) 0x01;
    writer.writePositiveInteger(scratch, SERIAL_OFFSET, SERIAL_RANDOM_LENGTH);
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
   * Writes the attestation-certificate extensions.
   *
   * <p>In order: non-critical basicConstraints {@code cA FALSE} (RFC 5280, Section 4.2.1.9);
   * critical keyUsage selected by {@link #keyUsageFor} (Section 4.2.1.3: &quot;conforming CAs
   * SHOULD mark this extension as critical&quot;); non-critical authorityKeyIdentifier carrying the
   * F9 subject key identifier (Section 4.2.1.1); and the non-critical OpenPhysical attestation
   * extension {@code 1.3.6.1.4.1.57923.20.10.20.1}:
   *
   * <pre>
   * SEQUENCE { version INTEGER (1), appletVersion OCTET STRING (4), buildFlags OCTET STRING (1),
   *   vciSuite OCTET STRING (1), platformId OCTET STRING, keyReference OCTET STRING (1),
   *   mechanism OCTET STRING (1), role OCTET STRING (1), attributes OCTET STRING (1),
   *   origin ENUMERATED (2 = generated), contactMode OCTET STRING (1),
   *   contactlessMode OCTET STRING (1) }
   * </pre>
   *
   * <p>buildFlags bit 0 is the FIPS profile and bit 1 is attestation support.
   *
   * @param writer certificate writer
   * @param target attested key
   * @param slot attested key reference
   * @param keyUsage DER keyUsage BIT STRING
   */
  private void writeExtensions(
      DERWriter writer, PIVKeyObjectPKI target, byte slot, byte[] keyUsage) {
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
    writer.write(DER_CRITICAL, (short) 0x00, (short) DER_CRITICAL.length);
    writer.writeTlv((byte) 0x04, keyUsage, (short) 0x00, (short) keyUsage.length);
    writer.end();

    writer.begin((byte) 0x30);
    writer.writeTlv(
        (byte) 0x06,
        OID_AUTHORITY_KEY_IDENTIFIER,
        (short) 0x00,
        (short) OID_AUTHORITY_KEY_IDENTIFIER.length);
    writer.begin((byte) 0x04);
    writer.begin((byte) 0x30);
    writer.writeTlv((byte) 0x80, authorityCertificate, keyIdOffset, LENGTH_KEY_IDENTIFIER);
    writer.end();
    writer.end();
    writer.end();

    writer.begin((byte) 0x30);
    writer.writeTlv(
        (byte) 0x06,
        OID_OPENPHYSICAL_ATTESTATION,
        (short) 0x00,
        (short) OID_OPENPHYSICAL_ATTESTATION.length);
    writer.begin((byte) 0x04);
    writer.begin((byte) 0x30);
    writer.writeIntegerByte(OPENPHYSICAL_EXTENSION_VERSION);
    writer.write((byte) 0x04);
    writer.write((byte) 0x04);
    writer.write(Config.VERSION_MAJOR);
    writer.write(Config.VERSION_MINOR);
    writer.write(Config.VERSION_REVISION);
    writer.write(Config.VERSION_DEBUG);
    writeOctetByte(
        writer,
        (byte) ((FipsPolicy.ENABLED ? BUILD_FLAG_FIPS : (byte) 0) | BUILD_FLAG_ATTESTATION));
    writeOctetByte(writer, PIV.ID_ALG_ECC_SM);
    writer.writeTlv(
        (byte) 0x04,
        BuildProfile.PLATFORM_ID,
        (short) 0x00,
        (short) BuildProfile.PLATFORM_ID.length);
    writeOctetByte(writer, slot);
    writeOctetByte(writer, target.getMechanism());
    writeOctetByte(writer, target.getRoles());
    writeOctetByte(writer, target.getAttributes());
    writer.write((byte) 0x0A);
    writer.write((byte) 0x01);
    writer.write(PIVKeyObject.ORIGIN_GENERATED);
    writeOctetByte(writer, target.getModeContact());
    writeOctetByte(writer, target.getModeContactless());
    writer.end();
    writer.end();
    writer.end();

    writer.end();
    writer.end();
  }

  /** Writes a one-octet OCTET STRING. */
  private static void writeOctetByte(DERWriter writer, byte value) {
    writer.write((byte) 0x04);
    writer.write((byte) 0x01);
    writer.write(value);
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

  /** Validates one complete DER Name; see {@link DERValidator#validateDerName}. */
  static void validateDerName(byte[] buffer, short offset, short length) {
    DERValidator.validateDerName(buffer, offset, length);
  }

  /** Validates one complete DER Validity; see {@link DERValidator#validateDerValidity}. */
  static void validateDerValidity(byte[] buffer, short offset, short length) {
    DERValidator.validateDerValidity(buffer, offset, length);
  }

  // Leaf certificate profile, mirrored from docs/ATTESTATION.md:
  // - issuer and validity are the stored F9 certificate subject and validity
  // - subject is CN=PIV Attestation <slot>
  // - signatureAlgorithm is ecdsa-with-SHA256 because F9 is fixed to P-256
  // - extensions: BasicConstraints CA=false, critical KeyUsage by role, AKI = F9 SKI, and the
  //   OpenPhysical attestation extension
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
  // AlgorithmIdentifier SEQUENCE { ecdsa-with-SHA256 } with parameters absent.
  private static final byte[] DER_ECDSA_WITH_SHA256_ALGORITHM = {
    (byte) 0x30,
    (byte) 0x0A,
    (byte) 0x06,
    (byte) 0x08,
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
  private static final byte[] OID_SERIAL_NUMBER = {(byte) 0x55, (byte) 0x04, (byte) 0x05};
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
  private static final byte[] OID_SUBJECT_KEY_IDENTIFIER = {(byte) 0x55, (byte) 0x1D, (byte) 0x0E};
  private static final byte[] OID_AUTHORITY_KEY_IDENTIFIER = {
    (byte) 0x55, (byte) 0x1D, (byte) 0x23
  };
  // 1.3.6.1.4.1.57923.20.10.20.1
  private static final byte[] OID_OPENPHYSICAL_ATTESTATION = {
    (byte) 0x2B,
    (byte) 0x06,
    (byte) 0x01,
    (byte) 0x04,
    (byte) 0x01,
    (byte) 0x83,
    (byte) 0xC4,
    (byte) 0x43,
    (byte) 0x14,
    (byte) 0x0A,
    (byte) 0x14,
    (byte) 0x01
  };
  private static final byte OPENPHYSICAL_EXTENSION_VERSION = (byte) 0x01;
  private static final byte BUILD_FLAG_FIPS = (byte) 0x01;
  private static final byte BUILD_FLAG_ATTESTATION = (byte) 0x02;
  private static final byte[] DER_VERSION_V3 = {
    (byte) 0xA0, (byte) 0x03, (byte) 0x02, (byte) 0x01, (byte) 0x02
  };
  private static final byte[] DER_CRITICAL = {(byte) 0x01, (byte) 0x01, (byte) 0xFF};
  private static final byte[] DER_BASIC_CONSTRAINTS_CA_FALSE = {(byte) 0x30, (byte) 0x00};
  private static final byte[] DER_BASIC_CONSTRAINTS_CA_PATHLEN_0 = {
    (byte) 0x30,
    (byte) 0x06,
    (byte) 0x01,
    (byte) 0x01,
    (byte) 0xFF,
    (byte) 0x02,
    (byte) 0x01,
    (byte) 0x00
  };
  private static final byte[] DER_KEY_USAGE_DIGITAL_SIGNATURE = {
    (byte) 0x03, (byte) 0x02, (byte) 0x07, (byte) 0x80
  };
  private static final byte[] DER_KEY_USAGE_KEY_ENCIPHERMENT = {
    (byte) 0x03, (byte) 0x02, (byte) 0x05, (byte) 0x20
  };
  private static final byte[] DER_KEY_USAGE_KEY_AGREEMENT = {
    (byte) 0x03, (byte) 0x02, (byte) 0x03, (byte) 0x08
  };
  private static final byte[] DER_KEY_USAGE_KEY_CERT_SIGN = {
    (byte) 0x03, (byte) 0x02, (byte) 0x02, (byte) 0x04
  };
  private static final byte[] POP_PREFIX = {
    (byte) 'O', (byte) 'P', (byte) 'F', (byte) '9', (byte) 'P', (byte) 'O', (byte) 'P'
  };
  private static final byte[] CONTAINER_TRAILER = {
    (byte) 0x71, (byte) 0x01, (byte) 0x00, (byte) 0xFE, (byte) 0x00
  };

  private static final byte SEEN_BASIC_CONSTRAINTS = (byte) 0x01;
  private static final byte SEEN_KEY_USAGE = (byte) 0x02;
  private static final byte SEEN_SUBJECT_KEY_IDENTIFIER = (byte) 0x04;
  private static final byte SEEN_AUTHORITY_KEY_IDENTIFIER = (byte) 0x08;
  private static final byte SEEN_ALL = (byte) 0x0F;

  private static final short HASH_SHA256_LENGTH = (short) 0x20;
  private static final short CERT_HASH_OFFSET = (short) 0x00;
  private static final short CERT_SIGNATURE_OFFSET =
      (short) (CERT_HASH_OFFSET + HASH_SHA256_LENGTH);
  private static final short SERIAL_OFFSET = (short) 0x00;
  private static final short SERIAL_RANDOM_LENGTH = (short) 0x10;
}
// #endif
