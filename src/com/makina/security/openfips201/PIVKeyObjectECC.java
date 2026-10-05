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

import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

/** Provides functionality for ECC PIV key objects */
final class PIVKeyObjectECC extends PIVKeyObjectPKI {
  // The ECC public key element tag
  static final byte ELEMENT_ECC_POINT = (byte) 0x86;

  // The ECC private key element tag
  static final byte ELEMENT_ECC_SECRET = (byte) 0x87;

  // The PIV secure messaging CVC element tag (OpenFIPS201 ASN.1 smCVC [10]).
  static final byte ELEMENT_SM_CVC = (byte) 0x8A;

  // #if VCI_CS2
  private static final short LENGTH_SM_CVC_MAX = (short) 256;
  // #else
  // CS7 (P-384) production CVCs are ~275 bytes; allow headroom for encoding variance.
  private static final short LENGTH_SM_CVC_MAX = (short) 384;
  // #endif

  private ECPrivateKey privateKey = null;
  private ECPublicKey publicKey = null;
  private KeyPair keyPair = null;
  // The published CVC and an equal-sized staging buffer. Util.arrayCopyNonAtomic "does not use
  // the transaction facility during the copy operation even if a transaction is in progress" (JC
  // 3.0.5 API), so a replacement is copied into the staging buffer and published by a
  // transactional swap of the references and length.
  private byte[] smCvc = null;
  private byte[] smCvcStaging = null;
  private short smCvcLength = (short) 0;

  private final ECParams params;
  private final short marshaledPubKeyLen;

  private PIVKeyObjectECC(
      byte id,
      byte modeContact,
      byte modeContactless,
      byte adminKey,
      byte mechanism,
      byte role,
      byte attributes,
      ECParams params)
      throws ISOException {
    super(id, modeContact, modeContactless, adminKey, mechanism, role, attributes);
    this.params = params;
    if (params == null) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    // Uncompressed ECC public keys are marshaled as 04 || X || Y, where each coordinate is the
    // byte length of the key.
    marshaledPubKeyLen = ECPointValidator.encodedLength(getKeyLengthBytes());
    allocatePrivate();
    allocatePublic();
    if (isSecureMessagingMechanism()) {
      smCvc = new byte[LENGTH_SM_CVC_MAX];
      smCvcStaging = new byte[LENGTH_SM_CVC_MAX];
    }
  }

  static PIVKeyObjectECC create(
      byte id,
      byte modeContact,
      byte modeContactless,
      byte adminKey,
      byte mechanism,
      byte role,
      byte attributes,
      ECCurveRegistry curves) {
    validateRoleAttributes(role, attributes);
    return new PIVKeyObjectECC(
        id,
        modeContact,
        modeContactless,
        adminKey,
        mechanism,
        role,
        attributes,
        curves.forMechanism(mechanism));
  }

  /**
   * Updates the elements of the keypair with new values.
   *
   * <p>Notes:
   *
   * <ul>
   *   <li>If the card does not support ObjectDeletion, repeatedly calling this method may exhaust
   *       NV RAM.
   *   <li>The ELEMENT_ECC_POINT element must be formatted as an octet string as per ANSI X9.62.
   *   <li>The ELEMENT_ECC_SECRET must be formatted as a big-endian, right-aligned big number.
   *   <li>Updating only one element may render the card in a non-deterministic state
   * </ul>
   *
   * @param element the element to update
   * @param buffer containing the updated element
   * @param offset first byte of the element in the buffer
   * @param length the length of the element
   */
  @Override
  void updateElement(byte element, byte[] buffer, short offset, short length) throws ISOException {

    switch (element) {
      case ELEMENT_ECC_POINT:
        if (length != marshaledPubKeyLen) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
          return; // Keep static analyser happy
        }

        // Only uncompressed points are supported
        if (buffer[offset] != ECPointValidator.POINT_UNCOMPRESSED) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
          return; // Keep static analyser happy
        }

        allocatePublic();

        publicKey.setW(buffer, offset, length);
        break;

      case ELEMENT_ECC_SECRET:
        if (length != getKeyLengthBytes()) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
          return; // Keep static analyser happy
        }

        allocatePrivate();

        privateKey.setS(buffer, offset, length);
        break;

      case ELEMENT_SM_CVC:
        if (!isSecureMessagingMechanism()) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
          return;
        }
        if (length <= (short) 0 || length > LENGTH_SM_CVC_MAX) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
          return;
        }
        publishSmCvc(buffer, offset, length);
        break;

        // Clear all key parts
      case ELEMENT_CLEAR:
        clear();
        break;

      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        break;
    }
  }

  /**
   * Replaces the secure-messaging CVC so that a power loss leaves either the complete previous or
   * the complete new certificate published.
   *
   * <p>The bytes go non-atomically into the unpublished staging buffer; the reference and length
   * swap is then a persistent update inside the caller's transaction, or inside a transaction
   * started here when none is in progress.
   */
  private void publishSmCvc(byte[] buffer, short offset, short length) {
    byte[] staged = smCvcStaging;
    Util.arrayCopyNonAtomic(buffer, offset, staged, (short) 0, length);
    boolean ownTransaction = JCSystem.getTransactionDepth() == (byte) 0;
    if (ownTransaction) JCSystem.beginTransaction();
    smCvcStaging = smCvc;
    smCvc = staged;
    smCvcLength = length;
    if (ownTransaction) JCSystem.commitTransaction();
  }

  /** Clears and reallocates a private key. */
  private void allocatePrivate() {
    if (privateKey == null) {
      privateKey =
          (ECPrivateKey)
              KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, getKeyLengthBits(), false);
      setDomainParams(privateKey);
      allocateKeyPair();
    }
  }

  /** Clears and if necessary reallocates a public key. */
  private void allocatePublic() {
    if (publicKey == null) {
      publicKey =
          (ECPublicKey)
              KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, getKeyLengthBits(), false);
      setDomainParams(publicKey);
      allocateKeyPair();
    }
  }

  private void allocateKeyPair() {
    if (keyPair == null && publicKey != null && privateKey != null) {
      keyPair = new KeyPair(publicKey, privateKey);
    }
  }

  @Override
  short generate(byte[] scratch, short offset) throws CardRuntimeException {

    short length = 0;
    try {
      // Clear any key material
      clear();

      // Allocate both parts (this only occurs if it hasn't already been allocated)
      allocatePrivate();
      allocatePublic();

      keyPair.genKeyPair();

      // The attestation authority runs the pairwise consistency test in every profile: its public
      // key is certified by the issuer, so a generated pair must be proven consistent first.
      if ((FipsPolicy.ENABLED || getId() == PIV.ID_KEY_ATTESTATION)
          && !pairwiseConsistencyTest(scratch, offset)) {
        ISOException.throwIt(ISO7816.SW_FILE_INVALID);
      }

      TLVWriter writer = TLVWriter.getInstance();

      // We know that the worst-case of this will fit into a short-form length.
      writer.init(scratch, offset, TLV.LENGTH_1BYTE_MAX, CONST_TAG_RESPONSE);
      writer.writeTag(ELEMENT_ECC_POINT);
      writer.writeLength(marshaledPubKeyLen);
      offset = writer.getOffset();
      offset += (publicKey).getW(scratch, offset);

      writer.setOffset(offset);
      length = writer.finish();
    } catch (CardRuntimeException cre) {
      // At this point we are in a nondeterministic state so we will
      // clear both the public and private keys if they exist. The original exception is rethrown
      // so an ISOException (such as the 6A84 consistency failure) keeps its status word: JCRE
      // 3.0.5 Section 3.3 returns ISO7816.SW_UNKNOWN for "any other exception".
      clear();
      throw cre;
    }

    return length;
  }

  @Override
  boolean pairwiseConsistencyTest(byte[] scratch, short offset) {
    if ((getRoles() & ROLE_KEY_ESTABLISH) != (byte) 0) {
      return PIVCrypto.pairwiseAgreementTest(privateKey, publicKey, params, scratch, offset);
    }
    short hashLength = getKeyLengthBytes();
    javacard.framework.Util.arrayFillNonAtomic(scratch, offset, hashLength, (byte) 0x5A);
    short signatureOffset = (short) (offset + hashLength);
    short signatureLength =
        PIVCrypto.doSign(privateKey, scratch, offset, hashLength, scratch, signatureOffset);
    return PIVCrypto.doVerify(
        publicKey, scratch, offset, hashLength, scratch, signatureOffset, signatureLength);
  }

  /**
   * ECC Keys don't have a block length but we conform to SP 800-73-4 Part 2 Para 4.1.4 and return
   * the key length
   *
   * @return the block length equal to the key length
   */
  @Override
  short getBlockLength() {
    return getKeyLengthBytes();
  }

  /**
   * The length, in bytes, of the key
   *
   * @return the length of the key
   */
  @Override
  short getKeyLengthBits() {
    // The curve is selected by ECCurveRegistry.forMechanism, the single mechanism-to-curve
    // mapping. A P-256 or P-384 field prime is 32 or 48 octets (KeyBuilder.LENGTH_EC_FP_256/384).
    return (short) (params.getP().length * 8);
  }

  /**
   * @return true if the privateKey exists and is initialized and, for a secure messaging key, its
   *     CVC is loaded.
   */
  @Override
  boolean hasPrivateMaterial() {
    return privateKey != null
        && privateKey.isInitialized()
        && (!isSecureMessagingMechanism() || smCvcLength > (short) 0);
  }

  @Override
  void clear() {
    // Unpublish before wiping: the origin, ready flag and CVC length are each a single atomic
    // persistent write, so a power loss during the non-atomic wipe below leaves an unusable key
    // rather than a published key or CVC with partly erased content.
    smCvcLength = (short) 0;
    clearOrigin();
    resetImportedPairReady();
    resetImportedParts();
    publicKey.clearKey();
    privateKey.clearKey();
    setDomainParams(publicKey);
    setDomainParams(privateKey);
    if (smCvc != null) {
      PIVSecurityProvider.zeroise(smCvc, (short) 0, (short) smCvc.length);
      PIVSecurityProvider.zeroise(smCvcStaging, (short) 0, (short) smCvcStaging.length);
    }
  }

  @Override
  byte importPartForElement(byte element) {
    if (element == ELEMENT_ECC_POINT) return (byte) 1;
    if (element == ELEMENT_ECC_SECRET) return (byte) 2;
    return (byte) 0;
  }

  @Override
  byte requiredImportParts() {
    return (byte) 3;
  }

  short getSmCvc(byte[] buffer, short offset) throws ISOException {
    if (smCvcLength <= (short) 0) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      return (short) 0;
    }
    return javacard.framework.Util.arrayCopyNonAtomic(
        smCvc, (short) 0, buffer, offset, smCvcLength);
  }

  short getSmCvcLength() {
    return smCvcLength;
  }

  private boolean isSecureMessagingMechanism() {
    return getMechanism() == PIV.ID_ALG_ECC_CS2 || getMechanism() == PIV.ID_ALG_ECC_CS7;
  }

  /** Sets this key's ECC domain parameters on {@code key}. */
  private void setDomainParams(ECKey key) {
    byte[] a = params.getA();
    byte[] b = params.getB();
    byte[] g = params.getG();
    byte[] p = params.getP();
    byte[] r = params.getN();

    key.setA(a, (short) 0, (short) a.length);
    key.setB(b, (short) 0, (short) b.length);
    key.setG(g, (short) 0, (short) g.length);
    key.setR(r, (short) 0, (short) r.length);
    key.setFieldFP(p, (short) 0, (short) p.length);
    key.setK(params.getH());
  }

  /**
   * Performs an ECDH key agreement
   *
   * @param inBuffer the public key of the other party
   * @param inOffset the the location of first byte of the public key
   * @param inLength the length of the public key
   * @param outBuffer the computed secret
   * @param outOffset the location of the first byte of the computed secret
   * @return the length of the computed secret
   */
  @Override
  short keyAgreement(
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset,
      ECPointValidator validator)
      throws ISOException {
    return PIVCrypto.doKeyAgreement(
        privateKey, inBuffer, inOffset, inLength, outBuffer, outOffset, validator, params);
  }

  /**
   * Signs the passed precomputed hash
   *
   * @param inBuffer contains the precomputed hash
   * @param inOffset the location of the first byte of the hash
   * @param inLength the length of the computed hash
   * @param outBuffer the buffer to contain the signature
   * @param outOffset the location of the first byte of the signature
   * @return the length of the signature
   */
  @Override
  short sign(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset)
      throws ISOException {
    return PIVCrypto.doSign(privateKey, inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  boolean verify(
      byte[] hash,
      short hashOffset,
      short hashLength,
      byte[] signature,
      short signatureOffset,
      short signatureLength)
      throws ISOException {
    return PIVCrypto.doVerify(
        publicKey, hash, hashOffset, hashLength, signature, signatureOffset, signatureLength);
  }

  // #if ATTESTATION_ENABLED
  /**
   * Writes the uncompressed public point {@code 04 || X || Y} (ANSI X9.62).
   *
   * @param outBuffer the output buffer
   * @param outOffset the starting output offset
   * @return the point length (65 octets for P-256)
   * @throws ISOException with {@link ISO7816#SW_CONDITIONS_NOT_SATISFIED} if no public key is set
   */
  short getPublicPoint(byte[] outBuffer, short outOffset) throws ISOException {
    if (publicKey == null || !publicKey.isInitialized()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      return (short) 0x00;
    }
    return publicKey.getW(outBuffer, outOffset);
  }
  // #endif

  @Override
  short writeSubjectPublicKeyInfo(byte[] outBuffer, short outOffset) throws ISOException {
    if (publicKey == null || !publicKey.isInitialized()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      return (short) 0x00;
    }

    DERWriter writer = DERWriter.getNestedInstance();
    writer.init(outBuffer, outOffset);
    writer.begin((byte) 0x30);
    writer.begin((byte) 0x30);
    writer.writeTlv((byte) 0x06, OID_EC_PUBLIC_KEY, (short) 0x00, (short) OID_EC_PUBLIC_KEY.length);
    if (getKeyLengthBits() == KeyBuilder.LENGTH_EC_FP_256) {
      writer.writeTlv((byte) 0x06, OID_PRIME256V1, (short) 0x00, (short) OID_PRIME256V1.length);
    } else {
      writer.writeTlv((byte) 0x06, OID_SECP384R1, (short) 0x00, (short) OID_SECP384R1.length);
    }
    writer.end();
    writer.write((byte) 0x03);
    writer.writeLength((short) (marshaledPubKeyLen + 1));
    writer.write((byte) 0x00);
    short pointOffset = writer.getOffset();
    writer.setOffset((short) (pointOffset + publicKey.getW(outBuffer, pointOffset)));
    writer.end();
    return (short) (writer.getOffset() - outOffset);
  }

  private static final byte[] OID_EC_PUBLIC_KEY = {
    (byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0xCE, (byte) 0x3D, (byte) 0x02, (byte) 0x01
  };
  private static final byte[] OID_PRIME256V1 = {
    (byte) 0x2A,
    (byte) 0x86,
    (byte) 0x48,
    (byte) 0xCE,
    (byte) 0x3D,
    (byte) 0x03,
    (byte) 0x01,
    (byte) 0x07
  };
  private static final byte[] OID_SECP384R1 = {
    (byte) 0x2B, (byte) 0x81, (byte) 0x04, (byte) 0x00, (byte) 0x22
  };
}
