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
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

/** Provides functionality for ECC PIV key objects */
final class PIVKeyObjectECC extends PIVKeyObjectPKI {
  private static final byte CONST_POINT_UNCOMPRESSED = (byte) 0x04;

  // The ECC public key element tag
  private static final byte ELEMENT_ECC_POINT = (byte) 0x86;

  // The ECC private key element tag
  private static final byte ELEMENT_ECC_SECRET = (byte) 0x87;

  // The PIV secure messaging CVC element tag (OpenFIPS201 ASN.1 smCVC [10]).
  static final byte ELEMENT_SM_CVC = (byte) 0x8A;

  //#if VCI_CS2
  private static final short LENGTH_SM_CVC_MAX = (short) 256;
  //#else
  // CS7 (P-384) production CVCs are ~275 bytes; allow headroom for encoding variance.
  private static final short LENGTH_SM_CVC_MAX = (short) 384;
  //#endif

  private ECPrivateKey privateKey = null;
  private ECPublicKey publicKey = null;
  private KeyPair keyPair = null;
  private byte[] smCvc = null;
  private short smCvcLength = (short) 0;

  // TODO: Refactor to remove the need for a permanent ECParams object
  private final ECParams params;
  private final short marshaledPubKeyLen;

  PIVKeyObjectECC(
      byte id,
      byte modeContact,
      byte modeContactless,
      byte adminKey,
      byte mechanism,
      byte role,
      byte attributes)
      throws ISOException {
    super(id, modeContact, modeContactless, adminKey, mechanism, role, attributes);

    switch (getMechanism()) {
      case PIV.ID_ALG_ECC_P256:
      case PIV.ID_ALG_ECC_CS2:
        params = ECParamsP256.getInstance();
        break;
      case PIV.ID_ALG_ECC_P384:
      case PIV.ID_ALG_ECC_CS7:
        params = ECParamsP384.getInstance();
        break;
      default:
        params = null; // Keep the compiler happy
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    // Uncompressed ECC public keys are marshaled as the concatenation of:
    // CONST_POINT_UNCOMPRESSED | X | Y
    // where the length of the X and Y coordinates is the byte length of the key.
    // TODO: We can use 2 consts and decide which to compare against based on the mechanism!
    marshaledPubKeyLen = (short) (getKeyLengthBytes() * 2 + 1);
    allocatePrivate();
    allocatePublic();
    if (isSecureMessagingMechanism()) {
      smCvc = new byte[LENGTH_SM_CVC_MAX];
    }
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
        if (buffer[offset] != CONST_POINT_UNCOMPRESSED) {
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
        javacard.framework.Util.arrayCopyNonAtomic(buffer, offset, smCvc, (short) 0, length);
        smCvcLength = length;
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

  /** Clears and reallocates a private key. */
  private void allocatePrivate() {
    if (privateKey == null) {
      privateKey =
          (ECPrivateKey)
              KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, getKeyLengthBits(), false);
      setPrivateParams();
      allocateKeyPair();
    }
  }

  /** Clears and if necessary reallocates a public key. */
  private void allocatePublic() {
    if (publicKey == null) {
      publicKey =
          (ECPublicKey)
              KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, getKeyLengthBits(), false);
      setPublicParams();
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
      // clear both the public and private keys if they exist
      clear();
      CardRuntimeException.throwIt(cre.getReason());
    }

    return length;
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
  short getKeyLengthBits() throws ISOException {
    switch (getMechanism()) {
      case PIV.ID_ALG_ECC_P256:
      case PIV.ID_ALG_ECC_CS2:
        return KeyBuilder.LENGTH_EC_FP_256;

      case PIV.ID_ALG_ECC_P384:
      case PIV.ID_ALG_ECC_CS7:
        return KeyBuilder.LENGTH_EC_FP_384;

      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        return (short) 0; // Keep compiler happy
    }
  }

  /**
   * @return true if the privateKey exists and is initialized.
   */
  @Override
  boolean isInitialised() {

    switch (getMechanism()) {
      case PIV.ID_ALG_ECC_P256:
      case PIV.ID_ALG_ECC_P384:
        return (privateKey != null && privateKey.isInitialized());

      case PIV.ID_ALG_ECC_CS2:
      case PIV.ID_ALG_ECC_CS7:
        return (privateKey != null && privateKey.isInitialized() && smCvcLength > (short) 0);

      default:
        return false; // Satisfy the compiler
    }
  }

  @Override
  void clear() {
    publicKey.clearKey();
    privateKey.clearKey();
    setPublicParams();
    setPrivateParams();
    if (smCvc != null) {
      PIVSecurityProvider.zeroise(smCvc, (short) 0, (short) smCvc.length);
    }
    smCvcLength = (short) 0;
    clearOrigin();
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

  boolean validatePublicPoint(byte[] buffer, short offset, short length, byte[] work, short workOffset) {
    short fieldLength = getKeyLengthBytes();
    if (length != (short) (1 + fieldLength + fieldLength)
        || buffer[offset] != CONST_POINT_UNCOMPRESSED) {
      return false;
    }

    byte[] p = params.getP();
    byte[] b = params.getB();
    short xOff = workOffset;
    short yOff = (short) (xOff + fieldLength);
    short lhsOff = (short) (yOff + fieldLength);
    short rhsOff = (short) (lhsOff + fieldLength);
    short tmpOff = (short) (rhsOff + fieldLength);

    javacard.framework.Util.arrayCopyNonAtomic(
        buffer, (short) (offset + 1), work, xOff, fieldLength);
    javacard.framework.Util.arrayCopyNonAtomic(
        buffer, (short) (offset + 1 + fieldLength), work, yOff, fieldLength);

    if (compareUnsigned(work, xOff, p, (short) 0, fieldLength) >= (byte) 0
        || compareUnsigned(work, yOff, p, (short) 0, fieldLength) >= (byte) 0) {
      return false;
    }

    // SP 800-73-5 Part 2 step C4 requires partial validation of Q_eH before ECDH.
    // For P-256/P-384 (cofactor 1), check that y^2 == x^3 - 3x + b over Fp.
    modMultiply(work, lhsOff, work, yOff, work, yOff, p, fieldLength, tmpOff);
    modMultiply(work, rhsOff, work, xOff, work, xOff, p, fieldLength, tmpOff);
    modMultiply(work, rhsOff, work, rhsOff, work, xOff, p, fieldLength, tmpOff);
    modDouble(work, tmpOff, work, xOff, p, fieldLength);
    modAdd(work, tmpOff, work, tmpOff, work, xOff, p, fieldLength);
    modSubtract(work, rhsOff, work, rhsOff, work, tmpOff, p, fieldLength);
    modAdd(work, rhsOff, work, rhsOff, b, (short) 0, p, fieldLength);

    return compareUnsigned(work, lhsOff, work, rhsOff, fieldLength) == (byte) 0;
  }

  private static void modMultiply(
      byte[] out,
      short outOff,
      byte[] left,
      short leftOff,
      byte[] right,
      short rightOff,
      byte[] p,
      short length,
      short tmpOff) {
    javacard.framework.Util.arrayCopyNonAtomic(left, leftOff, out, tmpOff, length);
    javacard.framework.Util.arrayFillNonAtomic(out, outOff, length, (byte) 0);

    for (short i = (short) (length - 1); i >= (short) 0; i--) {
      byte value = right[(short) (rightOff + i)];
      for (byte mask = (byte) 1; mask != (byte) 0; mask = (byte) (mask << 1)) {
        if ((value & mask) != (byte) 0) {
          modAdd(out, outOff, out, outOff, out, tmpOff, p, length);
        }
        modDouble(out, tmpOff, out, tmpOff, p, length);
      }
    }
  }

  private static void modDouble(
      byte[] out, short outOff, byte[] value, short valueOff, byte[] p, short length) {
    short carry = (short) 0;
    for (short i = (short) (length - 1); i >= (short) 0; i--) {
      short sum = (short) (((value[(short) (valueOff + i)] & 0xFF) << 1) + carry);
      out[(short) (outOff + i)] = (byte) sum;
      carry = (short) ((sum >> 8) & 0x01);
    }
    if (carry != (short) 0 || compareUnsigned(out, outOff, p, (short) 0, length) >= (byte) 0) {
      subtractInPlace(out, outOff, p, (short) 0, length);
    }
  }

  private static void modAdd(
      byte[] out,
      short outOff,
      byte[] left,
      short leftOff,
      byte[] right,
      short rightOff,
      byte[] p,
      short length) {
    short carry = (short) 0;
    for (short i = (short) (length - 1); i >= (short) 0; i--) {
      short sum =
          (short)
              ((left[(short) (leftOff + i)] & 0xFF)
                  + (right[(short) (rightOff + i)] & 0xFF)
                  + carry);
      out[(short) (outOff + i)] = (byte) sum;
      carry = (short) ((sum >> 8) & 0x01);
    }
    if (carry != (short) 0 || compareUnsigned(out, outOff, p, (short) 0, length) >= (byte) 0) {
      subtractInPlace(out, outOff, p, (short) 0, length);
    }
  }

  private static void modSubtract(
      byte[] out,
      short outOff,
      byte[] left,
      short leftOff,
      byte[] right,
      short rightOff,
      byte[] p,
      short length) {
    short borrow = subtract(out, outOff, left, leftOff, right, rightOff, length);
    if (borrow != (short) 0) {
      short carry = (short) 0;
      for (short i = (short) (length - 1); i >= (short) 0; i--) {
        short sum = (short) ((out[(short) (outOff + i)] & 0xFF) + (p[i] & 0xFF) + carry);
        out[(short) (outOff + i)] = (byte) sum;
        carry = (short) ((sum >> 8) & 0x01);
      }
    }
  }

  private static void subtractInPlace(
      byte[] left, short leftOff, byte[] right, short rightOff, short length) {
    subtract(left, leftOff, left, leftOff, right, rightOff, length);
  }

  private static short subtract(
      byte[] out,
      short outOff,
      byte[] left,
      short leftOff,
      byte[] right,
      short rightOff,
      short length) {
    short borrow = (short) 0;
    for (short i = (short) (length - 1); i >= (short) 0; i--) {
      short diff =
          (short)
              ((left[(short) (leftOff + i)] & 0xFF)
                  - (right[(short) (rightOff + i)] & 0xFF)
                  - borrow);
      out[(short) (outOff + i)] = (byte) diff;
      borrow = diff < (short) 0 ? (short) 1 : (short) 0;
    }
    return borrow;
  }

  private static byte compareUnsigned(
      byte[] left, short leftOff, byte[] right, short rightOff, short length) {
    for (short i = (short) 0; i < length; i++) {
      short a = (short) (left[(short) (leftOff + i)] & 0xFF);
      short b = (short) (right[(short) (rightOff + i)] & 0xFF);
      if (a < b) return (byte) -1;
      if (a > b) return (byte) 1;
    }
    return (byte) 0;
  }

  private boolean isSecureMessagingMechanism() {
    return getMechanism() == PIV.ID_ALG_ECC_CS2 || getMechanism() == PIV.ID_ALG_ECC_CS7;
  }

  /** Set ECC domain parameters. */
  private void setPrivateParams() {

    byte[] a = params.getA();
    byte[] b = params.getB();
    byte[] g = params.getG();
    byte[] p = params.getP();
    byte[] r = params.getN();

    privateKey.setA(a, (short) 0, (short) a.length);
    privateKey.setB(b, (short) 0, (short) b.length);
    privateKey.setG(g, (short) 0, (short) g.length);
    privateKey.setR(r, (short) 0, (short) r.length);
    privateKey.setFieldFP(p, (short) 0, (short) p.length);
    privateKey.setK(params.getH());
  }

  /** Set ECC domain parameters. */
  private void setPublicParams() {
    byte[] a = params.getA();
    byte[] b = params.getB();
    byte[] g = params.getG();
    byte[] p = params.getP();
    byte[] r = params.getN();

    publicKey.setA(a, (short) 0, (short) a.length);
    publicKey.setB(b, (short) 0, (short) b.length);
    publicKey.setG(g, (short) 0, (short) g.length);
    publicKey.setR(r, (short) 0, (short) r.length);
    publicKey.setFieldFP(p, (short) 0, (short) p.length);
    publicKey.setK(params.getH());
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
        privateKey, inBuffer, inOffset, inLength, outBuffer, outOffset, validator);
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
