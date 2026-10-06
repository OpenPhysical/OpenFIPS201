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

abstract class PIVKeyObjectPKI extends PIVKeyObject {

  protected static final short CONST_TAG_RESPONSE = (short) 0x7F49;
  private byte importedParts;
  private byte importedPairReady;

  protected PIVKeyObjectPKI(
      byte id,
      byte modeContact,
      byte modeContactless,
      byte adminKey,
      byte mechanism,
      byte role,
      byte attributes,
      PIVCrypto crypto) {
    super(id, modeContact, modeContactless, adminKey, mechanism, role, attributes, crypto);
  }

  /**
   * Rejects a role and attribute combination that no asymmetric key definition supports: any of the
   * symmetric challenge-response attributes, or both the signing and key-establishment roles.
   *
   * @throws ISOException {@link ISO7816#SW_WRONG_DATA} if the combination is not supported
   */
  static void validateRoleAttributes(byte role, byte attributes) {
    byte symmetricAttributes =
        (byte) (ATTR_PERMIT_INTERNAL | ATTR_PERMIT_EXTERNAL | ATTR_PERMIT_MUTUAL);
    if ((attributes & symmetricAttributes) != (byte) 0
        || (role & (ROLE_SIGN | ROLE_KEY_ESTABLISH)) == (byte) (ROLE_SIGN | ROLE_KEY_ESTABLISH)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
  }

  /**
   * Signs the passed precomputed hash
   *
   * @param inBuffer contains the precomputed hash
   * @param inOffset the location of the first byte of the hash
   * @param inLength the length og the computed hash
   * @param outBuffer the buffer to contain the signature
   * @param outOffset the location of the first byte of the signature
   * @return the length of the signature
   */
  abstract short sign(
      byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset);

  /**
   * Performs a key agreement
   *
   * @param inBuffer the input to the key agreement operation
   * @param inOffset the the location of first byte of the key agreement input
   * @param inLength the length of the key agreement input
   * @param outBuffer the key agreement output
   * @param outOffset the location of the first byte of the key agreement output
   * @return the length of the key agreement output
   */
  abstract short keyAgreement(
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset,
      ECPointValidator validator);

  /**
   * Generates a new asymmetric key pair and returns the public component.
   *
   * @param writer the TLV writer that encodes the public component template
   * @param outBuffer the output buffer to hold the generated public component
   * @param outOffset the starting position of the output buffer
   * @return The length of the generated key
   */
  abstract short generate(TLVWriter writer, byte[] outBuffer, short outOffset);

  /** Verifies that the public and private components form a usable pair. */
  abstract boolean pairwiseConsistencyTest(byte[] scratch, short offset);

  final boolean isImportedKeyMaterial(byte element) {
    return importPartForElement(element) != (byte) 0;
  }

  /**
   * Returns true when recording this element would complete a fresh imported key pair, without
   * changing the import state.
   */
  final boolean isLastImportedPart(byte element) {
    byte importedPart = importPartForElement(element);
    if (importedPart == (byte) 0) return false;
    return (byte) ((importedParts | importedPart) & requiredImportParts()) == requiredImportParts();
  }

  /** Returns true exactly when this element completes a fresh imported key pair. */
  final boolean completesImportedKeyPair(byte element) {
    byte importedPart = importPartForElement(element);
    if (importedPart == (byte) 0) return false;

    importedParts |= importedPart;
    if ((importedParts & requiredImportParts()) != requiredImportParts()) return false;
    importedParts = (byte) 0;
    return true;
  }

  final boolean hasPendingImportedParts() {
    return importedParts != (byte) 0;
  }

  final void resetImportedParts() {
    importedParts = (byte) 0;
  }

  final void markImportedPairReady() {
    importedPairReady = (byte) 1;
  }

  final void resetImportedPairReady() {
    importedPairReady = (byte) 0;
  }

  abstract byte importPartForElement(byte element);

  abstract byte requiredImportParts();

  /** Returns whether complete, consistency-tested key material is ready for use. */
  final boolean isInitialised() {
    return hasPrivateMaterial() && (isGenerated() || importedPairReady != (byte) 0);
  }

  abstract boolean hasPrivateMaterial();

  /**
   * Writes the public key as an X.509 SubjectPublicKeyInfo structure.
   *
   * @param writer a DER writer not in use by the caller, whose state this method replaces
   * @param outBuffer the output buffer
   * @param outOffset the starting output offset
   * @return length of the DER SubjectPublicKeyInfo
   */
  abstract short writeSubjectPublicKeyInfo(DERWriter writer, byte[] outBuffer, short outOffset);
}
