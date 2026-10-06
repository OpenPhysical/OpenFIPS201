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
import javacard.framework.JCSystem;
import javacard.security.AESKey;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.SecretKey;

/** Provides functionality for symmetric PIV key objects */
final class PIVKeyObjectSYM extends PIVKeyObject {

  // The only element that can be updated in a symmetric key
  static final byte ELEMENT_KEY = (byte) 0x80;
  // Clear any key material from this object (same wire tag as the common ELEMENT_CLEAR)
  static final byte ELEMENT_KEY_CLEAR = ELEMENT_CLEAR;
  // Length of one DES key within a 3TDEA key bundle
  private static final short LENGTH_DES_KEY = (short) 8;
  // Two key containers are built when the key object is defined. An update writes the inactive
  // container and publishes it by a transactional swap of the active reference, so a key rotation
  // allocates no persistent memory and a power loss leaves either the previous or the new key
  // active. JC 3.0.5 API JCSystem.isObjectDeletionSupported() "is used to determine if the
  // implementation for the Java Card platform supports the object deletion mechanism", so a
  // container built per update cannot be assumed reclaimable.
  private final SecretKey keyA;
  private final SecretKey keyB;
  // The active container (keyA or keyB), or null when no key value is published.
  private SecretKey key;

  private PIVKeyObjectSYM(
      byte id,
      byte modeContact,
      byte modeContactless,
      byte adminKey,
      byte mechanism,
      byte role,
      byte attributes)
      throws ISOException {
    super(id, modeContact, modeContactless, adminKey, mechanism, role, attributes);
    keyA = allocateKey();
    keyB = allocateKey();
  }

  static PIVKeyObjectSYM create(
      byte id,
      byte modeContact,
      byte modeContactless,
      byte adminKey,
      byte mechanism,
      byte role,
      byte attributes) {
    if ((role & (ROLE_SIGN | ROLE_KEY_ESTABLISH)) != (byte) 0
        || (attributes & ATTR_IMPORTABLE) == (byte) 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    return new PIVKeyObjectSYM(
        id, modeContact, modeContactless, adminKey, mechanism, role, attributes);
  }

  @Override
  void updateElement(byte element, byte[] buffer, short offset, short length) throws ISOException {
    if (element == ELEMENT_KEY_CLEAR) {
      if (length != (short) 0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      clear();
      return;
    }
    short keyLengthBytes = getKeyLengthBytes();
    if (length != keyLengthBytes) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    try {
      switch (element) {
        case ELEMENT_KEY:
          // SP 800-78-5 Section 3.1 Table 1 note 3: "3TDEA is Triple DES using Keying Option 1
          // from [SP800-67], which requires that all three keys be unique (i.e., Key 1 != Key 2,
          // Key 2 != Key 3, and Key 3 != Key 1)." DES ignores the parity bit of each byte.
          if (isTdea() && !hasDistinctTdeaKeys(buffer, offset)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
          }
          SecretKey replacement = (key == keyA) ? keyB : keyA;
          try {
            if (replacement.getType() == KeyBuilder.TYPE_DES) {
              ((DESKey) replacement).setKey(buffer, offset);
            } else if (replacement.getType() == KeyBuilder.TYPE_AES) {
              ((AESKey) replacement).setKey(buffer, offset);
            } else {
              // Internal fault: ISO/IEC 7816-4 Table 6 '6F00' (no precise diagnosis).
              ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }
          } catch (Exception ex) {
            replacement.clearKey();
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
          }

          SecretKey previous = key;
          JCSystem.beginTransaction();
          key = replacement;
          JCSystem.commitTransaction();
          if (previous != null) previous.clearKey();
          break;

        default:
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
          break;
      }
    } finally {
      PIVSecurityProvider.zeroise(buffer, offset, keyLengthBytes);
    }
  }

  private boolean isTdea() {
    return getMechanism() == PIV.ID_ALG_DEFAULT || getMechanism() == PIV.ID_ALG_TDEA_3KEY;
  }

  /**
   * Returns whether the three 8-byte DES keys of a 3TDEA key bundle are pairwise distinct, ignoring
   * the parity bit (bit 0) of every byte.
   */
  private static boolean hasDistinctTdeaKeys(byte[] buffer, short offset) {
    short key2 = (short) (offset + LENGTH_DES_KEY);
    short key3 = (short) (key2 + LENGTH_DES_KEY);
    return !desKeysEqual(buffer, offset, key2)
        && !desKeysEqual(buffer, key2, key3)
        && !desKeysEqual(buffer, key3, offset);
  }

  private static boolean desKeysEqual(byte[] buffer, short first, short second) {
    byte difference = 0;
    for (short i = 0; i < LENGTH_DES_KEY; i++) {
      difference |=
          (byte) ((buffer[(short) (first + i)] ^ buffer[(short) (second + i)]) & (byte) 0xFE);
    }
    return difference == 0;
  }

  private SecretKey allocateKey() throws ISOException {
    switch (header[HEADER_MECHANISM]) {
      case PIV.ID_ALG_DEFAULT:
      case PIV.ID_ALG_TDEA_3KEY:
        // If the TDEA cipher is null, the card does not support this key type!
        return (SecretKey)
            KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_3KEY, false);

      case PIV.ID_ALG_AES_128:
        return (SecretKey)
            KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

      case PIV.ID_ALG_AES_192:
        return (SecretKey)
            KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_192, false);

      case PIV.ID_ALG_AES_256:
        return (SecretKey)
            KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);

      default:
        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        return null;
    }
  }

  @Override
  void clear() {
    // Unpublish before wiping, so an interrupted clear never leaves a partly cleared key active.
    key = null;
    keyA.clearKey();
    keyB.clearKey();
    clearOrigin();
  }

  boolean isInitialised() {
    return (key != null && key.isInitialized());
  }

  @Override
  short getBlockLength() throws ISOException {
    switch (getMechanism()) {
      case PIV.ID_ALG_DEFAULT:
      case PIV.ID_ALG_TDEA_3KEY:
        return PIVCrypto.LENGTH_BLOCK_TDEA;

      case PIV.ID_ALG_AES_128:
      case PIV.ID_ALG_AES_192:
      case PIV.ID_ALG_AES_256:
        return PIVCrypto.LENGTH_BLOCK_AES;

      default:
        // ISO/IEC 7816-4 Table 7 '6A81' (function not supported): not a symmetric mechanism.
        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        return (short) 0; // Keep compiler happy
    }
  }

  @Override
  short getKeyLengthBits() throws ISOException {
    switch (getMechanism()) {
      case PIV.ID_ALG_DEFAULT:
      case PIV.ID_ALG_TDEA_3KEY:
        return KeyBuilder.LENGTH_DES3_3KEY;

      case PIV.ID_ALG_AES_128:
        return KeyBuilder.LENGTH_AES_128;

      case PIV.ID_ALG_AES_192:
        return KeyBuilder.LENGTH_AES_192;

      case PIV.ID_ALG_AES_256:
        return KeyBuilder.LENGTH_AES_256;

      default:
        // ISO/IEC 7816-4 Table 7 '6A81' (function not supported): not a symmetric mechanism.
        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        return (short) 0; // Keep compiler happy
    }
  }

  short encrypt(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset)
      throws ISOException {

    // PRE-CONDITION 1 - The length must be equal to the block length
    if (inLength != getBlockLength()) {
      // ISO/IEC 7816-4 Table 7 '6A80' (incorrect parameters in the command data field).
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    return PIVCrypto.doEncrypt(key, inBuffer, inOffset, inLength, outBuffer, outOffset);
  }
}
