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
  // Clear any key material from this object
  static final byte ELEMENT_KEY_CLEAR = (byte) 0xFF;
  private SecretKey key;

  PIVKeyObjectSYM(
      byte id,
      byte modeContact,
      byte modeContactless,
      byte adminKey,
      byte mechanism,
      byte role,
      byte attributes)
      throws ISOException {
    super(id, modeContact, modeContactless, adminKey, mechanism, role, attributes);
  }

  @Override
  void updateElement(byte element, byte[] buffer, short offset, short length) throws ISOException {
    short keyLengthBytes = getKeyLengthBytes();
    if (length != keyLengthBytes) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    try {
      switch (element) {
        case ELEMENT_KEY:
          SecretKey replacement = allocateKey();
          try {
            if (replacement.getType() == KeyBuilder.TYPE_DES) {
              ((DESKey) replacement).setKey(buffer, offset);
            } else if (replacement.getType() == KeyBuilder.TYPE_AES) {
              ((AESKey) replacement).setKey(buffer, offset);
            } else {
              ISOException.throwIt(ISO7816.SW_DATA_INVALID);
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
          runGc();
          break;

          // Clear Key
        case ELEMENT_KEY_CLEAR:
          clear();
          break;

        default:
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
          break;
      }
    } finally {
      PIVSecurityProvider.zeroise(buffer, offset, keyLengthBytes);
    }
  }

  private SecretKey allocateKey() throws ISOException {
    switch (header[HEADER_MECHANISM]) {
      case PIV.ID_ALG_DEFAULT:
      case PIV.ID_ALG_TDEA_3KEY:
        // If the TDEA cipher is null, the card does not support this key type!
        return
            (SecretKey)
                KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_3KEY, false);

      case PIV.ID_ALG_AES_128:
        return
            (SecretKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

      case PIV.ID_ALG_AES_192:
        return
            (SecretKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_192, false);

      case PIV.ID_ALG_AES_256:
        return
            (SecretKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);

      default:
        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        return null;
    }
  }

  @Override
  void clear() {
    if (key != null) {
      key.clearKey();
      key = null;
      runGc();
    }
  }

  boolean isInitialised() {
    return (key != null && key.isInitialized());
  }

  @Override
  short getBlockLength() throws ISOException {
    switch (getMechanism()) {
      case PIV.ID_ALG_DEFAULT:
      case PIV.ID_ALG_TDEA_3KEY:
        return (short) 8;

      case PIV.ID_ALG_AES_128:
      case PIV.ID_ALG_AES_192:
      case PIV.ID_ALG_AES_256:
        return (short) 16;

      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
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
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        return (short) 0; // Keep compiler happy
    }
  }

  short encrypt(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset)
      throws ISOException {

    // PRE-CONDITION 1 - The length must be equal to the block length
    if (inLength != getBlockLength()) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    return PIVCrypto.doEncrypt(key, inBuffer, inOffset, inLength, outBuffer, outOffset);
  }
}
