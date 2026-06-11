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
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.SecretKey;

/** Tracks transient PIV secure messaging and VCI session state. */
final class PIVSecureMessaging {
  private static final short OFFSET_SM_ESTABLISHED = (short) 0;
  private static final short OFFSET_PAIRING_VERIFIED = (short) 1;
  private static final short OFFSET_VCI_ESTABLISHED = (short) 2;
  private static final short OFFSET_LAST_CLA = (short) 3;
  private static final short OFFSET_LAST_INS = (short) 4;
  private static final short LENGTH_STATE = (short) 5;
  private static final short LENGTH_KEY = (short) 16;
  private static final short LENGTH_BLOCK = (short) 16;
  private static final short LENGTH_SHORT_MAC = (short) 8;
  static final short MAX_RESPONSE_PLAINTEXT = (short) 191;
  private static final byte CLA_SECURE_MESSAGING = (byte) 0x0C;
  private static final byte CLA_CHAINED_SECURE_MESSAGING = (byte) 0x1C;
  private static final byte INS_GET_RESPONSE = (byte) 0xC0;
  private static final byte TAG_ENCRYPTED_DATA = (byte) 0x87;
  private static final byte TAG_MAC = (byte) 0x8E;
  private static final byte TAG_LE = (byte) 0x97;
  private static final byte TAG_STATUS = (byte) 0x99;
  private static final byte PADDING_INDICATOR = (byte) 0x01;

  private final byte[] state;
  private final byte[] commandMcv;
  private final byte[] responseMcv;
  private final byte[] encCounter;
  private final AESKey skCfrm;
  private final AESKey skMac;
  private final AESKey skEnc;
  private final AESKey skRmac;

  PIVSecureMessaging() {
    state = JCSystem.makeTransientByteArray(LENGTH_STATE, JCSystem.CLEAR_ON_DESELECT);
    commandMcv = JCSystem.makeTransientByteArray(LENGTH_BLOCK, JCSystem.CLEAR_ON_DESELECT);
    responseMcv = JCSystem.makeTransientByteArray(LENGTH_BLOCK, JCSystem.CLEAR_ON_DESELECT);
    encCounter = JCSystem.makeTransientByteArray(LENGTH_BLOCK, JCSystem.CLEAR_ON_DESELECT);
    skCfrm = PIVCrypto.buildTransientAes128Key();
    skMac = PIVCrypto.buildTransientAes128Key();
    skEnc = PIVCrypto.buildTransientAes128Key();
    skRmac = PIVCrypto.buildTransientAes128Key();
  }

  void clear() {
    state[OFFSET_SM_ESTABLISHED] = (byte) 0;
    state[OFFSET_PAIRING_VERIFIED] = (byte) 0;
    state[OFFSET_VCI_ESTABLISHED] = (byte) 0;
    Util.arrayFillNonAtomic(commandMcv, (short) 0, LENGTH_BLOCK, (byte) 0);
    Util.arrayFillNonAtomic(responseMcv, (short) 0, LENGTH_BLOCK, (byte) 0);
    Util.arrayFillNonAtomic(encCounter, (short) 0, LENGTH_BLOCK, (byte) 0);
    state[OFFSET_LAST_CLA] = (byte) 0;
    state[OFFSET_LAST_INS] = (byte) 0;
    skCfrm.clearKey();
    skMac.clearKey();
    skEnc.clearKey();
    skRmac.clearKey();
  }

  boolean isEstablished() {
    return state[OFFSET_SM_ESTABLISHED] != (byte) 0;
  }

  boolean isVciEstablished() {
    return state[OFFSET_VCI_ESTABLISHED] != (byte) 0;
  }

  void markEstablished(boolean pairingRequired) {
    state[OFFSET_SM_ESTABLISHED] = (byte) 1;
    state[OFFSET_PAIRING_VERIFIED] = (byte) 0;
    state[OFFSET_VCI_ESTABLISHED] = pairingRequired ? (byte) 0 : (byte) 1;
    Util.arrayFillNonAtomic(commandMcv, (short) 0, LENGTH_BLOCK, (byte) 0);
    Util.arrayFillNonAtomic(responseMcv, (short) 0, LENGTH_BLOCK, (byte) 0);
    Util.arrayFillNonAtomic(encCounter, (short) 0, LENGTH_BLOCK, (byte) 0);
    encCounter[(short) 15] = (byte) 1;
    state[OFFSET_LAST_CLA] = (byte) 0;
    state[OFFSET_LAST_INS] = (byte) 0;
  }

  void markPairingVerified() {
    state[OFFSET_PAIRING_VERIFIED] = (byte) 1;
    state[OFFSET_VCI_ESTABLISHED] = (byte) 1;
  }

  void setSessionKeys(byte[] buffer, short offset) {
    skCfrm.setKey(buffer, offset);
    offset += LENGTH_KEY;
    skMac.setKey(buffer, offset);
    offset += LENGTH_KEY;
    skEnc.setKey(buffer, offset);
    offset += LENGTH_KEY;
    skRmac.setKey(buffer, offset);
  }

  short computeConfirmationMac(byte[] buffer, short offset, short length, byte[] out, short outOffset) {
    return PIVCrypto.doAesCmac(skCfrm, buffer, offset, length, out, outOffset);
  }

  boolean isSecureMessagingCla(byte cla) {
    return (byte) (cla & (byte) 0x1C) == CLA_SECURE_MESSAGING
        || (byte) (cla & (byte) 0x1C) == CLA_CHAINED_SECURE_MESSAGING;
  }

  short unwrapCommand(byte[] apdu, short offset, short length, byte[] work, short workOffset) {
    if (!isEstablished()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

    short end = (short) (offset + length);
    short cursor = offset;
    short encryptedTlvOffset = (short) -1;
    short encryptedValueOffset = (short) -1;
    short encryptedValueLength = (short) 0;
    short macTlvOffset = (short) -1;
    short macValueOffset = (short) -1;

    while (cursor < end) {
      byte tag = apdu[cursor];
      short tlvLength = TLVReader.getLength(apdu, cursor);
      short valueOffset = TLVReader.getDataOffset(apdu, cursor);
      short next = (short) (valueOffset + tlvLength);
      if (next > end) ISOException.throwIt(ISO7816.SW_DATA_INVALID);

      if (tag == TAG_ENCRYPTED_DATA) {
        if (encryptedTlvOffset != (short) -1 || tlvLength < (short) 17) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        if (apdu[valueOffset] != PADDING_INDICATOR) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        encryptedTlvOffset = cursor;
        encryptedValueOffset = (short) (valueOffset + 1);
        encryptedValueLength = (short) (tlvLength - 1);
        if ((short) (encryptedValueLength % LENGTH_BLOCK) != (short) 0) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
      } else if (tag == TAG_LE) {
        if (tlvLength != (short) 1 || apdu[valueOffset] != (byte) 0x00) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
      } else if (tag == TAG_MAC) {
        if (macTlvOffset != (short) -1 || tlvLength != LENGTH_SHORT_MAC || next != end) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        macTlvOffset = cursor;
        macValueOffset = valueOffset;
      } else {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }

      cursor = next;
    }

    if (macTlvOffset == (short) -1) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    short macInputLength = buildCommandMacInput(apdu, offset, macTlvOffset, work, workOffset);
    PIVCrypto.doAesCmac(skMac, work, workOffset, macInputLength, work, (short) (workOffset + macInputLength));
    if (Util.arrayCompare(
            work,
            (short) (workOffset + macInputLength),
            apdu,
            macValueOffset,
            LENGTH_SHORT_MAC)
        != (byte) 0) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
    Util.arrayCopyNonAtomic(work, (short) (workOffset + macInputLength), commandMcv, (short) 0, LENGTH_BLOCK);

    state[OFFSET_LAST_CLA] = apdu[ISO7816.OFFSET_CLA];
    state[OFFSET_LAST_INS] = apdu[ISO7816.OFFSET_INS];
    apdu[ISO7816.OFFSET_CLA] = (byte) (apdu[ISO7816.OFFSET_CLA] & (byte) 0xF3);

    if (encryptedTlvOffset == (short) -1) return (short) 0;

    buildIv(false, work, workOffset);
    short plainLength =
        PIVCrypto.doAesCbcDecrypt(
            skEnc,
            work,
            workOffset,
            LENGTH_BLOCK,
            apdu,
            encryptedValueOffset,
            encryptedValueLength,
            apdu,
            offset);
    return stripPadding(apdu, offset, plainLength);
  }

  short wrapResponse(
      byte[] plaintext,
      short plaintextOffset,
      short plaintextLength,
      short sw,
      byte[] out,
      short outOffset) {
    short cursor = outOffset;

    if (plaintextLength > (short) 0) {
      out[cursor++] = TAG_ENCRYPTED_DATA;
      short paddedLength = paddedLength(plaintextLength);
      cursor += writeLength(out, cursor, (short) (paddedLength + 1));
      short valueOffset = cursor;
      out[cursor++] = PADDING_INDICATOR;
      Util.arrayCopyNonAtomic(plaintext, plaintextOffset, out, cursor, plaintextLength);
      short padOffset = (short) (cursor + plaintextLength);
      out[padOffset] = (byte) 0x80;
      Util.arrayFillNonAtomic(out, (short) (padOffset + 1), (short) (paddedLength - plaintextLength - 1), (byte) 0);
      buildIv(true, out, (short) (valueOffset + 1));
      PIVCrypto.doAesCbcEncrypt(
          skEnc,
          out,
          (short) (valueOffset + 1),
          LENGTH_BLOCK,
          out,
          cursor,
          paddedLength,
          out,
          cursor);
      cursor += paddedLength;
    }

    out[cursor++] = TAG_STATUS;
    out[cursor++] = (byte) 2;
    Util.setShort(out, cursor, sw);
    cursor += (short) 2;

    short macInputLength = buildResponseMacInput(out, outOffset, cursor, out, cursor);
    PIVCrypto.doAesCmac(skRmac, out, cursor, macInputLength, out, (short) (cursor + macInputLength));
    Util.arrayCopyNonAtomic(out, (short) (cursor + macInputLength), responseMcv, (short) 0, LENGTH_BLOCK);

    out[cursor++] = TAG_MAC;
    out[cursor++] = (byte) LENGTH_SHORT_MAC;
    Util.arrayCopyNonAtomic(responseMcv, (short) 0, out, cursor, LENGTH_SHORT_MAC);
    cursor += LENGTH_SHORT_MAC;

    if (shouldIncrementCounter()) incrementCounter();
    return (short) (cursor - outOffset);
  }

  private short buildCommandMacInput(
      byte[] apdu, short bodyOffset, short bodyEnd, byte[] out, short outOffset) {
    short cursor = outOffset;
    Util.arrayCopyNonAtomic(commandMcv, (short) 0, out, cursor, LENGTH_BLOCK);
    cursor += LENGTH_BLOCK;
    out[cursor++] = CLA_SECURE_MESSAGING;
    out[cursor++] = apdu[ISO7816.OFFSET_INS];
    out[cursor++] = apdu[ISO7816.OFFSET_P1];
    out[cursor++] = apdu[ISO7816.OFFSET_P2];
    out[cursor++] = (byte) 0x80;
    Util.arrayFillNonAtomic(out, cursor, (short) 11, (byte) 0);
    cursor += (short) 11;
    if (bodyEnd > bodyOffset) {
      short bodyLength = (short) (bodyEnd - bodyOffset);
      Util.arrayCopyNonAtomic(apdu, bodyOffset, out, cursor, bodyLength);
      cursor += bodyLength;
    }
    return (short) (cursor - outOffset);
  }

  private short buildResponseMacInput(byte[] response, short offset, short end, byte[] out, short outOffset) {
    short cursor = outOffset;
    Util.arrayCopyNonAtomic(responseMcv, (short) 0, out, cursor, LENGTH_BLOCK);
    cursor += LENGTH_BLOCK;
    Util.arrayCopyNonAtomic(response, offset, out, cursor, (short) (end - offset));
    cursor += (short) (end - offset);
    return (short) (cursor - outOffset);
  }

  private void buildIv(boolean response, byte[] out, short outOffset) {
    Util.arrayCopyNonAtomic(encCounter, (short) 0, out, outOffset, LENGTH_BLOCK);
    if (response) out[outOffset] = (byte) (out[outOffset] | (byte) 0x80);
    PIVCrypto.doAesEcbEncrypt(skEnc, out, outOffset, LENGTH_BLOCK, out, outOffset);
  }

  private short stripPadding(byte[] buffer, short offset, short length) {
    short cursor = (short) (offset + length - 1);
    while (cursor >= offset) {
      if (buffer[cursor] == (byte) 0x80) return (short) (cursor - offset);
      if (buffer[cursor] != (byte) 0x00) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      cursor--;
    }
    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    return (short) 0;
  }

  private short paddedLength(short length) {
    return (short) (length + (short) (LENGTH_BLOCK - (short) (length % LENGTH_BLOCK)));
  }

  private boolean shouldIncrementCounter() {
    if (state[OFFSET_LAST_INS] == INS_GET_RESPONSE) return false;
    return state[OFFSET_LAST_CLA] != CLA_CHAINED_SECURE_MESSAGING;
  }

  private void incrementCounter() {
    for (short i = (short) 15; i >= (short) 0; i--) {
      encCounter[i]++;
      if (encCounter[i] != (byte) 0) return;
    }
  }

  private short writeLength(byte[] buffer, short offset, short length) {
    if (length <= (short) 0x7F) {
      buffer[offset] = (byte) length;
      return (short) 1;
    }
    buffer[offset++] = (byte) 0x81;
    buffer[offset] = (byte) length;
    return (short) 2;
  }
}
