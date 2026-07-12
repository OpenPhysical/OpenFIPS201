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

/**
 * Tracks transient PIV secure messaging and VCI session state.
 *
 * <p>NIST SP 800-73-5 Part 2 Sections 4.2.1-4.2.7 define PIV secure messaging
 * data objects, command/response protection, and error handling. This class implements that
 * APDU wrapping for Cipher Suites 2 and 7 (Section 4.1.4 Table 18): AES-128 (CS2) or AES-256
 * (CS7) session keys with a 128-bit AES block for CMAC/CBC.
 */
final class PIVSecureMessaging {
  private static final short OFFSET_SM_ESTABLISHED = (short) 0;
  private static final short OFFSET_PAIRING_VERIFIED = (short) 1;
  private static final short OFFSET_VCI_ESTABLISHED = (short) 2;
  private static final short OFFSET_LAST_CLA = (short) 3;
  private static final short OFFSET_LAST_INS = (short) 4;
  private static final short LENGTH_STATE = (short) 5;
  //#if VCI_CS2
  private static final short LENGTH_SESSION_KEY = (short) 16;
  //#else
  private static final short LENGTH_SESSION_KEY = (short) 32;
  //#endif
  private static final short OFFSET_RESPONSE_PHASE = (short) 0;
  private static final short OFFSET_RESPONSE_PHASE_OFFSET = (short) 1;
  private static final short OFFSET_RESPONSE_PLAIN_REMAINING = (short) 2;
  private static final short OFFSET_RESPONSE_PADDING_REMAINING = (short) 3;
  private static final short OFFSET_RESPONSE_PADDED_LENGTH = (short) 4;
  private static final short OFFSET_RESPONSE_SW = (short) 5;
  private static final short OFFSET_RESPONSE_BLOCK_OFFSET = (short) 6;
  private static final short OFFSET_RESPONSE_PLAIN_CONSUMED = (short) 7;
  private static final short LENGTH_RESPONSE_STATE = (short) 8;
  private static final short RESPONSE_PHASE_NONE = (short) 0;
  private static final short RESPONSE_PHASE_HEADER = (short) 1;
  private static final short RESPONSE_PHASE_DATA = (short) 2;
  private static final short RESPONSE_PHASE_FINAL = (short) 3;
  private static final short LENGTH_BLOCK = (short) 16;
  private static final short LENGTH_SHORT_MAC = (short) 8;
  static final short MAX_RESPONSE_PLAINTEXT = (short) 191;
  private static final byte CLA_SECURE_MESSAGING = (byte) 0x0C;
  private static final byte CLA_CHAINED_SECURE_MESSAGING = (byte) 0x1C;
  private static final byte INS_GET_RESPONSE = (byte) 0xC0;
  // BER-TLV Tags defined in NIST SP 800-73-5 Part 2, Section 4.2.1 Table 21
  private static final byte TAG_ENCRYPTED_DATA = (byte) 0x87; // Padding indicator + encrypted data
  private static final byte TAG_MAC = (byte) 0x8E; // Cryptographic checksum (C-MAC/R-MAC)
  private static final byte TAG_LE = (byte) 0x97; // Le encapsulation
  private static final byte TAG_STATUS = (byte) 0x99; // Status word
  private static final byte PADDING_INDICATOR = (byte) 0x01; // Padding indicator per Section 4.2.2

  // Secure messaging processing status words, NIST SP 800-73-5 Part 2 Section 4.2.7 (Error
  // Handling). These are the SW processing statuses of the secure messaging layer itself and are
  // returned without performing further secure messaging (i.e. never wrapped):
  //   '69 82' - security status not satisfied (secure messaging requested but no session keys
  //             have been established - Section 4.2.7 footnote)
  //   '69 87' - expected secure messaging data objects are missing
  //   '69 88' - secure messaging data objects are incorrect
  private static final short SW_SM_EXPECTED_OBJECTS_MISSING = (short) 0x6987;
  private static final short SW_SM_OBJECTS_INCORRECT = (short) 0x6988;

  private final byte[] state;
  private final byte[] commandMcv;
  private final byte[] responseMcv;
  private final byte[] encCounter;
  private final short[] responseState;
  private final byte[] responseIv;
  private final byte[] responseBlock;
  private final byte[] responseTail;
  private final AESKey skCfrm;
  private final AESKey skMac;
  private final AESKey skEnc;
  private final AESKey skRmac;

  PIVSecureMessaging() {
    state = JCSystem.makeTransientByteArray(LENGTH_STATE, JCSystem.CLEAR_ON_DESELECT);
    commandMcv = JCSystem.makeTransientByteArray(LENGTH_BLOCK, JCSystem.CLEAR_ON_DESELECT);
    responseMcv = JCSystem.makeTransientByteArray(LENGTH_BLOCK, JCSystem.CLEAR_ON_DESELECT);
    encCounter = JCSystem.makeTransientByteArray(LENGTH_BLOCK, JCSystem.CLEAR_ON_DESELECT);
    responseState = JCSystem.makeTransientShortArray(LENGTH_RESPONSE_STATE, JCSystem.CLEAR_ON_DESELECT);
    responseIv = JCSystem.makeTransientByteArray(LENGTH_BLOCK, JCSystem.CLEAR_ON_DESELECT);
    responseBlock = JCSystem.makeTransientByteArray(LENGTH_BLOCK, JCSystem.CLEAR_ON_DESELECT);
    responseTail = JCSystem.makeTransientByteArray((short) 14, JCSystem.CLEAR_ON_DESELECT);
    //#if VCI_CS2
    skCfrm = PIVCrypto.buildTransientAes128Key();
    skMac = PIVCrypto.buildTransientAes128Key();
    skEnc = PIVCrypto.buildTransientAes128Key();
    skRmac = PIVCrypto.buildTransientAes128Key();
    //#else
    skCfrm = PIVCrypto.buildTransientAes256Key();
    skMac = PIVCrypto.buildTransientAes256Key();
    skEnc = PIVCrypto.buildTransientAes256Key();
    skRmac = PIVCrypto.buildTransientAes256Key();
    //#endif
  }

  void clear() {
    state[OFFSET_SM_ESTABLISHED] = (byte) 0;
    state[OFFSET_PAIRING_VERIFIED] = (byte) 0;
    state[OFFSET_VCI_ESTABLISHED] = (byte) 0;
    Util.arrayFillNonAtomic(commandMcv, (short) 0, LENGTH_BLOCK, (byte) 0);
    Util.arrayFillNonAtomic(responseMcv, (short) 0, LENGTH_BLOCK, (byte) 0);
    Util.arrayFillNonAtomic(encCounter, (short) 0, LENGTH_BLOCK, (byte) 0);
    clearResponseState();
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
    clearResponseState();
    encCounter[(short) 15] = (byte) 1;
    state[OFFSET_LAST_CLA] = (byte) 0;
    state[OFFSET_LAST_INS] = (byte) 0;
  }

  void markPairingVerified() {
    state[OFFSET_PAIRING_VERIFIED] = (byte) 1;
    state[OFFSET_VCI_ESTABLISHED] = (byte) 1;
  }

  /**
   * Loads SK_CFRM || SK_MAC || SK_ENC || SK_RMAC (each {@code keyLength} bytes).
   *
   * @param keyLength 16 (CS2) or 32 (CS7)
   */
  void setSessionKeys(byte[] buffer, short offset, short keyLength) {
    if (keyLength != LENGTH_SESSION_KEY) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    skCfrm.setKey(buffer, offset);
    offset += keyLength;
    skMac.setKey(buffer, offset);
    offset += keyLength;
    skEnc.setKey(buffer, offset);
    offset += keyLength;
    skRmac.setKey(buffer, offset);
  }

  /** Loads 16-byte (CS2) session keys. */
  void setSessionKeys(byte[] buffer, short offset) {
    setSessionKeys(buffer, offset, LENGTH_SESSION_KEY);
  }

  short computeConfirmationMac(
      byte[] buffer, short offset, short length, byte[] out, short outOffset) {
    return PIVCrypto.doAesCmac(skCfrm, buffer, offset, length, out, outOffset);
  }

  boolean isSecureMessagingCla(byte cla) {
    return (byte) (cla & (byte) 0x1C) == CLA_SECURE_MESSAGING
        || (byte) (cla & (byte) 0x1C) == CLA_CHAINED_SECURE_MESSAGING;
  }

  void markGetResponse() {
    state[OFFSET_LAST_INS] = INS_GET_RESPONSE;
  }

  /**
   * Unwraps an incoming command APDU.
   *
   * <p>Aligned with NIST SP 800-73-5 Part 2, Section 4.2.4 (Command with PIV Secure Messaging). If
   * any secure messaging error (like C-MAC verification or decryption fail) occurs, the session
   * keys are zeroized per Section 4.3 (Session Key Destruction).
   */
  short unwrapCommand(byte[] apdu, short offset, short length, byte[] work, short workOffset) {
    try {
      return unwrapCommandChecked(apdu, offset, length, work, workOffset);
    } catch (ISOException ex) {
      // NIST SP 800-73-5 Part 2 Section 4.3 requires key zeroization on secure messaging errors.
      clear();
      throw ex;
    }
  }

  private short unwrapCommandChecked(
      byte[] apdu, short offset, short length, byte[] work, short workOffset) {
    // NIST SP 800-73-5 Part 2 Section 4.2.7 SW '69 82' is returned when secure messaging is
    // requested but no session keys are established.
    if (!isEstablished()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

    short end = (short) (offset + length);
    short cursor = offset;
    short encryptedTlvOffset = (short) -1;
    short encryptedValueOffset = (short) -1;
    short encryptedValueLength = (short) 0;
    short macTlvOffset = (short) -1;
    short macValueOffset = (short) -1;

    // Any malformed, duplicated, misordered or unknown secure messaging data object in the
    // command data field is "secure messaging data objects are incorrect": '69 88' per NIST
    // SP 800-73-5 Part 2 Section 4.2.7.
    while (cursor < end) {
      byte tag = apdu[cursor];
      short tlvLength = TLVReader.getLength(apdu, cursor);
      short valueOffset = TLVReader.getDataOffset(apdu, cursor);
      short next = (short) (valueOffset + tlvLength);
      if (next > end) ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);

      if (tag == TAG_ENCRYPTED_DATA) {
        if (encryptedTlvOffset != (short) -1 || tlvLength < (short) 17) {
          ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
        }
        if (apdu[valueOffset] != PADDING_INDICATOR) ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
        encryptedTlvOffset = cursor;
        encryptedValueOffset = (short) (valueOffset + 1);
        encryptedValueLength = (short) (tlvLength - 1);
        if ((short) (encryptedValueLength % LENGTH_BLOCK) != (short) 0) {
          ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
        }
      } else if (tag == TAG_LE) {
        if (tlvLength != (short) 1 || apdu[valueOffset] != (byte) 0x00) {
          ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
        }
      } else if (tag == TAG_MAC) {
        if (macTlvOffset != (short) -1 || tlvLength != LENGTH_SHORT_MAC || next != end) {
          ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
        }
        macTlvOffset = cursor;
        macValueOffset = valueOffset;
      } else {
        ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
      }

      cursor = next;
    }

    // NIST SP 800-73-5 Part 2 Section 4.2.7 requires returning '69 87' if expected secure
    // messaging data objects (like tag '8E' for C-MAC) are missing.
    if (macTlvOffset == (short) -1) ISOException.throwIt(SW_SM_EXPECTED_OBJECTS_MISSING);

    // Verify C-MAC (NIST SP 800-73-5 Part 2 Section 4.2.3)
    short macInputLength = buildCommandMacInput(apdu, offset, macTlvOffset, work, workOffset);
    PIVCrypto.doAesCmac(
        skMac, work, workOffset, macInputLength, work, (short) (workOffset + macInputLength));
    if (Util.arrayCompare(
            work, (short) (workOffset + macInputLength), apdu, macValueOffset, LENGTH_SHORT_MAC)
        != (byte) 0) {
      // A C-MAC ('8E') that fails verification is an incorrect secure messaging data object:
      // '69 88' per NIST SP 800-73-5 Part 2 Section 4.2.7. ('69 82' is reserved for secure
      // messaging requested before session keys are established - Section 4.2.7 footnote.)
      ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
    }
    // Update MAC chaining value (MCV) per Section 4.2
    Util.arrayCopyNonAtomic(
        work, (short) (workOffset + macInputLength), commandMcv, (short) 0, LENGTH_BLOCK);

    state[OFFSET_LAST_CLA] = apdu[ISO7816.OFFSET_CLA];
    state[OFFSET_LAST_INS] = apdu[ISO7816.OFFSET_INS];
    apdu[ISO7816.OFFSET_CLA] = (byte) (apdu[ISO7816.OFFSET_CLA] & (byte) 0xF3);

    if (encryptedTlvOffset == (short) -1) return (short) 0;

    // Decrypt command data (NIST SP 800-73-5 Part 2 Section 4.2.2)
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

  /**
   * Wraps a response payload under secure messaging.
   *
   * <p>Aligned with NIST SP 800-73-5 Part 2, Section 4.2.6 (Response with PIV Secure Messaging).
   * Data confidentiality and response integrity are achieved as per Section 4.2.2 and Section
   * 4.2.5.
   */
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
      Util.arrayFillNonAtomic(
          out, (short) (padOffset + 1), (short) (paddedLength - plaintextLength - 1), (byte) 0);
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

    // Encapsulate status word (NIST SP 800-73-5 Part 2 Section 4.2.5 item 3)
    out[cursor++] = TAG_STATUS;
    out[cursor++] = (byte) 2;
    Util.setShort(out, cursor, sw);
    cursor += (short) 2;

    // Compute R-MAC over response data and status template (NIST SP 800-73-5 Part 2 Section 4.2.5)
    short macInputLength = buildResponseMacInput(out, outOffset, cursor, out, cursor);
    PIVCrypto.doAesCmac(
        skRmac, out, cursor, macInputLength, out, (short) (cursor + macInputLength));
    Util.arrayCopyNonAtomic(
        out, (short) (cursor + macInputLength), responseMcv, (short) 0, LENGTH_BLOCK);

    out[cursor++] = TAG_MAC;
    out[cursor++] = (byte) LENGTH_SHORT_MAC;
    Util.arrayCopyNonAtomic(responseMcv, (short) 0, out, cursor, LENGTH_SHORT_MAC);
    cursor += LENGTH_SHORT_MAC;

    if (shouldIncrementCounter()) incrementCounter();
    return (short) (cursor - outOffset);
  }

  void beginResponseStream(short plaintextLength, short sw) {
    clearResponseState();
    responseState[OFFSET_RESPONSE_SW] = sw;
    responseState[OFFSET_RESPONSE_PLAIN_REMAINING] = plaintextLength;

    PIVCrypto.doAesCmacInit(skRmac);
    PIVCrypto.doAesCmacUpdate(responseMcv, (short) 0, LENGTH_BLOCK);

    if (plaintextLength > (short) 0) {
      short paddedLength = paddedLength(plaintextLength);
      responseState[OFFSET_RESPONSE_PADDED_LENGTH] = paddedLength;
      responseState[OFFSET_RESPONSE_PADDING_REMAINING] = (short) (paddedLength - plaintextLength);
      buildIv(true, responseIv, (short) 0);
      responseState[OFFSET_RESPONSE_PHASE] = RESPONSE_PHASE_HEADER;
    } else {
      prepareFinalResponseTail();
    }
  }

  short writeResponseStreamChunk(
      byte[] plaintext, short plaintextOffset, byte[] out, short outOffset, short maxLength) {
    responseState[OFFSET_RESPONSE_PLAIN_CONSUMED] = (short) 0;
    short cursor = outOffset;
    short end = (short) (outOffset + maxLength);

    while (cursor < end && responseState[OFFSET_RESPONSE_PHASE] != RESPONSE_PHASE_NONE) {
      short phase = responseState[OFFSET_RESPONSE_PHASE];
      if (phase == RESPONSE_PHASE_HEADER) {
        cursor = writeResponseHeader(out, cursor, end);
      } else if (phase == RESPONSE_PHASE_DATA) {
        cursor = writeResponseCiphertext(plaintext, plaintextOffset, out, cursor, end);
      } else {
        cursor = writeResponseTail(out, cursor, end);
      }
    }

    return (short) (cursor - outOffset);
  }

  short getResponseStreamPlaintextConsumed() {
    return responseState[OFFSET_RESPONSE_PLAIN_CONSUMED];
  }

  boolean isResponseStreamComplete() {
    return responseState[OFFSET_RESPONSE_PHASE] == RESPONSE_PHASE_NONE;
  }

  short getResponseStreamStatusWord() {
    if (isResponseStreamComplete()) return ISO7816.SW_NO_ERROR;

    short remaining = remainingResponseStreamBytes();
    short sw2 = remaining > (short) 0x00FF ? (short) 0 : remaining;
    return (short) (ISO7816.SW_BYTES_REMAINING_00 | sw2);
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

  private short buildResponseMacInput(
      byte[] response, short offset, short end, byte[] out, short outOffset) {
    short cursor = outOffset;
    Util.arrayCopyNonAtomic(responseMcv, (short) 0, out, cursor, LENGTH_BLOCK);
    cursor += LENGTH_BLOCK;
    Util.arrayCopyNonAtomic(response, offset, out, cursor, (short) (end - offset));
    cursor += (short) (end - offset);
    return (short) (cursor - outOffset);
  }

  private short writeResponseHeader(byte[] out, short cursor, short end) {
    short encryptedValueLength = (short) (responseState[OFFSET_RESPONSE_PADDED_LENGTH] + (short) 1);
    short headerLength = responseHeaderLength(encryptedValueLength);
    while (cursor < end && responseState[OFFSET_RESPONSE_PHASE_OFFSET] < headerLength) {
      short index = responseState[OFFSET_RESPONSE_PHASE_OFFSET];
      out[cursor] = responseHeaderByte(encryptedValueLength, index);
      PIVCrypto.doAesCmacUpdate(out, cursor, (short) 1);
      cursor++;
      responseState[OFFSET_RESPONSE_PHASE_OFFSET]++;
    }

    if (responseState[OFFSET_RESPONSE_PHASE_OFFSET] == headerLength) {
      responseState[OFFSET_RESPONSE_PHASE_OFFSET] = (short) 0;
      responseState[OFFSET_RESPONSE_PHASE] = RESPONSE_PHASE_DATA;
    }

    return cursor;
  }

  private byte responseHeaderByte(short encryptedValueLength, short index) {
    if (index == (short) 0) return TAG_ENCRYPTED_DATA;
    if (encryptedValueLength <= (short) 0x7F) {
      if (index == (short) 1) return (byte) encryptedValueLength;
      return PADDING_INDICATOR;
    }

    if (encryptedValueLength <= (short) 0x00FF) {
      if (index == (short) 1) return (byte) 0x81;
      if (index == (short) 2) return (byte) encryptedValueLength;
      return PADDING_INDICATOR;
    }

    if (index == (short) 1) return (byte) 0x82;
    if (index == (short) 2) return (byte) (encryptedValueLength >> 8);
    if (index == (short) 3) return (byte) encryptedValueLength;
    return PADDING_INDICATOR;
  }

  private short responseHeaderLength(short encryptedValueLength) {
    if (encryptedValueLength <= (short) 0x7F) return (short) 3;
    if (encryptedValueLength <= (short) 0x00FF) return (short) 4;
    return (short) 5;
  }

  private short writeResponseCiphertext(
      byte[] plaintext, short plaintextOffset, byte[] out, short cursor, short end) {
    while (cursor < end && responseState[OFFSET_RESPONSE_PHASE] == RESPONSE_PHASE_DATA) {
      if (responseState[OFFSET_RESPONSE_BLOCK_OFFSET] == (short) 0) {
        prepareNextResponseCiphertextBlock(plaintext, plaintextOffset);
      }

      while (cursor < end && responseState[OFFSET_RESPONSE_BLOCK_OFFSET] < LENGTH_BLOCK) {
        out[cursor++] = responseBlock[responseState[OFFSET_RESPONSE_BLOCK_OFFSET]++];
      }

      if (responseState[OFFSET_RESPONSE_BLOCK_OFFSET] == LENGTH_BLOCK) {
        responseState[OFFSET_RESPONSE_BLOCK_OFFSET] = (short) 0;
        if (responseState[OFFSET_RESPONSE_PLAIN_REMAINING] == (short) 0
            && responseState[OFFSET_RESPONSE_PADDING_REMAINING] == (short) 0) {
          prepareFinalResponseTail();
        }
      }
    }

    return cursor;
  }

  private void prepareNextResponseCiphertextBlock(byte[] plaintext, short plaintextOffset) {
    short copied = (short) 0;
    short remainingPlain = responseState[OFFSET_RESPONSE_PLAIN_REMAINING];
    if (remainingPlain > (short) 0) {
      copied = remainingPlain > LENGTH_BLOCK ? LENGTH_BLOCK : remainingPlain;
      short consumed = responseState[OFFSET_RESPONSE_PLAIN_CONSUMED];
      Util.arrayCopyNonAtomic(
          plaintext, (short) (plaintextOffset + consumed), responseBlock, (short) 0, copied);
      responseState[OFFSET_RESPONSE_PLAIN_REMAINING] = (short) (remainingPlain - copied);
      responseState[OFFSET_RESPONSE_PLAIN_CONSUMED] = (short) (consumed + copied);
    }

    short paddingOffset = copied;
    if (paddingOffset < LENGTH_BLOCK) {
      responseBlock[paddingOffset++] = (byte) 0x80;
      responseState[OFFSET_RESPONSE_PADDING_REMAINING]--;
      short zeroes = (short) (LENGTH_BLOCK - paddingOffset);
      Util.arrayFillNonAtomic(responseBlock, paddingOffset, zeroes, (byte) 0);
      responseState[OFFSET_RESPONSE_PADDING_REMAINING] =
          (short) (responseState[OFFSET_RESPONSE_PADDING_REMAINING] - zeroes);
    }

    for (short index = (short) 0; index < LENGTH_BLOCK; index++) {
      responseBlock[index] ^= responseIv[index];
    }

    PIVCrypto.doAesEcbEncrypt(
        skEnc, responseBlock, (short) 0, LENGTH_BLOCK, responseBlock, (short) 0);
    Util.arrayCopyNonAtomic(responseBlock, (short) 0, responseIv, (short) 0, LENGTH_BLOCK);
    PIVCrypto.doAesCmacUpdate(responseBlock, (short) 0, LENGTH_BLOCK);
  }

  private void prepareFinalResponseTail() {
    responseTail[(short) 0] = TAG_STATUS;
    responseTail[(short) 1] = (byte) 2;
    Util.setShort(responseTail, (short) 2, responseState[OFFSET_RESPONSE_SW]);
    PIVCrypto.doAesCmacFinal(responseTail, (short) 0, (short) 4, responseMcv, (short) 0);
    responseTail[(short) 4] = TAG_MAC;
    responseTail[(short) 5] = (byte) LENGTH_SHORT_MAC;
    Util.arrayCopyNonAtomic(responseMcv, (short) 0, responseTail, (short) 6, LENGTH_SHORT_MAC);
    responseState[OFFSET_RESPONSE_PHASE_OFFSET] = (short) 0;
    responseState[OFFSET_RESPONSE_PHASE] = RESPONSE_PHASE_FINAL;
  }

  private short writeResponseTail(byte[] out, short cursor, short end) {
    while (cursor < end && responseState[OFFSET_RESPONSE_PHASE_OFFSET] < (short) 14) {
      out[cursor++] = responseTail[responseState[OFFSET_RESPONSE_PHASE_OFFSET]++];
    }

    if (responseState[OFFSET_RESPONSE_PHASE_OFFSET] == (short) 14) {
      responseState[OFFSET_RESPONSE_PHASE] = RESPONSE_PHASE_NONE;
      responseState[OFFSET_RESPONSE_PHASE_OFFSET] = (short) 0;
      if (shouldIncrementCounter()) incrementCounter();
    }

    return cursor;
  }

  private short remainingResponseStreamBytes() {
    short phase = responseState[OFFSET_RESPONSE_PHASE];
    if (phase == RESPONSE_PHASE_NONE) return (short) 0;

    short remaining = (short) 0;
    if (phase == RESPONSE_PHASE_HEADER) {
      short encryptedValueLength =
          (short) (responseState[OFFSET_RESPONSE_PADDED_LENGTH] + (short) 1);
      remaining =
          (short)
              (remaining
                  + responseHeaderLength(encryptedValueLength)
                  - responseState[OFFSET_RESPONSE_PHASE_OFFSET]);
      phase = RESPONSE_PHASE_DATA;
    }

    if (phase == RESPONSE_PHASE_DATA) {
      short pendingBlock =
          responseState[OFFSET_RESPONSE_BLOCK_OFFSET] == (short) 0
              ? (short) 0
              : (short) (LENGTH_BLOCK - responseState[OFFSET_RESPONSE_BLOCK_OFFSET]);
      remaining =
          (short)
              (remaining
                  + pendingBlock
                  + responseState[OFFSET_RESPONSE_PLAIN_REMAINING]
                  + responseState[OFFSET_RESPONSE_PADDING_REMAINING]);
      phase = RESPONSE_PHASE_FINAL;
    }

    if (phase == RESPONSE_PHASE_FINAL) {
      remaining = (short) (remaining + (short) 14 - responseState[OFFSET_RESPONSE_PHASE_OFFSET]);
    }

    return remaining;
  }

  private void buildIv(boolean response, byte[] out, short outOffset) {
    Util.arrayCopyNonAtomic(encCounter, (short) 0, out, outOffset, LENGTH_BLOCK);
    if (response) out[outOffset] = (byte) (out[outOffset] | (byte) 0x80);
    PIVCrypto.doAesEcbEncrypt(skEnc, out, outOffset, LENGTH_BLOCK, out, outOffset);
  }

  private short stripPadding(byte[] buffer, short offset, short length) {
    // Invalid ISO 7816-4 padding in the recovered plaintext means the '87' encrypted-data
    // object was incorrect: '69 88' per NIST SP 800-73-5 Part 2 Section 4.2.7.
    short cursor = (short) (offset + length - 1);
    while (cursor >= offset) {
      if (buffer[cursor] == (byte) 0x80) return (short) (cursor - offset);
      if (buffer[cursor] != (byte) 0x00) ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
      cursor--;
    }
    ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
    return (short) 0;
  }

  private short paddedLength(short length) {
    return (short) (length + (short) (LENGTH_BLOCK - (short) (length % LENGTH_BLOCK)));
  }

  /**
   * Checks whether the encryption counter should be incremented.
   *
   * <p>NIST SP 800-73-5 Part 2 Section 4.2.2 requires the encryption counter to be incremented by
   * one after each APDU sent over secure messaging, except for the GET RESPONSE command and APDUs
   * with a CLA of '1C'.
   */
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

    if (length <= (short) 0x00FF) {
      buffer[offset++] = (byte) 0x81;
      buffer[offset] = (byte) length;
      return (short) 2;
    }

    buffer[offset++] = (byte) 0x82;
    Util.setShort(buffer, offset, length);
    return (short) 3;
  }

  private void clearResponseState() {
    for (short index = (short) 0; index < LENGTH_RESPONSE_STATE; index++) {
      responseState[index] = (short) 0;
    }
  }
}
