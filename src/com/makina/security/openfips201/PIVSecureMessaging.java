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
import javacard.security.KeyBuilder;

/**
 * Tracks transient PIV secure messaging and VCI session state.
 *
 * <p>NIST SP 800-73-5 Part 2 Sections 4.2.1-4.2.7 define PIV secure messaging data objects,
 * command/response protection, and error handling. This class implements that APDU wrapping for
 * Cipher Suites 2 and 7 (Section 4.1.4 Table 18): AES-128 (CS2) or AES-256 (CS7) session keys with
 * a 128-bit AES block for CMAC/CBC.
 *
 * <p>A bounded parser handles a contactless PUT DATA command that policy must reject. Section 4.2.4
 * requires the card to "reconstruct and process[] the entire command" before it applies the command
 * policy. The parser authenticates and decrypts the logical command across APDU frames. It stores
 * only one plaintext block and does not retain the rejected value.
 */
final class PIVSecureMessaging {
  private static final short OFFSET_SM_ESTABLISHED = (short) 0;
  private static final short OFFSET_VCI_ESTABLISHED = (short) 1;
  private static final short OFFSET_LAST_CLA = (short) 2;
  private static final short OFFSET_LAST_INS = (short) 3;
  private static final short LENGTH_STATE = (short) 4;
  private static final short LENGTH_SESSION_KEY = PIVOpacity.SESSION_KEY_LENGTH;
  private static final short OFFSET_RESPONSE_PHASE = (short) 0;
  private static final short OFFSET_RESPONSE_PHASE_OFFSET = (short) 1;
  private static final short OFFSET_RESPONSE_PLAIN_REMAINING = (short) 2;
  private static final short OFFSET_RESPONSE_PADDING_REMAINING = (short) 3;
  private static final short OFFSET_RESPONSE_PADDED_LENGTH = (short) 4;
  private static final short OFFSET_RESPONSE_SW = (short) 5;
  private static final short OFFSET_RESPONSE_BLOCK_OFFSET = (short) 6;
  private static final short OFFSET_RESPONSE_PLAIN_CONSUMED = (short) 7;
  private static final short LENGTH_RESPONSE_STATE = (short) 8;
  /*
   * Bounded rejected-command parser state.
   *
   * The accepted object order is:
   *   87 length 01 ciphertext [97 01 00] 8E 08 command-mac
   *
   * A state can end at any APDU boundary. Length, ciphertext, and MAC counters therefore remain
   * explicit. No offset points into an APDU buffer because the JCRE can replace that buffer between
   * calls.
   */
  private static final short OFFSET_COMMAND_STREAM_PHASE = (short) 0;
  private static final short OFFSET_COMMAND_STREAM_LENGTH_BYTES = (short) 1;
  private static final short OFFSET_COMMAND_STREAM_VALUE_LENGTH = (short) 2;
  private static final short OFFSET_COMMAND_STREAM_CIPHER_REMAINING = (short) 3;
  private static final short OFFSET_COMMAND_STREAM_BLOCK_LENGTH = (short) 4;
  private static final short OFFSET_COMMAND_STREAM_MAC_LENGTH = (short) 5;
  private static final short OFFSET_COMMAND_STREAM_PADDING_VALID = (short) 6;
  private static final short LENGTH_COMMAND_STREAM_STATE = (short) 7;
  private static final short COMMAND_STREAM_NONE = (short) 0;
  private static final short COMMAND_STREAM_ENCRYPTED_TAG = (short) 1;
  private static final short COMMAND_STREAM_LENGTH = (short) 2;
  private static final short COMMAND_STREAM_LONG_LENGTH = (short) 3;
  private static final short COMMAND_STREAM_PADDING_INDICATOR = (short) 4;
  private static final short COMMAND_STREAM_CIPHERTEXT = (short) 5;
  private static final short COMMAND_STREAM_AFTER_ENCRYPTED = (short) 6;
  private static final short COMMAND_STREAM_LE_LENGTH = (short) 7;
  private static final short COMMAND_STREAM_LE_VALUE = (short) 8;
  private static final short COMMAND_STREAM_MAC_TAG = (short) 9;
  private static final short COMMAND_STREAM_MAC_LENGTH = (short) 10;
  private static final short COMMAND_STREAM_MAC_VALUE = (short) 11;
  private static final short COMMAND_STREAM_COMPLETE = (short) 12;
  private static final short RESPONSE_PHASE_NONE = (short) 0;
  private static final short RESPONSE_PHASE_HEADER = (short) 1;
  private static final short RESPONSE_PHASE_DATA = (short) 2;
  private static final short RESPONSE_PHASE_FINAL = (short) 3;
  private static final short LENGTH_BLOCK = PIVCrypto.LENGTH_BLOCK_AES;
  static final short LENGTH_SHORT_MAC = (short) 8;
  static final byte CLA_SECURE_MESSAGING = (byte) 0x0C;
  static final byte CLA_CHAINED_SECURE_MESSAGING = (byte) 0x1C;
  private static final byte INS_GET_RESPONSE = OpenFIPS201.INS_GP_GET_RESPONSE;
  // BER-TLV Tags defined in NIST SP 800-73-5 Part 2, Section 4.2.1 Table 21
  static final byte TAG_ENCRYPTED_DATA = (byte) 0x87; // Padding indicator + encrypted data
  static final byte TAG_MAC = (byte) 0x8E; // Cryptographic checksum (C-MAC/R-MAC)
  private static final byte TAG_LE = (byte) 0x97; // Le encapsulation
  static final byte TAG_STATUS = (byte) 0x99; // Status word
  static final byte PADDING_INDICATOR = (byte) 0x01; // Padding indicator per Section 4.2.2
  static final byte PADDING_DELIMITER = (byte) 0x80; // ISO/IEC 9797-1 padding method 2

  // Secure messaging processing status words, NIST SP 800-73-5 Part 2 Section 4.2.7 (Error
  // Handling). These are the SW processing statuses of the secure messaging layer itself and are
  // returned without performing further secure messaging (i.e. never wrapped):
  //   '69 82' - security status not satisfied (secure messaging requested but no session keys
  //             have been established - Section 4.2.7 footnote)
  //   '69 87' - expected secure messaging data objects are missing
  //   '69 88' - secure messaging data objects are incorrect
  private static final short SW_SM_NOT_SUPPORTED = (short) 0x6882;
  private static final short SW_SM_EXPECTED_OBJECTS_MISSING = (short) 0x6987;
  static final short SW_SM_OBJECTS_INCORRECT = (short) 0x6988;

  /**
   * Maps a failure of protected-command processing to its Section 4.2.7 SW processing status.
   *
   * <p>"If the processing was successful, it SHALL be '90 00'. Otherwise, it SHALL be as follows:
   * '68 82' ... '69 82' ... '69 87' ... '69 88'". Any other reason raised while unwrapping or
   * reassembling a protected command is reported as '69 88'.
   */
  static short toProcessingStatus(short reason) {
    if (reason == SW_SM_NOT_SUPPORTED
        || reason == ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED
        || reason == SW_SM_EXPECTED_OBJECTS_MISSING
        || reason == SW_SM_OBJECTS_INCORRECT) {
      return reason;
    }
    return SW_SM_OBJECTS_INCORRECT;
  }

  private final byte[] state;
  private final byte[] commandMcv;
  private final byte[] responseMcv;
  private final byte[] encCounter;
  private final short[] responseState;
  /** Parser phase and counters that survive command-chain APDU boundaries. */
  private final short[] commandStreamState;

  private final byte[] responseIv;
  private final byte[] responseBlock;
  private final byte[] responseCandidateMcv;
  private final byte[] responseTail;
  /** INS, P1, and P2 of the logical command. Each chained frame must match them. */
  private final byte[] commandStreamHeader;
  /** One AES block for bounded CBC decryption. */
  private final byte[] commandStreamBlock;
  /** The received eight-byte command MAC. */
  private final byte[] commandStreamMac;

  private final AESKey skCfrm;
  private final AESKey skMac;
  private final AESKey skEnc;
  private final AESKey skRmac;

  // The applet instance's cryptographic engines (AES-CBC and the command and response CMACs).
  private final PIVCrypto crypto;

  PIVSecureMessaging(PIVCrypto crypto) {
    this.crypto = crypto;
    // SP 800-73-5 Part 2 Section 3.1.1: when the PIV Card Application is reselected "the setting
    // of all security status indicators in the PIV Card Application SHALL be unchanged". JCRE 3.0.5
    // Section 5.1 clears CLEAR_ON_DESELECT objects "regardless of whether the SELECT FILE command
    // ... Reselects the same applet", so the session (keys, MCVs, counter, SM/VCI status and the
    // response phase that owns the counter advance) is CLEAR_ON_RESET. PIV.deselect() clears it
    // explicitly when the application is genuinely deselected.
    state = JCSystem.makeTransientByteArray(LENGTH_STATE, JCSystem.CLEAR_ON_RESET);
    commandMcv = JCSystem.makeTransientByteArray(LENGTH_BLOCK, JCSystem.CLEAR_ON_RESET);
    responseMcv = JCSystem.makeTransientByteArray(LENGTH_BLOCK, JCSystem.CLEAR_ON_RESET);
    encCounter = JCSystem.makeTransientByteArray(LENGTH_BLOCK, JCSystem.CLEAR_ON_RESET);
    responseState =
        JCSystem.makeTransientShortArray(LENGTH_RESPONSE_STATE, JCSystem.CLEAR_ON_RESET);
    commandStreamState =
        JCSystem.makeTransientShortArray(LENGTH_COMMAND_STREAM_STATE, JCSystem.CLEAR_ON_DESELECT);
    responseIv = JCSystem.makeTransientByteArray(LENGTH_BLOCK, JCSystem.CLEAR_ON_DESELECT);
    responseBlock = JCSystem.makeTransientByteArray(LENGTH_BLOCK, JCSystem.CLEAR_ON_DESELECT);
    responseCandidateMcv =
        JCSystem.makeTransientByteArray(LENGTH_BLOCK, JCSystem.CLEAR_ON_DESELECT);
    responseTail = JCSystem.makeTransientByteArray((short) 14, JCSystem.CLEAR_ON_DESELECT);
    // Transient storage limits rejected-command plaintext to one AES block. It also ensures that a
    // deselection removes the parser state, partial ciphertext, and received MAC.
    commandStreamHeader = JCSystem.makeTransientByteArray((short) 3, JCSystem.CLEAR_ON_DESELECT);
    commandStreamBlock = JCSystem.makeTransientByteArray(LENGTH_BLOCK, JCSystem.CLEAR_ON_DESELECT);
    commandStreamMac =
        JCSystem.makeTransientByteArray(LENGTH_SHORT_MAC, JCSystem.CLEAR_ON_DESELECT);
    // #if VCI_CS2
    skCfrm = PIVCrypto.buildSessionAesKey(KeyBuilder.LENGTH_AES_128);
    skMac = PIVCrypto.buildSessionAesKey(KeyBuilder.LENGTH_AES_128);
    skEnc = PIVCrypto.buildSessionAesKey(KeyBuilder.LENGTH_AES_128);
    skRmac = PIVCrypto.buildSessionAesKey(KeyBuilder.LENGTH_AES_128);
    // #else
    skCfrm = PIVCrypto.buildSessionAesKey(KeyBuilder.LENGTH_AES_256);
    skMac = PIVCrypto.buildSessionAesKey(KeyBuilder.LENGTH_AES_256);
    skEnc = PIVCrypto.buildSessionAesKey(KeyBuilder.LENGTH_AES_256);
    skRmac = PIVCrypto.buildSessionAesKey(KeyBuilder.LENGTH_AES_256);
    // #endif
  }

  void clear() {
    state[OFFSET_SM_ESTABLISHED] = (byte) 0;
    state[OFFSET_VCI_ESTABLISHED] = (byte) 0;
    Util.arrayFillNonAtomic(commandMcv, (short) 0, LENGTH_BLOCK, (byte) 0);
    Util.arrayFillNonAtomic(responseMcv, (short) 0, LENGTH_BLOCK, (byte) 0);
    Util.arrayFillNonAtomic(encCounter, (short) 0, LENGTH_BLOCK, (byte) 0);
    clearResponseState();
    clearRejectedCommandStream();
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
    state[OFFSET_VCI_ESTABLISHED] = pairingRequired ? (byte) 0 : (byte) 1;
    Util.arrayFillNonAtomic(commandMcv, (short) 0, LENGTH_BLOCK, (byte) 0);
    Util.arrayFillNonAtomic(responseMcv, (short) 0, LENGTH_BLOCK, (byte) 0);
    Util.arrayFillNonAtomic(encCounter, (short) 0, LENGTH_BLOCK, (byte) 0);
    clearResponseState();
    clearRejectedCommandStream();
    encCounter[(short) 15] = (byte) 1;
    state[OFFSET_LAST_CLA] = (byte) 0;
    state[OFFSET_LAST_INS] = (byte) 0;
  }

  void markPairingVerified() {
    state[OFFSET_VCI_ESTABLISHED] = (byte) 1;
  }

  void resetPairingVerified() {
    state[OFFSET_VCI_ESTABLISHED] = (byte) 0;
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
    Util.arrayFillNonAtomic(commandMcv, (short) 0, LENGTH_BLOCK, (byte) 0);
    Util.arrayFillNonAtomic(responseMcv, (short) 0, LENGTH_BLOCK, (byte) 0);
    Util.arrayFillNonAtomic(encCounter, (short) 0, LENGTH_BLOCK, (byte) 0);
    clearResponseState();
    clearRejectedCommandStream();
    skCfrm.setKey(buffer, offset);
    offset += keyLength;
    skMac.setKey(buffer, offset);
    offset += keyLength;
    skEnc.setKey(buffer, offset);
    offset += keyLength;
    skRmac.setKey(buffer, offset);
  }

  short computeConfirmationMac(
      byte[] buffer, short offset, short length, byte[] out, short outOffset) {
    return crypto.doAesCmac(skCfrm, buffer, offset, length, out, outOffset);
  }

  void clearConfirmationKey() {
    skCfrm.clearKey();
  }

  boolean isSecureMessagingCla(byte cla) {
    return cla == CLA_SECURE_MESSAGING || cla == CLA_CHAINED_SECURE_MESSAGING;
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
      crypto.requireAesCmac(SW_SM_NOT_SUPPORTED);
      return unwrapCommandChecked(apdu, offset, length, work, workOffset);
    } catch (ISOException ex) {
      // NIST SP 800-73-5 Part 2 Section 4.3 requires key zeroization on secure messaging errors.
      clear();
      if (ex.getReason() == ISO7816.SW_WRONG_DATA) {
        ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
      }
      throw ex;
    } catch (javacard.security.CryptoException ex) {
      clear();
      ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
      return (short) 0;
    }
  }

  /**
   * Reports whether the bounded parser holds an incomplete rejected logical command.
   *
   * @return {@code true} after the first chained fragment and before completion or explicit clear
   */
  boolean isRejectedCommandStreamActive() {
    return commandStreamState[OFFSET_COMMAND_STREAM_PHASE] != COMMAND_STREAM_NONE;
  }

  /**
   * Confirms that an APDU continues the command recorded by the bounded parser.
   *
   * <p>ISO/IEC 7816-4 command chaining carries one logical command. INS, P1, and P2 therefore
   * remain bound to the first fragment.
   *
   * @param apdu candidate continuation APDU
   * @return {@code true} when an active stream and all three command fields match
   */
  boolean rejectedCommandStreamMatches(byte[] apdu) {
    return isRejectedCommandStreamActive()
        && commandStreamHeader[(short) 0] == apdu[ISO7816.OFFSET_INS]
        && commandStreamHeader[(short) 1] == apdu[ISO7816.OFFSET_P1]
        && commandStreamHeader[(short) 2] == apdu[ISO7816.OFFSET_P2];
  }

  /**
   * Erases all bounded-parser data without changing the secure-messaging session.
   *
   * <p>This operation discards an incomplete ISO/IEC 7816-4 command while preserving the
   * authenticated session and current command MCV for the next protected command.
   */
  void clearRejectedCommandStream() {
    Util.arrayFillNonAtomic(
        commandStreamHeader, (short) 0, (short) commandStreamHeader.length, (byte) 0);
    Util.arrayFillNonAtomic(
        commandStreamBlock, (short) 0, (short) commandStreamBlock.length, (byte) 0);
    Util.arrayFillNonAtomic(commandStreamMac, (short) 0, (short) commandStreamMac.length, (byte) 0);
    for (short i = (short) 0; i < LENGTH_COMMAND_STREAM_STATE; i++) {
      commandStreamState[i] = (short) 0;
    }
  }

  /**
   * Authenticates and decrypts a rejected contactless command without retaining its plaintext.
   *
   * <p>SP 800-73-5 Part 2, Section 4.2.4 says the card "reconstructs and processes the entire
   * command." This bounded stream preserves that logical-command rule when the wrapped data is
   * larger than the transient command buffer. The caller applies the Table 2 policy only after this
   * method verifies the final C-MAC and padding.
   *
   * <p>Each non-final frame returns {@code false}. A final, authenticated frame returns {@code
   * true}. A malformed object, invalid C-MAC, invalid padding, or missing session causes an
   * ISOException. Section 4.3 requires session-key destruction after a secure-messaging error, so
   * this method clears the session before it propagates that exception.
   *
   * @param apdu current APDU buffer, including its four-byte command header
   * @param offset first byte of protected command data in this frame
   * @param length protected command data length in this frame
   * @param finalFrame true only for the last frame of the logical command
   * @param work scratch buffer with at least one AES block at {@code workOffset}
   * @param workOffset first scratch-buffer byte available to this method
   * @return true only after complete C-MAC and padding validation
   */
  boolean processRejectedCommandFragment(
      byte[] apdu, short offset, short length, boolean finalFrame, byte[] work, short workOffset) {
    try {
      crypto.requireAesCmac(SW_SM_NOT_SUPPORTED);
      return processRejectedCommandFragmentChecked(
          apdu, offset, length, finalFrame, work, workOffset);
    } catch (ISOException ex) {
      // Section 4.3 requires session-key destruction after a secure messaging error.
      clear();
      throw ex;
    } catch (javacard.security.CryptoException ex) {
      clear();
      ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
      return false;
    }
  }

  /**
   * Advances the protected-command parser for one APDU fragment.
   *
   * <p>SP 800-73-5 Part 2, Sections 4.2.2 through 4.2.4 define the object order, command C-MAC,
   * padding, and logical-command reconstruction rules. The state machine authenticates every
   * protected object byte, decrypts ciphertext in one-block storage, and commits the new MCV only
   * after the final C-MAC and padding both validate.
   *
   * <p>The public wrapper owns session destruction on error. Keeping that action outside this
   * method gives every parser failure the same Section 4.3 teardown behavior.
   *
   * @param apdu current APDU buffer
   * @param offset first protected-data byte in this fragment
   * @param length protected-data length in this fragment
   * @param finalFrame {@code true} only for the final APDU in the logical command
   * @param work scratch buffer used for the padded header, final C-MAC, and decrypted block
   * @param workOffset first scratch-buffer byte available to this parser
   * @return {@code true} only when the final fragment has been fully authenticated
   * @throws ISOException if the session, encoding, C-MAC, padding, or chaining state is invalid
   */
  private boolean processRejectedCommandFragmentChecked(
      byte[] apdu, short offset, short length, boolean finalFrame, byte[] work, short workOffset) {
    if (!isEstablished()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    if (!isRejectedCommandStreamActive()) beginRejectedCommandStream(apdu, work, workOffset);
    if (!rejectedCommandStreamMatches(apdu)) ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);

    short cursor = offset;
    short end = (short) (offset + length);
    while (cursor < end) {
      // Ciphertext is the only variable-size value. Consume it in blocks without copying the
      // rejected plaintext into the logical-command buffer.
      short phase = commandStreamState[OFFSET_COMMAND_STREAM_PHASE];
      if (phase == COMMAND_STREAM_CIPHERTEXT) {
        cursor = processRejectedCiphertext(apdu, cursor, end, work, workOffset);
        continue;
      }

      byte value = apdu[cursor++];
      if (phase == COMMAND_STREAM_ENCRYPTED_TAG) {
        requireStreamByte(value, TAG_ENCRYPTED_DATA);
        updateCommandStreamMac(apdu, (short) (cursor - 1));
        commandStreamState[OFFSET_COMMAND_STREAM_PHASE] = COMMAND_STREAM_LENGTH;
      } else if (phase == COMMAND_STREAM_LENGTH) {
        // SP 800-73-5 uses BER definite lengths. This parser accepts the forms needed for the
        // APDU-size range: one short-form byte, 81, or 82. Each must be the shortest coding, the
        // rule TLV.valueLengthOrInvalid applies to every buffered command (ISO/IEC 7816-4
        // Section 6.3 "recommends to use the shortest possible coding of the length field,
        // according to DER encoding rules").
        updateCommandStreamMac(apdu, (short) (cursor - 1));
        short unsigned = (short) (value & (short) 0x00FF);
        if (unsigned < (short) 0x80) {
          startRejectedEncryptedValue(unsigned);
        } else if (unsigned == (short) 0x81 || unsigned == (short) 0x82) {
          commandStreamState[OFFSET_COMMAND_STREAM_LENGTH_BYTES] =
              (short) (unsigned & (short) 0x0003);
          commandStreamState[OFFSET_COMMAND_STREAM_VALUE_LENGTH] = (short) 0;
          commandStreamState[OFFSET_COMMAND_STREAM_PHASE] = COMMAND_STREAM_LONG_LENGTH;
        } else {
          ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
        }
      } else if (phase == COMMAND_STREAM_LONG_LENGTH) {
        updateCommandStreamMac(apdu, (short) (cursor - 1));
        short current = commandStreamState[OFFSET_COMMAND_STREAM_VALUE_LENGTH];
        short remaining = commandStreamState[OFFSET_COMMAND_STREAM_LENGTH_BYTES];
        short octet = (short) (value & (short) 0x00FF);
        // The first subsequent octet decides minimality, as in TLV.valueLengthOrInvalid: 81 must
        // encode at least 80, and 82 at least 0100 while remaining a non-negative short, so its
        // first octet lies in 01..7F. A zero first octet is rejected, so current is zero only
        // while the first subsequent octet is being read.
        if (current == (short) 0) {
          boolean minimal;
          if (remaining == (short) 1) {
            minimal = octet > TLV.LENGTH_1BYTE_MAX;
          } else {
            minimal = octet != (short) 0 && octet <= TLV.LENGTH_1BYTE_MAX;
          }
          if (!minimal) ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
        }
        current = (short) ((short) (current << 8) | octet);
        commandStreamState[OFFSET_COMMAND_STREAM_VALUE_LENGTH] = current;
        remaining = (short) (remaining - (short) 1);
        commandStreamState[OFFSET_COMMAND_STREAM_LENGTH_BYTES] = remaining;
        if (remaining == (short) 0) startRejectedEncryptedValue(current);
      } else if (phase == COMMAND_STREAM_PADDING_INDICATOR) {
        // Section 4.2.2 defines 01 as the padding-content indicator in object 87.
        requireStreamByte(value, PADDING_INDICATOR);
        updateCommandStreamMac(apdu, (short) (cursor - 1));
        buildIv(false, responseIv, (short) 0);
        crypto.doAesCbcDecryptInit(skEnc, responseIv, (short) 0, LENGTH_BLOCK);
        commandStreamState[OFFSET_COMMAND_STREAM_PHASE] = COMMAND_STREAM_CIPHERTEXT;
      } else if (phase == COMMAND_STREAM_AFTER_ENCRYPTED) {
        // Object 97 is optional. Object 8E is mandatory and must be last.
        if (value == TAG_LE) {
          updateCommandStreamMac(apdu, (short) (cursor - 1));
          commandStreamState[OFFSET_COMMAND_STREAM_PHASE] = COMMAND_STREAM_LE_LENGTH;
        } else {
          requireStreamByte(value, TAG_MAC);
          commandStreamState[OFFSET_COMMAND_STREAM_PHASE] = COMMAND_STREAM_MAC_LENGTH;
        }
      } else if (phase == COMMAND_STREAM_LE_LENGTH) {
        requireStreamByte(value, (byte) 0x01);
        updateCommandStreamMac(apdu, (short) (cursor - 1));
        commandStreamState[OFFSET_COMMAND_STREAM_PHASE] = COMMAND_STREAM_LE_VALUE;
      } else if (phase == COMMAND_STREAM_LE_VALUE) {
        requireStreamByte(value, (byte) 0x00);
        updateCommandStreamMac(apdu, (short) (cursor - 1));
        commandStreamState[OFFSET_COMMAND_STREAM_PHASE] = COMMAND_STREAM_MAC_TAG;
      } else if (phase == COMMAND_STREAM_MAC_TAG) {
        requireStreamByte(value, TAG_MAC);
        commandStreamState[OFFSET_COMMAND_STREAM_PHASE] = COMMAND_STREAM_MAC_LENGTH;
      } else if (phase == COMMAND_STREAM_MAC_LENGTH) {
        requireStreamByte(value, (byte) LENGTH_SHORT_MAC);
        commandStreamState[OFFSET_COMMAND_STREAM_MAC_LENGTH] = (short) 0;
        commandStreamState[OFFSET_COMMAND_STREAM_PHASE] = COMMAND_STREAM_MAC_VALUE;
      } else if (phase == COMMAND_STREAM_MAC_VALUE) {
        short macLength = commandStreamState[OFFSET_COMMAND_STREAM_MAC_LENGTH];
        commandStreamMac[macLength++] = value;
        commandStreamState[OFFSET_COMMAND_STREAM_MAC_LENGTH] = macLength;
        if (macLength == LENGTH_SHORT_MAC) {
          commandStreamState[OFFSET_COMMAND_STREAM_PHASE] = COMMAND_STREAM_COMPLETE;
        }
      } else {
        ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
      }
    }

    if (!finalFrame) {
      // A complete protected command cannot be followed by another chained frame.
      if (commandStreamState[OFFSET_COMMAND_STREAM_PHASE] == COMMAND_STREAM_COMPLETE) {
        ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
      }
      return false;
    }
    if (commandStreamState[OFFSET_COMMAND_STREAM_PHASE] != COMMAND_STREAM_COMPLETE) {
      ISOException.throwIt(SW_SM_EXPECTED_OBJECTS_MISSING);
    }

    crypto.doAesCmacFinal(work, workOffset, (short) 0, work, workOffset);
    // Do not report padding validity until the C-MAC is valid. This ordering prevents a padding
    // oracle and follows Section 4.2.3 command-authentication processing.
    if (!PIVSecurityProvider.arrayEqualsConstantTime(
        work, workOffset, commandStreamMac, (short) 0, LENGTH_SHORT_MAC)) {
      ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
    }
    if (commandStreamState[OFFSET_COMMAND_STREAM_PADDING_VALID] == (short) 0) {
      ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
    }

    Util.arrayCopyNonAtomic(work, workOffset, commandMcv, (short) 0, LENGTH_BLOCK);
    state[OFFSET_LAST_CLA] = apdu[ISO7816.OFFSET_CLA];
    state[OFFSET_LAST_INS] = apdu[ISO7816.OFFSET_INS];
    clearRejectedCommandStream();
    return true;
  }

  /**
   * Starts incremental C-MAC processing for a rejected logical command.
   *
   * <p>SP 800-73-5 Part 2, Section 4.2.3 authenticates the current MCV followed by the padded
   * command header and protected data objects. INS, P1, and P2 are retained so later fragments
   * cannot change the command being authenticated.
   *
   * @param apdu first APDU fragment
   * @param work scratch buffer for the padded command header
   * @param workOffset first scratch-buffer byte
   */
  private void beginRejectedCommandStream(byte[] apdu, byte[] work, short workOffset) {
    commandStreamHeader[(short) 0] = apdu[ISO7816.OFFSET_INS];
    commandStreamHeader[(short) 1] = apdu[ISO7816.OFFSET_P1];
    commandStreamHeader[(short) 2] = apdu[ISO7816.OFFSET_P2];
    commandStreamState[OFFSET_COMMAND_STREAM_PHASE] = COMMAND_STREAM_ENCRYPTED_TAG;
    buildPaddedCommandHeader(apdu, work, workOffset);
    crypto.doAesCmacInit(skMac);
    crypto.doAesCmacUpdate(commandMcv, (short) 0, LENGTH_BLOCK);
    crypto.doAesCmacUpdate(work, workOffset, LENGTH_BLOCK);
  }

  /**
   * Validates the length of secure-messaging object 87 and starts ciphertext processing.
   *
   * <p>SP 800-73-5 Part 2, Section 4.2.2 requires a one-byte padding indicator followed by one or
   * more complete AES blocks.
   *
   * @param valueLength complete object 87 value length
   * @throws ISOException if the value cannot contain the indicator and complete ciphertext blocks
   */
  private void startRejectedEncryptedValue(short valueLength) {
    // The value contains one indicator byte and one or more complete AES blocks.
    if (valueLength < (short) 17
        || (short) ((short) (valueLength - (short) 1) % LENGTH_BLOCK) != (short) 0) {
      ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
    }
    commandStreamState[OFFSET_COMMAND_STREAM_VALUE_LENGTH] = valueLength;
    commandStreamState[OFFSET_COMMAND_STREAM_CIPHER_REMAINING] = (short) (valueLength - (short) 1);
    commandStreamState[OFFSET_COMMAND_STREAM_PHASE] = COMMAND_STREAM_PADDING_INDICATOR;
  }

  /**
   * Authenticates ciphertext and decrypts it one block at a time.
   *
   * <p>The method keeps a partial ciphertext block across APDU boundaries. It records the final
   * padding result but does not expose that result until command-MAC verification succeeds.
   *
   * @param apdu current APDU buffer
   * @param cursor first unconsumed ciphertext octet
   * @param end exclusive fragment end
   * @param work scratch buffer for one plaintext block
   * @param workOffset first scratch-buffer byte
   * @return first unconsumed APDU offset
   */
  private short processRejectedCiphertext(
      byte[] apdu, short cursor, short end, byte[] work, short workOffset) {
    short remaining = commandStreamState[OFFSET_COMMAND_STREAM_CIPHER_REMAINING];
    short available = (short) (end - cursor);
    short consumed = available < remaining ? available : remaining;
    short consumedEnd = (short) (cursor + consumed);
    crypto.doAesCmacUpdate(apdu, cursor, consumed);

    while (cursor < consumedEnd) {
      short blockLength = commandStreamState[OFFSET_COMMAND_STREAM_BLOCK_LENGTH];
      short copyLength = (short) (LENGTH_BLOCK - blockLength);
      short sourceRemaining = (short) (consumedEnd - cursor);
      if (copyLength > sourceRemaining) copyLength = sourceRemaining;
      Util.arrayCopyNonAtomic(apdu, cursor, commandStreamBlock, blockLength, copyLength);
      cursor = (short) (cursor + copyLength);
      blockLength = (short) (blockLength + copyLength);
      remaining = (short) (remaining - copyLength);
      commandStreamState[OFFSET_COMMAND_STREAM_BLOCK_LENGTH] = blockLength;
      commandStreamState[OFFSET_COMMAND_STREAM_CIPHER_REMAINING] = remaining;

      if (blockLength == LENGTH_BLOCK) {
        short plainLength;
        if (remaining == (short) 0) {
          // Only the last block can contain Section 4.2.2 padding.
          plainLength =
              crypto.doAesCbcDecryptFinal(
                  commandStreamBlock, (short) 0, LENGTH_BLOCK, work, workOffset);
          commandStreamState[OFFSET_COMMAND_STREAM_PADDING_VALID] =
              hasValidPadding(work, workOffset, plainLength) ? (short) 1 : (short) 0;
          commandStreamState[OFFSET_COMMAND_STREAM_PHASE] = COMMAND_STREAM_AFTER_ENCRYPTED;
        } else {
          // The scratch block is overwritten by the next decrypted block and is never retained.
          plainLength =
              crypto.doAesCbcDecryptUpdate(
                  commandStreamBlock, (short) 0, LENGTH_BLOCK, work, workOffset);
        }
        if (plainLength != LENGTH_BLOCK) ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
        commandStreamState[OFFSET_COMMAND_STREAM_BLOCK_LENGTH] = (short) 0;
      }
    }
    return cursor;
  }

  /**
   * Adds one parsed protected-object octet to the incremental command C-MAC.
   *
   * @param buffer source buffer
   * @param offset source-octet offset
   */
  private void updateCommandStreamMac(byte[] buffer, short offset) {
    crypto.doAesCmacUpdate(buffer, offset, (short) 1);
  }

  /**
   * Requires an exact structural octet for the current protected-object parser phase.
   *
   * @throws ISOException with {@link #SW_SM_OBJECTS_INCORRECT} if the octet does not match
   */
  private void requireStreamByte(byte actual, byte expected) {
    if (actual != expected) ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
  }

  /**
   * Validates SP 800-73-5 Part 2, Section 4.2.2 command padding.
   *
   * <p>The required value is {@code 0x80} followed only by zero octets through the block end. The
   * scan runs from the end so plaintext length is not needed before C-MAC verification.
   *
   * @param buffer decrypted final block
   * @param offset first plaintext octet
   * @param length plaintext length
   * @return {@code true} only for a correctly padded block
   */
  private boolean hasValidPadding(byte[] buffer, short offset, short length) {
    return paddingStart(buffer, offset, length) >= offset;
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
    byte expectedTag = TAG_ENCRYPTED_DATA;

    // Any malformed, duplicated, misordered or unknown secure messaging data object in the
    // command data field is "secure messaging data objects are incorrect": '69 88' per NIST
    // SP 800-73-5 Part 2 Section 4.2.7.
    while (cursor < end) {
      byte tag = apdu[cursor];
      // Section 4.2.7 maps malformed protected objects to 6988. Parse within this command's
      // actual slice, never the unused tail of the larger APDU/reassembly buffer.
      short tlvLength = TLV.readLength(apdu, cursor, end);
      short valueOffset = TLV.dataOffset(apdu, cursor, end);
      short next = TLV.objectEnd(apdu, cursor, end);

      if (tag == TAG_ENCRYPTED_DATA) {
        if (expectedTag != TAG_ENCRYPTED_DATA) ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
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
        expectedTag = TAG_LE;
      } else if (tag == TAG_LE) {
        if (expectedTag == TAG_MAC) ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
        if (tlvLength != (short) 1 || apdu[valueOffset] != (byte) 0x00) {
          ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
        }
        expectedTag = TAG_MAC;
      } else if (tag == TAG_MAC) {
        if (macTlvOffset != (short) -1 || tlvLength != LENGTH_SHORT_MAC || next != end) {
          ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
        }
        macTlvOffset = cursor;
        macValueOffset = valueOffset;
        expectedTag = (byte) 0;
      } else {
        ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
      }

      cursor = next;
    }

    // NIST SP 800-73-5 Part 2 Section 4.2.7 requires returning '69 87' if expected secure
    // messaging data objects (like tag '8E' for C-MAC) are missing.
    if (macTlvOffset == (short) -1) ISOException.throwIt(SW_SM_EXPECTED_OBJECTS_MISSING);

    // Verify C-MAC (NIST SP 800-73-5 Part 2 Section 4.2.3). The command body can be
    // almost as large as the shared APDU work buffer, so feed CMAC incrementally instead of
    // staging MCV || padded-header || body in smResponse.
    buildPaddedCommandHeader(apdu, work, workOffset);
    crypto.doAesCmacInit(skMac);
    crypto.doAesCmacUpdate(commandMcv, (short) 0, LENGTH_BLOCK);
    crypto.doAesCmacUpdate(work, workOffset, LENGTH_BLOCK);
    crypto.doAesCmacFinal(apdu, offset, (short) (macTlvOffset - offset), work, workOffset);
    if (!PIVSecurityProvider.arrayEqualsConstantTime(
        work, workOffset, apdu, macValueOffset, LENGTH_SHORT_MAC)) {
      // A C-MAC ('8E') that fails verification is an incorrect secure messaging data object:
      // '69 88' per NIST SP 800-73-5 Part 2 Section 4.2.7. ('69 82' is reserved for secure
      // messaging requested before session keys are established - Section 4.2.7 footnote.)
      ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
    }
    // Update MAC chaining value (MCV) per Section 4.2
    Util.arrayCopyNonAtomic(work, workOffset, commandMcv, (short) 0, LENGTH_BLOCK);

    boolean protectedGetResponse = apdu[ISO7816.OFFSET_INS] == INS_GET_RESPONSE;
    if (!protectedGetResponse) {
      state[OFFSET_LAST_CLA] = apdu[ISO7816.OFFSET_CLA];
      state[OFFSET_LAST_INS] = apdu[ISO7816.OFFSET_INS];
    }
    apdu[ISO7816.OFFSET_CLA] = (byte) (apdu[ISO7816.OFFSET_CLA] & (byte) 0xF3);

    if (encryptedTlvOffset == (short) -1) return (short) 0;

    // Decrypt command data (NIST SP 800-73-5 Part 2 Section 4.2.2). Do not decrypt in-place
    // into an overlapping lower APDU offset; Java Card cipher providers are not required to
    // preserve CBC chaining material when input and output partially overlap.
    buildIv(false, responseIv, (short) 0);
    short plainLength =
        crypto.doAesCbcDecrypt(
            skEnc,
            responseIv,
            (short) 0,
            LENGTH_BLOCK,
            apdu,
            encryptedValueOffset,
            encryptedValueLength,
            work,
            workOffset);
    plainLength = stripPadding(work, workOffset, plainLength);
    Util.arrayCopyNonAtomic(work, workOffset, apdu, offset, plainLength);
    return plainLength;
  }

  void beginResponseStream(short plaintextLength, short sw) {
    crypto.requireAesCmac(SW_SM_NOT_SUPPORTED);
    clearResponseState();
    responseState[OFFSET_RESPONSE_SW] = sw;
    responseState[OFFSET_RESPONSE_PLAIN_REMAINING] = plaintextLength;

    crypto.doAesResponseCmacInit(skRmac);
    crypto.doAesResponseCmacUpdate(responseMcv, (short) 0, LENGTH_BLOCK);

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
    // Ne bounds the chunk only from above: an extended Le larger than the response work buffer
    // yields a full buffer and '61 XX', and the host retrieves the rest with GET RESPONSE
    // (SP 800-73-5 Part 2 Section 4.2.6).
    short capacity = (short) (out.length - outOffset);
    if (maxLength < (short) 0 || maxLength > capacity) maxLength = capacity;
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

  boolean isResponseStreamActive() {
    return responseState[OFFSET_RESPONSE_PHASE] != RESPONSE_PHASE_NONE;
  }

  /**
   * Abandons an incomplete protected response without publishing its undelivered R-MAC.
   *
   * <p>The encryption counter belongs to the original logical command, so interruption advances it
   * once under the same rule as normal completion. Session keys and the last delivered R-MCV are
   * retained for the next protected command.
   */
  void abortResponseStream() {
    if (!isResponseStreamActive()) return;
    if (shouldIncrementCounter()) incrementCounter();
    clearResponseState();
  }

  short getResponseStreamStatusWord() {
    if (isResponseStreamComplete()) return ISO7816.SW_NO_ERROR;

    return ChainBuffer.bytesRemainingStatusWord(remainingResponseStreamBytes());
  }

  private void buildPaddedCommandHeader(byte[] apdu, byte[] out, short outOffset) {
    short cursor = outOffset;
    out[cursor++] = CLA_SECURE_MESSAGING;
    out[cursor++] = apdu[ISO7816.OFFSET_INS];
    out[cursor++] = apdu[ISO7816.OFFSET_P1];
    out[cursor++] = apdu[ISO7816.OFFSET_P2];
    out[cursor++] = PADDING_DELIMITER;
    Util.arrayFillNonAtomic(out, cursor, (short) 11, (byte) 0);
  }

  private short writeResponseHeader(byte[] out, short cursor, short end) {
    short encryptedValueLength = (short) (responseState[OFFSET_RESPONSE_PADDED_LENGTH] + (short) 1);
    short headerLength = responseHeaderLength(encryptedValueLength);
    responseTail[(short) 0] = TAG_ENCRYPTED_DATA;
    short lengthSize = TLV.writeLength(responseTail, (short) 1, encryptedValueLength);
    responseTail[(short) (1 + lengthSize)] = PADDING_INDICATOR;
    while (cursor < end && responseState[OFFSET_RESPONSE_PHASE_OFFSET] < headerLength) {
      short index = responseState[OFFSET_RESPONSE_PHASE_OFFSET];
      out[cursor] = responseTail[index];
      crypto.doAesResponseCmacUpdate(out, cursor, (short) 1);
      cursor++;
      responseState[OFFSET_RESPONSE_PHASE_OFFSET]++;
    }

    if (responseState[OFFSET_RESPONSE_PHASE_OFFSET] == headerLength) {
      responseState[OFFSET_RESPONSE_PHASE_OFFSET] = (short) 0;
      responseState[OFFSET_RESPONSE_PHASE] = RESPONSE_PHASE_DATA;
    }

    return cursor;
  }

  private short responseHeaderLength(short encryptedValueLength) {
    return (short) (TLV.encodedLengthSize(encryptedValueLength) + (short) 2);
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
      responseBlock[paddingOffset++] = PADDING_DELIMITER;
      responseState[OFFSET_RESPONSE_PADDING_REMAINING]--;
      short zeroes = (short) (LENGTH_BLOCK - paddingOffset);
      Util.arrayFillNonAtomic(responseBlock, paddingOffset, zeroes, (byte) 0);
      responseState[OFFSET_RESPONSE_PADDING_REMAINING] =
          (short) (responseState[OFFSET_RESPONSE_PADDING_REMAINING] - zeroes);
    }

    for (short index = (short) 0; index < LENGTH_BLOCK; index++) {
      responseBlock[index] ^= responseIv[index];
    }

    crypto.doAesEcbEncrypt(skEnc, responseBlock, (short) 0, LENGTH_BLOCK, responseBlock, (short) 0);
    Util.arrayCopyNonAtomic(responseBlock, (short) 0, responseIv, (short) 0, LENGTH_BLOCK);
    crypto.doAesResponseCmacUpdate(responseBlock, (short) 0, LENGTH_BLOCK);
  }

  private void prepareFinalResponseTail() {
    responseTail[(short) 0] = TAG_STATUS;
    responseTail[(short) 1] = (byte) 2;
    Util.setShort(responseTail, (short) 2, responseState[OFFSET_RESPONSE_SW]);
    // Keep the candidate R-MCV private until every response byte has been delivered. If response
    // chaining is interrupted, the host never received this MAC and must continue from the prior
    // delivered R-MCV.
    crypto.doAesResponseCmacFinal(
        responseTail, (short) 0, (short) 4, responseCandidateMcv, (short) 0);
    responseTail[(short) 4] = TAG_MAC;
    responseTail[(short) 5] = (byte) LENGTH_SHORT_MAC;
    Util.arrayCopyNonAtomic(
        responseCandidateMcv, (short) 0, responseTail, (short) 6, LENGTH_SHORT_MAC);
    responseState[OFFSET_RESPONSE_PHASE_OFFSET] = (short) 0;
    responseState[OFFSET_RESPONSE_PHASE] = RESPONSE_PHASE_FINAL;
  }

  private short writeResponseTail(byte[] out, short cursor, short end) {
    while (cursor < end && responseState[OFFSET_RESPONSE_PHASE_OFFSET] < (short) 14) {
      out[cursor++] = responseTail[responseState[OFFSET_RESPONSE_PHASE_OFFSET]++];
    }

    if (responseState[OFFSET_RESPONSE_PHASE_OFFSET] == (short) 14) {
      Util.arrayCopyNonAtomic(
          responseCandidateMcv, (short) 0, responseMcv, (short) 0, LENGTH_BLOCK);
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
    Util.arrayCopyNonAtomic(encCounter, (short) 0, responseBlock, (short) 0, LENGTH_BLOCK);
    if (response) responseBlock[0] = (byte) (responseBlock[0] | (byte) 0x80);
    crypto.doAesEcbEncrypt(skEnc, responseBlock, (short) 0, LENGTH_BLOCK, out, outOffset);
  }

  private short stripPadding(byte[] buffer, short offset, short length) {
    // Invalid ISO 7816-4 padding in the recovered plaintext means the '87' encrypted-data
    // object was incorrect: '69 88' per NIST SP 800-73-5 Part 2 Section 4.2.7.
    short cursor = paddingStart(buffer, offset, length);
    if (cursor >= offset) return (short) (cursor - offset);
    ISOException.throwIt(SW_SM_OBJECTS_INCORRECT);
    return (short) 0;
  }

  /** Section 4.2.2 permits exactly 1..16 padding octets, confined to the final AES block. */
  private short paddingStart(byte[] buffer, short offset, short length) {
    short cursor = (short) (offset + length - 1);
    short lower = length > LENGTH_BLOCK ? (short) (offset + length - LENGTH_BLOCK) : offset;
    while (cursor >= lower) {
      if (buffer[cursor] == PADDING_DELIMITER) return cursor;
      if (buffer[cursor] != (byte) 0) return (short) -1;
      cursor--;
    }
    return (short) -1;
  }

  private short paddedLength(short length) {
    return (short) (length + (short) (LENGTH_BLOCK - (short) (length % LENGTH_BLOCK)));
  }

  /**
   * Checks whether the encryption counter should be incremented.
   *
   * <p>NIST SP 800-73-5 Part 2 Section 4.2.2 requires the encryption counter to be incremented once
   * per completed logical secure-messaging command, except chained '1C' commands. Plaintext GET
   * RESPONSE frames only transport the already-computed protected response stream.
   */
  private boolean shouldIncrementCounter() {
    return state[OFFSET_LAST_CLA] != CLA_CHAINED_SECURE_MESSAGING;
  }

  private void incrementCounter() {
    for (short i = (short) 15; i >= (short) 0; i--) {
      encCounter[i]++;
      if (encCounter[i] != (byte) 0) return;
    }
  }

  private void clearResponseState() {
    for (short index = (short) 0; index < LENGTH_RESPONSE_STATE; index++) {
      responseState[index] = (short) 0;
    }
    Util.arrayFillNonAtomic(responseCandidateMcv, (short) 0, LENGTH_BLOCK, (byte) 0);
    Util.arrayFillNonAtomic(responseIv, (short) 0, LENGTH_BLOCK, (byte) 0);
    Util.arrayFillNonAtomic(responseBlock, (short) 0, LENGTH_BLOCK, (byte) 0);
    Util.arrayFillNonAtomic(responseTail, (short) 0, (short) responseTail.length, (byte) 0);
  }
}
