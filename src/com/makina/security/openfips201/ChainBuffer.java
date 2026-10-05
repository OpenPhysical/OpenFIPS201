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

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * ChainBuffer supports reading and writing of buffers larger than a single APDU frame. It takes
 * away the responsibility of dealing with the actual read and write operations, state management
 * and transaction management from the APDU processing functions. Instead each function that needs
 * to support chained reads or writes simply calls this method with a buffer to act on and
 * ChainBuffer will do the rest.
 */
final class ChainBuffer {

  // The chain context is inactive and buffer does not point to anything
  static final short STATE_NONE = (short) 0x00;

  // The chain context is reading (supporting multiple GET RESPONSE commands)
  static final short STATE_OUTGOING = (short) 0x01;

  // The chain context is writing (supporting chained commands of whatever INS started it)
  static final short STATE_INCOMING_OBJECT = (short) 0x02;

  // The chain context is writing (supporting chained commands of whatever INS started it)
  static final short STATE_INCOMING_APDU = (short) 0x03;

  // The chain state
  private static final short CONTEXT_STATE = (short) 0;

  // The current offset in the data buffer
  private static final short CONTEXT_OFFSET = (short) 1;

  // The initial offset in the data buffer that was supplied by the caller
  private static final short CONTEXT_INITIAL = (short) 2;

  // The total length of the data buffer
  private static final short CONTEXT_LENGTH = (short) 3;

  // The number of remaining bytes to write or read in the buffer
  private static final short CONTEXT_REMAINING = (short) 4;

  // Indicates whether the buffer should be wiped on completion of the chain
  private static final short CONTEXT_CLEAR_ON_COMPLETE = (short) 5;

  private static final short CONTEXT_SECURE_OUTGOING = (short) 6;

  // The APDU header used for tracking incoming data: CLA (with the chaining bit cleared) and INS
  // as one short, then P1 and P2 as one short. ISO/IEC 7816-4 Section 5.3.3: "All CLA bytes of the
  // commands shall be the same, except for bit b5" and "All INS P1 P2 bytes of the commands shall
  // be the same."
  private static final short CONTEXT_APDU_CLA_INS = (short) 7;
  private static final short CONTEXT_APDU_P1P2 = (short) 8;
  private static final short CONTEXT_PROTECTION = (short) 9;

  // Total length of the context transient object
  private static final short LENGTH_CONTEXT = (short) 10;

  static final byte PROTECTION_PLAIN = (byte) 0;
  static final byte PROTECTION_PIV_SM = (byte) 1;
  static final byte PROTECTION_SCP = (byte) 2;

  // APDU constants
  static final byte CLA_CHAINING = (byte) 0x10;
  // Clears the CLA chaining bit in the CLA/INS short read from ISO7816.OFFSET_CLA
  private static final short CLA_INS_CHAINING_MASK = (short) 0xEFFF;
  private static final byte INS_GET_RESPONSE = OpenFIPS201.INS_GP_GET_RESPONSE;

  // A pointer to our read/write data buffer
  private final Object[] dataPtr;
  private final Object[] ownerPtr;

  // Holds transient context information about the current chain
  private final short[] context;

  ChainBuffer() {
    dataPtr = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
    ownerPtr = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
    context = JCSystem.makeTransientShortArray(LENGTH_CONTEXT, JCSystem.CLEAR_ON_DESELECT);

    reset();
  }

  /**
   * Discards an incomplete command chain and its staged object update.
   *
   * <p>ISO/IEC 7816-4 command chaining treats an interrupted chain as incomplete. The applet also
   * aborts any staged object update so the incomplete logical command is not published.
   */
  void abort() {
    reset();
  }

  /** Resets the ChainBuffer, publishing any staged object update */
  private void resetCommit() {

    if (ownerPtr[0] != null) {
      ((PIVDataObject) ownerPtr[0]).commitUpdate();
      ownerPtr[0] = null;
    }

    // Perform a normal reset
    reset();
  }

  /** Resets the ChainBuffer and clears any internal buffer and state tracking values */
  void reset() {

    if (ownerPtr[0] != null) {
      ((PIVDataObject) ownerPtr[0]).abortUpdate();
      ownerPtr[0] = null;
    }

    // Have we been asked to clear the buffer?
    if (dataPtr[0] != null && context[CONTEXT_CLEAR_ON_COMPLETE] != (short) 0) {
      byte[] data = (byte[]) dataPtr[0];
      Util.arrayFillNonAtomic(data, (short) 0, (short) data.length, (byte) 0x00);
    }

    // Burn them... Burn them all
    dataPtr[0] = null;
    context[CONTEXT_STATE] = STATE_NONE;

    context[CONTEXT_OFFSET] = (short) 0;
    context[CONTEXT_INITIAL] = (short) 0;
    context[CONTEXT_REMAINING] = (short) 0;
    context[CONTEXT_LENGTH] = (short) 0;
    context[CONTEXT_CLEAR_ON_COMPLETE] = (short) 0;
    context[CONTEXT_SECURE_OUTGOING] = (short) 0;
    context[CONTEXT_APDU_CLA_INS] = (short) 0;
    context[CONTEXT_APDU_P1P2] = (short) 0;
    context[CONTEXT_PROTECTION] = (short) PROTECTION_PLAIN;
  }

  /** Abandons an incomplete command-data chain when a different command arrives. */
  void checkIncomingAPDU(byte[] apdu) {
    if (context[CONTEXT_STATE] != STATE_INCOMING_APDU) return;
    if (!isSameChainedCommand(apdu)) reset();
  }

  /** Records the CLA (chaining bit cleared), INS, P1 and P2 of the first command of a chain. */
  private void recordChainHeader(byte[] apdu) {
    context[CONTEXT_APDU_CLA_INS] =
        (short) (Util.getShort(apdu, ISO7816.OFFSET_CLA) & CLA_INS_CHAINING_MASK);
    context[CONTEXT_APDU_P1P2] = Util.getShort(apdu, ISO7816.OFFSET_P1);
  }

  /** Returns whether {@code apdu} has the recorded CLA (ignoring bit b5), INS, P1 and P2. */
  private boolean isSameChainedCommand(byte[] apdu) {
    return context[CONTEXT_APDU_CLA_INS]
            == (short) (Util.getShort(apdu, ISO7816.OFFSET_CLA) & CLA_INS_CHAINING_MASK)
        && context[CONTEXT_APDU_P1P2] == Util.getShort(apdu, ISO7816.OFFSET_P1);
  }

  /**
   * Configures the ChainBuffer class to process a stream of outgoing data which will be retrieved
   * by subsequent GET RESPONSE commands
   *
   * @param buffer the buffer to read data from
   * @param offset The starting offset of the data to read from
   * @param length The total number of bytes to read
   * @param clearOnCompletion If true, the entire backing buffer will be wiped when the chain ends
   */
  void setOutgoing(byte[] buffer, short offset, short length, boolean clearOnCompletion) {

    reset();

    dataPtr[0] = buffer;

    context[CONTEXT_STATE] = STATE_OUTGOING;
    context[CONTEXT_OFFSET] = offset;
    context[CONTEXT_INITIAL] = offset;
    context[CONTEXT_REMAINING] = length;
    context[CONTEXT_LENGTH] = length;
    context[CONTEXT_CLEAR_ON_COMPLETE] = clearOnCompletion ? (short) 1 : (short) 0;
  }

  boolean isOutgoingActive() {
    return context[CONTEXT_STATE] == STATE_OUTGOING;
  }

  boolean isSecureOutgoingActive() {
    return isOutgoingActive() && context[CONTEXT_SECURE_OUTGOING] != (short) 0;
  }

  boolean isIncomingApduActive() {
    return context[CONTEXT_STATE] == STATE_INCOMING_APDU;
  }

  /** Abandons only an outgoing response, leaving incoming command chains untouched. */
  void abortOutgoing() {
    if (context[CONTEXT_STATE] == STATE_OUTGOING) {
      reset();
    }
  }

  /**
   * Configures the ChainBuffer class to stream incoming data into the unpublished staging buffer of
   * a data object. The final fragment publishes it ({@link PIVDataObject#commitUpdate()}); an
   * aborted chain discards it ({@link PIVDataObject#abortUpdate()}).
   *
   * @param destination The data object to replace
   * @param length The length to expect to be written
   */
  void setIncomingObject(PIVDataObject destination, short length) {
    reset();
    byte[] staged = destination.beginUpdate(length);
    dataPtr[0] = staged;
    ownerPtr[0] = destination;
    context[CONTEXT_STATE] = STATE_INCOMING_OBJECT;
    context[CONTEXT_OFFSET] = (short) 0;
    context[CONTEXT_REMAINING] = length;
    context[CONTEXT_LENGTH] = length;
  }

  /**
   * Configures the ChainBuffer class to process a large incoming APDU
   *
   * @param apdu The first incoming APDU buffer
   * @param inOffset The starting offset of initial APDU
   * @param inLength The length of the initial APDU
   * @param outBuffer The destination buffer for the large APDU CDATA content
   * @param outOffset The offset to start writing in the destination buffer
   * @return The number of bytes in the command data if complete, otherwise zero to indicate there
   *     is more to come NOTE: The destination will contain only the command data of the APDU, not
   *     the header.
   */
  short processIncomingAPDU(
      byte[] apdu, short inOffset, short inLength, byte[] outBuffer, short outOffset)
      throws ISOException {

    //
    // STATE VALIDATION
    //

    // Make sure that we are not in the middle of some other outstanding operation
    if (context[CONTEXT_STATE] != STATE_NONE && context[CONTEXT_STATE] != STATE_INCOMING_APDU) {
      // We have been called in the middle of another operation. Reset, which discards any staged
      // object update.
      reset();
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    boolean lastCommand = (apdu[ISO7816.OFFSET_CLA] & CLA_CHAINING) == 0;
    boolean chainActive = context[CONTEXT_STATE] == STATE_INCOMING_APDU;

    // A continuation must repeat the header of the first command. checkIncomingAPDU() normally
    // abandons a mismatched chain before this point; a mismatch reaching here is rejected.
    // ISO/IEC 7816-4 Section 5.3.3: "If SW1-SW2 is set to '6883', then the last command of the
    // chain is expected."
    if (chainActive && !isSameChainedCommand(apdu)) {
      reset();
      ISOException.throwIt(ISO7816.SW_LAST_COMMAND_EXPECTED);
    }

    short written = chainActive ? context[CONTEXT_LENGTH] : (short) 0;
    appendFragment(apdu, inOffset, inLength, outBuffer, outOffset, written);
    written += inLength;

    if (lastCommand) {
      // A single-frame command, or the last command of a chain: the command data is complete.
      if (chainActive) reset();
      return written;
    }

    // The first or a middle command of a chain: record the header and wait for more data.
    if (!chainActive) {
      context[CONTEXT_STATE] = STATE_INCOMING_APDU;
      context[CONTEXT_INITIAL] = inOffset;
      recordChainHeader(apdu);
    }
    context[CONTEXT_LENGTH] = written;
    return (short) 0;
  }

  /**
   * Copies one command-data fragment to {@code outBuffer} after the {@code written} bytes already
   * reassembled there.
   *
   * <p>Every reassembly overrun is reported as {@link ISO7816#SW_WRONG_LENGTH}: the logical command
   * carries more data than this applet accepts for it.
   */
  private void appendFragment(
      byte[] apdu,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset,
      short written) {
    short room = (short) ((short) (outBuffer.length - outOffset) - written);
    if (inLength < (short) 0
        || inOffset < (short) 0
        || (short) (inOffset + inLength) < inOffset
        || (short) (inOffset + inLength) > (short) apdu.length
        || outOffset < (short) 0
        || room < (short) 0
        || inLength > room) {
      reset();
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    Util.arrayCopyNonAtomic(apdu, inOffset, outBuffer, (short) (outOffset + written), inLength);
  }

  /**
   * Starts or continues processing of an incoming data stream, which will be written directly to a
   * buffer
   *
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset to read from
   * @param length The length of the data to read
   * @param protection The transport protection used for this frame
   */
  void processIncomingObject(byte[] buffer, short offset, short length, byte protection)
      throws ISOException {

    // Check if we have anything to do
    if (context[CONTEXT_STATE] != STATE_INCOMING_OBJECT) return;

    // This method presumes that setIncomingAndReceive() was previously called if required
    boolean firstFrame = context[CONTEXT_LENGTH] == context[CONTEXT_REMAINING];

    // If we have not written anything, this must be the first command so set the APDU header and
    // bind the logical write to its transport protection.
    if (firstFrame) {
      recordChainHeader(buffer);
      context[CONTEXT_PROTECTION] = (short) protection;
    }

    // Validate that we are chaining for the correct command
    if (!firstFrame && !isSameChainedCommand(buffer)) {

      // Abort the data object write
      reset();

      // Ignore this and let the applet handle as a new APDU
      return;
    }

    // A same-command protection change is a downgrade attempt. Check this after distinguishing an
    // unrelated ISO/IEC 7816-4 command, which first discards the incomplete logical command.
    if (!firstFrame && context[CONTEXT_PROTECTION] != (short) protection) {
      reset();
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // Check if we are chaining or not (we don't use the in-built APDU.isCommandChainingCLA() call
    // because it doesn't always work!
    if ((buffer[ISO7816.OFFSET_CLA] & CLA_CHAINING) != 0) {

      //
      // CASE 0: If the chaining bit is SET, we are writing the first or an intermediary frame
      // 		   and we must not write up to or over the total expected length
      //

      // An empty intermediate frame adds nothing and leaves the chain unchanged. It is a
      // continuation of this logical command, so it must not fall through to command dispatch.
      if (length == 0) ISOException.throwIt(ISO7816.SW_NO_ERROR);

      if (length >= context[CONTEXT_REMAINING]) {
        reset();
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }

      // Write to the data buffer and update our context
      copyIncomingObjectFragment(buffer, offset, length);
      context[CONTEXT_OFFSET] += length;
      context[CONTEXT_REMAINING] -= length;
    } else {

      //
      // CASE 1: If the chaining bit is NOT SET, we must be writing either the last or the only
      // frame
      //		   and we must write exactly up to the length of the data buffer
      //

      if (length == 0) {
        reset();
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }

      // Must be exactly the # of bytes remaining
      if (length != context[CONTEXT_REMAINING]) {
        reset();
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }

      // Write to the data buffer and update our context
      copyIncomingObjectFragment(buffer, offset, length);

      // Clear our context as the chain is now complete
      resetCommit();
    }
    ISOException.throwIt(ISO7816.SW_NO_ERROR);
  }

  private void copyIncomingObjectFragment(byte[] source, short offset, short length) {
    // PIVDataObject receives into unpublished staging. Only its reference swap needs a
    // transaction; atomically copying a large final fragment can exhaust the commit buffer.
    Util.arrayCopyNonAtomic(source, offset, (byte[]) dataPtr[0], context[CONTEXT_OFFSET], length);
  }

  /**
   * Starts or continues processing for an outgoing buffer being transmitted to the host
   *
   * <p>The response is bound to the class family of the command that started it. The initiating
   * command records its transport {@code protection}. GP SCP protects commands only (this applet
   * applies no response MAC or encryption), so every response on this path is plaintext and a
   * plaintext GET RESPONSE (CLA '00' or '80') continues it, whichever class started it. A GP
   * SCP-protected GET RESPONSE continues only a response started under GP SCP; any other GP SCP
   * continuation abandons the response and returns '69 85'.
   *
   * @param apdu The current APDU buffer to transmit with
   * @param protection The transport protection of the current command
   */
  void processOutgoing(APDU apdu, byte protection) throws ISOException {
    byte[] apduBuffer = apdu.getBuffer();
    boolean getResponse = apduBuffer[ISO7816.OFFSET_INS] == INS_GET_RESPONSE;
    if (getResponse) requireGetResponseHeader(apduBuffer);

    // GET RESPONSE is valid only while an outgoing response is pending. Rejecting an idle request
    // exposes a host state error instead of reporting a successful command with no response data.
    // The status matches the protected GET RESPONSE path.
    if (context[CONTEXT_STATE] != STATE_OUTGOING) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    // CASE 0 - If the remaining data is EQUAL TO the total data, ignore the INS
    // CASE 1 - If the remaining data is LESS THAN the total data, look for a GET RESPONSE command
    // (clear if it isn't)
    if (!getResponse && context[CONTEXT_REMAINING] != context[CONTEXT_LENGTH]) {

      // Clear the apdu buffer
      reset();

      // Ignore this and let the applet handle this as a new command
      return;
    }

    if (!getResponse) {
      context[CONTEXT_PROTECTION] = (short) protection;
    } else if (protection != PROTECTION_PLAIN
        && context[CONTEXT_PROTECTION] != (short) protection) {
      reset();
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    //
    // Transmit the next frame up to a maximum of 'LE' bytes
    //

    short le = outgoingLength(apdu);
    short length = (context[CONTEXT_REMAINING] > le) ? le : context[CONTEXT_REMAINING];

    sendOutgoing(apdu, (byte[]) dataPtr[0], context[CONTEXT_OFFSET], length);
    advanceOutgoing(length);

    // If we have nothing left to send, clear our context and return 9000
    ISOException.throwIt(outgoingStatusWord());
  }

  void processOutgoingSecure(APDU apdu, PIVSecureMessaging secureMessaging, byte[] buffer, short sw)
      throws ISOException {

    byte[] apduBuffer = apdu.getBuffer();
    if (apduBuffer[ISO7816.OFFSET_INS] == INS_GET_RESPONSE) requireGetResponseHeader(apduBuffer);
    short plaintextOffset = (short) 0;
    short plaintextRemaining = (short) 0;

    if (context[CONTEXT_STATE] == STATE_OUTGOING) {
      if (apduBuffer[ISO7816.OFFSET_INS] != INS_GET_RESPONSE
          && context[CONTEXT_SECURE_OUTGOING] != (short) 0) {
        reset();
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      plaintextOffset = context[CONTEXT_OFFSET];
      plaintextRemaining = context[CONTEXT_REMAINING];
      if (context[CONTEXT_SECURE_OUTGOING] == (short) 0) {
        secureMessaging.beginResponseStream(plaintextRemaining, sw);
        context[CONTEXT_SECURE_OUTGOING] = (short) 1;
      }
    } else if (context[CONTEXT_STATE] != STATE_NONE) {
      reset();
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    } else {
      if (apduBuffer[ISO7816.OFFSET_INS] == INS_GET_RESPONSE) {
        if (!secureMessaging.isResponseStreamActive()) {
          ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
      } else {
        secureMessaging.beginResponseStream((short) 0, sw);
        context[CONTEXT_SECURE_OUTGOING] = (short) 1;
      }
    }

    short le = outgoingLength(apdu);
    short length =
        secureMessaging.writeResponseStreamChunk(
            context[CONTEXT_STATE] == STATE_OUTGOING ? (byte[]) dataPtr[0] : buffer,
            plaintextOffset,
            buffer,
            (short) 0,
            le);
    short consumed = secureMessaging.getResponseStreamPlaintextConsumed();
    if (consumed > (short) 0) {
      advanceOutgoing(consumed);
    }

    sendOutgoing(apdu, buffer, (short) 0, length);
    short responseSw = secureMessaging.getResponseStreamStatusWord();
    if (secureMessaging.isResponseStreamComplete()) {
      reset();
    }

    ISOException.throwIt(responseSw);
  }

  private short outgoingLength(APDU apdu) {
    short le = apdu.setOutgoing();
    //
    // !! HACK !!
    // Most applets completely ignore this value and so interface developers have gotten lazy about
    // whether or not they include an LE byte when they expect response data.
    // This treats the absence of an LE byte (case 3) as if it were a case 4 byte with LE == '00',
    // which maps to 256 bytes.
    //
    return le == (short) 0 ? OpenFIPS201.MAX_SHORT_APDU_RESPONSE_LENGTH : le;
  }

  private void sendOutgoing(APDU apdu, byte[] buffer, short offset, short length) {
    apdu.setOutgoingLength(length);
    apdu.sendBytesLong(buffer, offset, length);
  }

  private void advanceOutgoing(short length) {
    context[CONTEXT_REMAINING] -= length;
    context[CONTEXT_OFFSET] += length;
  }

  private short outgoingStatusWord() {
    if (context[CONTEXT_REMAINING] == (short) 0) {
      reset();
      return ISO7816.SW_NO_ERROR;
    }
    return bytesRemainingStatusWord(context[CONTEXT_REMAINING]);
  }

  /**
   * Returns '61 XX' for {@code remaining} (greater than zero) response bytes.
   *
   * <p>ISO/IEC 7816-4 Section 5.6: "If SW1 is set to '61', then the process is completed and before
   * issuing any other command, a get response command may be issued with the same CLA and using SW2
   * (number of data bytes still available) as short L e field." A short Le of '00' encodes 256, so
   * 256 or more remaining bytes are reported as '61 00'.
   */
  static short bytesRemainingStatusWord(short remaining) {
    short sw2 = remaining > (short) 0x00FF ? (short) 0x0000 : remaining;
    return (short) (ISO7816.SW_BYTES_REMAINING_00 | sw2);
  }

  /**
   * Rejects a GET RESPONSE whose header is not 'C0 00 00' and abandons the pending response.
   *
   * <p>ISO/IEC 7816-4 Section 5.3.4: "With the exception of the first command APDU of the sequence,
   * all INS P1-P2 bytes of the command APDUs shall be 'C0 00 00' (get response)." Section 11.8.1
   * Table 120 defines P1-P2 as "'0000' (any other value is RFU)".
   */
  private void requireGetResponseHeader(byte[] apduBuffer) {
    if (Util.getShort(apduBuffer, ISO7816.OFFSET_P1) != (short) 0) {
      abortOutgoing();
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
  }
}
