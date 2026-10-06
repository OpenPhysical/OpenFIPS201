/******************************************************************************
 * MIT License
 *
 * Project: OpenPhysical Issuer SAM
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

package dev.mistial.openphysical.sam;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Minimal ISO/IEC 7816-4 command chaining into the I/O buffer and outgoing response chaining from
 * it.
 *
 * <p>Incoming: ISO/IEC 7816-4 Section 5.1.1.1 command chaining accumulates the data fields of
 * consecutive frames of one command. A chain is bound to its INS, P1-P2 and to the protection of
 * its first frame: a frame with different protection abandons the chain with {@link
 * ISO7816#SW_SECURITY_STATUS_NOT_SATISFIED}, so a sensitive payload cannot be completed after a
 * secure-channel downgrade. All context is CLEAR_ON_DESELECT.
 *
 * <p>Outgoing: a response that exceeds Ne is returned in Ne-sized blocks with {@code 61xx}; GET
 * RESPONSE continues it and any other command abandons it.
 */
final class ApduChain {
  private static final short IN_ACTIVE = (short) 0;
  private static final short IN_INS = (short) 1;
  private static final short IN_P1P2 = (short) 2;
  private static final short IN_PROTECTED = (short) 3;
  private static final short IN_STAGE = (short) 4;
  private static final short IN_LENGTH = (short) 5;
  private static final short IN_LIMIT = (short) 6;
  private static final short OUT_ACTIVE = (short) 7;
  private static final short OUT_OFFSET = (short) 8;
  private static final short OUT_REMAINING = (short) 9;
  private static final short LENGTH_CONTEXT = (short) 10;

  private static final short TRUE = (short) 1;
  private static final short SHORT_RESPONSE_MAX = (short) 256;

  private final byte[] io;
  private final short[] context;

  ApduChain(byte[] io) {
    this.io = io;
    context = JCSystem.makeTransientShortArray(LENGTH_CONTEXT, JCSystem.CLEAR_ON_DESELECT);
  }

  void abortIncoming() {
    context[IN_ACTIVE] = (short) 0;
    context[IN_LENGTH] = (short) 0;
  }

  void abortOutgoing() {
    context[OUT_ACTIVE] = (short) 0;
    context[OUT_REMAINING] = (short) 0;
  }

  /** Returns true when a chain is pending for a different INS than {@code ins}. */
  boolean isIncomingForOther(byte ins) {
    return context[IN_ACTIVE] == TRUE && context[IN_INS] != (short) (ins & 0xFF);
  }

  /**
   * Appends one frame of a possibly chained command to the I/O buffer.
   *
   * @param ins instruction of this frame
   * @param p1p2 P1-P2 of this frame
   * @param protectedFrame whether this frame was unwrapped from an authenticated secure channel
   * @param more whether the chaining bit was set (further frames follow)
   * @param data source of this frame's data field
   * @param offset data offset
   * @param length data length
   * @param stage I/O buffer offset at which the command data is assembled
   * @param limit maximum assembled length
   * @return the assembled length at {@code stage} when this frame completes the command, or -1 when
   *     further frames are expected
   */
  short append(
      byte ins,
      short p1p2,
      boolean protectedFrame,
      boolean more,
      byte[] data,
      short offset,
      short length,
      short stage,
      short limit) {
    short protection = protectedFrame ? TRUE : (short) 0;
    if (context[IN_ACTIVE] == TRUE) {
      if (context[IN_INS] != (short) (ins & 0xFF)
          || context[IN_P1P2] != p1p2
          || context[IN_STAGE] != stage) {
        abortIncoming();
      } else if (context[IN_PROTECTED] != protection) {
        abortIncoming();
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }
    }
    if (context[IN_ACTIVE] != TRUE) {
      context[IN_INS] = (short) (ins & 0xFF);
      context[IN_P1P2] = p1p2;
      context[IN_PROTECTED] = protection;
      context[IN_STAGE] = stage;
      context[IN_LIMIT] = limit;
      context[IN_LENGTH] = (short) 0;
      context[IN_ACTIVE] = TRUE;
    }
    short current = context[IN_LENGTH];
    if (length < (short) 0 || length > (short) (context[IN_LIMIT] - current)) {
      abortIncoming();
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    Util.arrayCopyNonAtomic(data, offset, io, (short) (stage + current), length);
    current += length;
    if (more) {
      context[IN_LENGTH] = current;
      return (short) -1;
    }
    abortIncoming();
    return current;
  }

  /** Starts sending {@code io[offset..offset+length)}. */
  void send(APDU apdu, short offset, short length) {
    context[OUT_OFFSET] = offset;
    context[OUT_REMAINING] = length;
    context[OUT_ACTIVE] = TRUE;
    sendNext(apdu);
  }

  /** Sends the next block of the pending response (GET RESPONSE), or 6985 when none is pending. */
  void sendNext(APDU apdu) {
    if (context[OUT_ACTIVE] != TRUE) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    short remaining = context[OUT_REMAINING];
    short offset = context[OUT_OFFSET];
    short ne = apdu.setOutgoing();
    if (ne <= (short) 0) ne = SHORT_RESPONSE_MAX;
    short block = remaining < ne ? remaining : ne;
    apdu.setOutgoingLength(block);
    apdu.sendBytesLong(io, offset, block);
    remaining -= block;
    if (remaining == (short) 0) {
      abortOutgoing();
      return;
    }
    context[OUT_OFFSET] = (short) (offset + block);
    context[OUT_REMAINING] = remaining;
    ISOException.throwIt(
        (short)
            (ISO7816.SW_BYTES_REMAINING_00 | (remaining > (short) 0xFF ? (short) 0 : remaining)));
  }
}
