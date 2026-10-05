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
import javacard.framework.Util;

/** Provides functionality for PIV data objects */
final class PIVDataObject extends PIVObject {

  // NOTES:
  // - We deliberately make this public to provide access via ChainBuffer, etc. It isn't good OO
  //   but it's Java Card so we forgive ourselves.
  // - Do NOT use content.length to determine the number of bytes in the content array rather use
  //   getLength().
  byte[] content;
  private byte[] pendingContent;
  private short pendingLength;
  private final boolean fixedCapacity;

  // Indicates the number of bytes currently allocated.  In the case where an object is
  // reallocated with a smaller size this will be less than content.length
  private short bytesAllocated;

  PIVDataObject(byte id, byte modeContact, byte modeContactless, byte adminKey) {
    super(id, modeContact, modeContactless, adminKey, (byte) 0);
    fixedCapacity = false;
  }

  PIVDataObject(
      byte[] idBuffer,
      short idOffset,
      short idLength,
      byte modeContact,
      byte modeContactless,
      byte adminKey) {
    this(idBuffer, idOffset, idLength, modeContact, modeContactless, adminKey, (short) 0);
  }

  PIVDataObject(
      byte[] idBuffer,
      short idOffset,
      short idLength,
      byte modeContact,
      byte modeContactless,
      byte adminKey,
      short capacity) {
    super(idBuffer, idOffset, idLength, modeContact, modeContactless, adminKey, (byte) 0);
    fixedCapacity = capacity > (short) 0;
    if (fixedCapacity) {
      content = new byte[capacity];
      pendingContent = new byte[capacity];
    }
  }

  /**
   * @return the number of bytes allocated in content which may be less than content.length
   */
  short getLength() {
    return bytesAllocated;
  }

  void allocate(short length) throws ISOException {

    if (length <= (short) 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    if (fixedCapacity) {
      if (length > (short) content.length) ISOException.throwIt(ISO7816.SW_FILE_FULL);
      PIVSecurityProvider.zeroise(content, (short) 0, (short) content.length);
      PIVSecurityProvider.zeroise(pendingContent, (short) 0, (short) pendingContent.length);
    } else if (content == null) {
      content = new byte[length];
    } else if (length > (short) content.length) {
      // Try to reclaim the resources and re-allocate. If this fails then this card does not
      // support objection deletion and so we can't write an object greater than the initial size
      if (!JCSystem.isObjectDeletionSupported()) ISOException.throwIt(ISO7816.SW_FILE_FULL);

      clear();
      content = new byte[length];
    } else {
      // Just clear the content object
      Util.arrayFillNonAtomic(content, (short) 0, (short) content.length, (byte) 0x00);
    }
    bytesAllocated = length;
  }

  /**
   * Prepares an inactive persistent buffer for a complete object replacement.
   *
   * <p>The published content remains unchanged until {@link #commitUpdate()}. Retained staging
   * storage is reused whenever the replacement fits; only growth allocates. On platforms without
   * object deletion, growth that cannot be made atomic is rejected.
   *
   * @param length required replacement length
   * @return erased buffer that receives the replacement
   * @throws ISOException if the length is invalid or persistent capacity is insufficient
   */
  byte[] beginUpdate(short length) {
    if (length <= (short) 0) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    abortUpdate();
    if (fixedCapacity) {
      if (length > (short) pendingContent.length) ISOException.throwIt(ISO7816.SW_FILE_FULL);
    } else if (pendingContent != null && length <= (short) pendingContent.length) {
      // The retained staging buffer fits, so the replacement allocates no persistent memory.
      PIVSecurityProvider.zeroise(pendingContent, (short) 0, (short) pendingContent.length);
    } else if (JCSystem.isObjectDeletionSupported()) {
      // Growth: release the smaller retained buffer and allocate the required length.
      if (pendingContent != null) {
        PIVSecurityProvider.zeroise(pendingContent, (short) 0, (short) pendingContent.length);
        pendingContent = null;
        JCSystem.requestObjectDeletion();
      }
      pendingContent = new byte[length];
    } else {
      // Without object deletion the first published length bounds every later replacement.
      if (pendingContent != null || (content != null && length > (short) content.length)) {
        ISOException.throwIt(ISO7816.SW_FILE_FULL);
      }
      pendingContent = new byte[content == null ? length : (short) content.length];
    }
    pendingLength = length;
    return pendingContent;
  }

  /**
   * Publishes the prepared replacement with one transactional reference swap.
   *
   * <p>The previously published buffer becomes the staging buffer for the next replacement, so
   * updates that fit allocate no persistent memory. Bulk erasure occurs after the transaction to
   * keep transaction-log use bounded.
   */
  void commitUpdate() {
    byte[] previous = content;
    JCSystem.beginTransaction();
    content = pendingContent;
    bytesAllocated = pendingLength;
    pendingContent = previous;
    pendingLength = (short) 0;
    JCSystem.commitTransaction();
    if (previous != null) {
      PIVSecurityProvider.zeroise(previous, (short) 0, (short) previous.length);
    }
  }

  /**
   * Erases and releases, or retains for safe reuse, an unpublished replacement buffer.
   *
   * <p>The published content and its length are not changed.
   */
  void abortUpdate() {
    if (pendingContent == null || pendingLength == (short) 0) return;
    PIVSecurityProvider.zeroise(pendingContent, (short) 0, (short) pendingContent.length);
    pendingLength = (short) 0;
    if (!fixedCapacity && JCSystem.isObjectDeletionSupported()) {
      pendingContent = null;
      JCSystem.requestObjectDeletion();
    }
  }

  /**
   * Returns true if this object is populated with data
   *
   * @return True if the object is initialised
   */
  boolean isInitialised() {
    return bytesAllocated > (short) 0;
  }

  /*
   * Wipes all data from the current object
   */
  void clear() {
    abortUpdate();
    if (content == null) return;

    // JC 3.0.5 API Util.arrayFillNonAtomic is "suitable for use only when the contents of the byte
    // array can be left in a partially filled state in the event of a power loss in the middle of
    // the fill operation". The single persistent length write unpublishes the object first, so a
    // power loss during the wipe leaves it empty rather than readable with partly erased content.
    bytesAllocated = 0;
    PIVSecurityProvider.zeroise(content, (short) 0, (short) content.length);

    // Wipe our reference to the data, let the GC collect and re-allocate
    // NOTE: requestObjectDeletion doesn't necessarily do it straight away, so both objects may
    // remain allocated until the next call to process()
    if (!fixedCapacity && JCSystem.isObjectDeletionSupported()) {
      content = null;
      JCSystem.requestObjectDeletion();
    }
  }
}
