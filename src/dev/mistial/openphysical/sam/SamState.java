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

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;

/**
 * All persistent SAM state and the transactional commit for each event.
 *
 * <p>Invariants after LOCK: {@code issued <= quota <= m}; {@code lcgX = f^issued(x0)}; {@code
 * chainHead = SHA-256(lastEntry)}; {@code eventSeq} is the event number of {@code lastEntry}. Every
 * commit method updates these fields together inside one transaction and re-checks its precondition
 * inside that transaction, so a tear leaves either the old or the new event visible, never a
 * mixture. Before LOCK, the personalization handlers write their data fields while the lifecycle is
 * demoted and then flip the lifecycle with {@link #commitLifecycle}.
 */
final class SamState {
  byte lifecycle;

  // Provisioned issuance identity.
  final byte[] issuerDigits; // 4 digit values, most significant first
  final byte[] batchDigits; // 4 digit values, most significant first

  // LCG parameters and current value mod m = 10^8: 8 decimal digit values, little-endian.
  final byte[] lcgA;
  final byte[] lcgC;
  final byte[] lcgX0;
  final byte[] lcgX;

  // Secret jump maps M_j = f^(10^(j-1)) for j = 1..8 as affine pairs (A_j, C_j) mod 10^8, digits
  // little-endian at offset 8 (j - 1); used by DECIPHER and cleared on TERMINATE.
  final byte[] jumpA;
  final byte[] jumpC;

  // Metering and audit chain.
  final byte[] issued; // u32
  final byte[] quota; // u32
  final byte[] lastTopUpTs; // u64 milliseconds, big-endian
  final byte[] eventSeq; // u32
  final byte[] chainHead; // SHA-256 of lastEntry
  final byte[] paramsDigest; // paramsDigest over the provisioned (initial) parameters
  final byte[] lastEntry;
  short lastEntryLength;

  // Names.
  final byte[] f9SubjectTemplate; // RDN content of the F9 subject, without the SEQUENCE header
  short f9SubjectTemplateLength;
  final byte[] expectedSamSubject; // complete Name DER, or length 0 when not provisioned
  short expectedSamSubjectLength;

  // SAM certificate.
  final byte[] samCert;
  short samCertLength;
  short samSubjectOffset;
  short samSubjectLength;
  final byte[] samNotBefore; // ASCII YYYYMMDDHHMMSS
  final byte[] samNotAfter;
  final byte[] samSki;

  // Batch extension v3 registry binding, recorded at LOAD SAM CERTIFICATE.
  final byte[] allocationSeq; // u32
  final byte[] registryHead;

  // Copy of the CLOSE entry, re-served by an idempotent CLOSE.
  final byte[] closeEntry;

  // Operator PIN.
  final OwnerPIN operatorPin;
  boolean pinSet;

  SamState() {
    lifecycle = SamConst.LC_INSTALLED;
    issuerDigits = new byte[SamConst.ISSUER_DIGITS];
    batchDigits = new byte[SamConst.BATCH_DIGITS];
    lcgA = new byte[SamConst.LENGTH_DIGITS];
    lcgC = new byte[SamConst.LENGTH_DIGITS];
    lcgX0 = new byte[SamConst.LENGTH_DIGITS];
    lcgX = new byte[SamConst.LENGTH_DIGITS];
    jumpA = new byte[(short) (SamConst.JUMP_MAPS * SamConst.LENGTH_DIGITS)];
    jumpC = new byte[(short) (SamConst.JUMP_MAPS * SamConst.LENGTH_DIGITS)];
    issued = new byte[SamConst.LENGTH_U32];
    quota = new byte[SamConst.LENGTH_U32];
    lastTopUpTs = new byte[SamConst.LENGTH_TIMESTAMP];
    eventSeq = new byte[SamConst.LENGTH_U32];
    chainHead = new byte[SamConst.LENGTH_HASH];
    paramsDigest = new byte[SamConst.LENGTH_HASH];
    lastEntry = new byte[SamConst.LENGTH_LAST_ENTRY];
    f9SubjectTemplate = new byte[SamConst.LENGTH_F9_TEMPLATE_MAX];
    expectedSamSubject = new byte[SamConst.LENGTH_SAM_SUBJECT_MAX];
    samCert = new byte[SamConst.LENGTH_SAM_CERT_MAX];
    samNotBefore = new byte[SamConst.LENGTH_TIME];
    samNotAfter = new byte[SamConst.LENGTH_TIME];
    samSki = new byte[SamConst.LENGTH_SKI];
    allocationSeq = new byte[SamConst.LENGTH_U32];
    registryHead = new byte[SamConst.LENGTH_HASH];
    closeEntry = new byte[SamConst.LENGTH_CLOSE_ENTRY];
    operatorPin = new OwnerPIN(SamConst.PIN_TRIES, (byte) SamConst.LENGTH_PIN_MAX);
  }

  //
  // Lifecycle predicates. Each compares with == only, so an unknown (faulted) value satisfies
  // none of them.
  //

  boolean isLocked() {
    return lifecycle == SamConst.LC_OPERATIONAL
        || lifecycle == SamConst.LC_CLOSED
        || lifecycle == SamConst.LC_TERMINATED;
  }

  /** OPERATIONAL or CLOSED: the SAM key is live and the ledger can still be extended. */
  boolean isLive() {
    return lifecycle == SamConst.LC_OPERATIONAL || lifecycle == SamConst.LC_CLOSED;
  }

  boolean isOperational() {
    return lifecycle == SamConst.LC_OPERATIONAL;
  }

  boolean hasParameters() {
    return lifecycle == SamConst.LC_PARAMS_SET
        || lifecycle == SamConst.LC_KEY_GENERATED
        || lifecycle == SamConst.LC_CERT_LOADED
        || isLocked();
  }

  boolean hasCertificate() {
    return lifecycle == SamConst.LC_CERT_LOADED || isLocked();
  }

  /**
   * Returns true when another OPID may be issued: {@code issued < quota} and {@code issued < m}.
   * The second bound stops the sequence before it wraps to x0.
   */
  boolean hasCapacity() {
    return U32.compare(issued, (short) 0, quota, (short) 0, SamConst.LENGTH_U32) < 0
        && U32.compare(issued, (short) 0, SamConst.MODULUS, (short) 0, SamConst.LENGTH_U32) < 0;
  }

  /** Zeroizes the secret LCG parameters, state and jump maps. */
  void clearLcgSecrets() {
    Util.arrayFillNonAtomic(lcgA, (short) 0, SamConst.LENGTH_DIGITS, (byte) 0);
    Util.arrayFillNonAtomic(lcgC, (short) 0, SamConst.LENGTH_DIGITS, (byte) 0);
    Util.arrayFillNonAtomic(lcgX0, (short) 0, SamConst.LENGTH_DIGITS, (byte) 0);
    Util.arrayFillNonAtomic(lcgX, (short) 0, SamConst.LENGTH_DIGITS, (byte) 0);
    Util.arrayFillNonAtomic(jumpA, (short) 0, (short) jumpA.length, (byte) 0);
    Util.arrayFillNonAtomic(jumpC, (short) 0, (short) jumpC.length, (byte) 0);
  }

  //
  // Commits.
  //

  /** Flips the lifecycle in one transaction. */
  void commitLifecycle(byte next) {
    try {
      JCSystem.beginTransaction();
      lifecycle = next;
      JCSystem.commitTransaction();
    } finally {
      abortOpenTransaction();
    }
  }

  /** Records the loaded SAM certificate's lengths and flips the lifecycle to CERT_LOADED. */
  void commitCertificate(short length, short subjectOffset, short subjectLength) {
    try {
      JCSystem.beginTransaction();
      samCertLength = length;
      samSubjectOffset = subjectOffset;
      samSubjectLength = subjectLength;
      lifecycle = SamConst.LC_CERT_LOADED;
      JCSystem.commitTransaction();
    } finally {
      abortOpenTransaction();
    }
  }

  /**
   * LOCK: starts metering at zero, sets x = x0, records the genesis entry (event 1) and enters
   * OPERATIONAL.
   */
  void commitGenesis(
      byte[] entry, short entryOffset, short entryLength, byte[] head, short headOffset) {
    try {
      JCSystem.beginTransaction();
      if (lifecycle != SamConst.LC_CERT_LOADED) ISOException.throwIt(ISO_CONDITIONS);
      Util.arrayFillNonAtomic(issued, (short) 0, SamConst.LENGTH_U32, (byte) 0);
      Util.arrayCopy(
          entry,
          (short) (entryOffset + SamConst.ENTRY_OFFSET_EVENT),
          eventSeq,
          (short) 0,
          SamConst.LENGTH_U32);
      Util.arrayCopy(lcgX0, (short) 0, lcgX, (short) 0, SamConst.LENGTH_DIGITS);
      writeEntry(entry, entryOffset, entryLength, head, headOffset);
      lifecycle = SamConst.LC_OPERATIONAL;
      JCSystem.commitTransaction();
    } finally {
      abortOpenTransaction();
    }
  }

  /**
   * ISSUE: the only point at which an OPID is consumed. Re-checks the lifecycle and capacity inside
   * the transaction, then advances x, issued and the chain together.
   */
  void commitIssue(
      byte[] nextX,
      short nextXOffset,
      byte[] nextIssued,
      short nextIssuedOffset,
      byte[] entry,
      short entryOffset,
      short entryLength,
      byte[] head,
      short headOffset) {
    try {
      JCSystem.beginTransaction();
      if (lifecycle != SamConst.LC_OPERATIONAL) ISOException.throwIt(ISO_CONDITIONS);
      if (!hasCapacity()) ISOException.throwIt(SamConst.SW_EXHAUSTED);
      Util.arrayCopy(nextX, nextXOffset, lcgX, (short) 0, SamConst.LENGTH_DIGITS);
      Util.arrayCopy(nextIssued, nextIssuedOffset, issued, (short) 0, SamConst.LENGTH_U32);
      Util.arrayCopy(
          entry,
          (short) (entryOffset + SamConst.ENTRY_OFFSET_EVENT),
          eventSeq,
          (short) 0,
          SamConst.LENGTH_U32);
      writeEntry(entry, entryOffset, entryLength, head, headOffset);
      JCSystem.commitTransaction();
    } finally {
      abortOpenTransaction();
    }
  }

  /** TOP UP: raises the quota, records the root timestamp and extends the chain. */
  void commitTopUp(
      byte[] newQuota,
      short newQuotaOffset,
      byte[] timestamp,
      short timestampOffset,
      byte[] entry,
      short entryOffset,
      short entryLength,
      byte[] head,
      short headOffset) {
    try {
      JCSystem.beginTransaction();
      if (lifecycle != SamConst.LC_OPERATIONAL) ISOException.throwIt(ISO_CONDITIONS);
      Util.arrayCopy(newQuota, newQuotaOffset, quota, (short) 0, SamConst.LENGTH_U32);
      Util.arrayCopy(timestamp, timestampOffset, lastTopUpTs, (short) 0, SamConst.LENGTH_TIMESTAMP);
      Util.arrayCopy(
          entry,
          (short) (entryOffset + SamConst.ENTRY_OFFSET_EVENT),
          eventSeq,
          (short) 0,
          SamConst.LENGTH_U32);
      writeEntry(entry, entryOffset, entryLength, head, headOffset);
      JCSystem.commitTransaction();
    } finally {
      abortOpenTransaction();
    }
  }

  /** TERMINATE: records the final entry and enters TERMINATED. */
  void commitTerminate(
      byte[] entry, short entryOffset, short entryLength, byte[] head, short headOffset) {
    try {
      JCSystem.beginTransaction();
      if (!isLive()) ISOException.throwIt(ISO_CONDITIONS);
      Util.arrayCopy(
          entry,
          (short) (entryOffset + SamConst.ENTRY_OFFSET_EVENT),
          eventSeq,
          (short) 0,
          SamConst.LENGTH_U32);
      writeEntry(entry, entryOffset, entryLength, head, headOffset);
      lifecycle = SamConst.LC_TERMINATED;
      JCSystem.commitTransaction();
    } finally {
      abortOpenTransaction();
    }
  }

  /** VOID: appends the entry while OPERATIONAL or CLOSED; the lifecycle is unchanged. */
  void commitVoid(
      byte[] entry, short entryOffset, short entryLength, byte[] head, short headOffset) {
    try {
      JCSystem.beginTransaction();
      if (!isLive()) ISOException.throwIt(ISO_CONDITIONS);
      Util.arrayCopy(
          entry,
          (short) (entryOffset + SamConst.ENTRY_OFFSET_EVENT),
          eventSeq,
          (short) 0,
          SamConst.LENGTH_U32);
      writeEntry(entry, entryOffset, entryLength, head, headOffset);
      JCSystem.commitTransaction();
    } finally {
      abortOpenTransaction();
    }
  }

  /** CLOSE: appends the CLOSE entry, keeps a copy of it and enters CLOSED. */
  void commitClose(
      byte[] entry, short entryOffset, short entryLength, byte[] head, short headOffset) {
    try {
      JCSystem.beginTransaction();
      if (lifecycle != SamConst.LC_OPERATIONAL) ISOException.throwIt(ISO_CONDITIONS);
      Util.arrayCopy(
          entry,
          (short) (entryOffset + SamConst.ENTRY_OFFSET_EVENT),
          eventSeq,
          (short) 0,
          SamConst.LENGTH_U32);
      writeEntry(entry, entryOffset, entryLength, head, headOffset);
      Util.arrayCopy(entry, entryOffset, closeEntry, (short) 0, SamConst.LENGTH_CLOSE_ENTRY);
      lifecycle = SamConst.LC_CLOSED;
      JCSystem.commitTransaction();
    } finally {
      abortOpenTransaction();
    }
  }

  private void writeEntry(
      byte[] entry, short entryOffset, short entryLength, byte[] head, short headOffset) {
    Util.arrayCopy(head, headOffset, chainHead, (short) 0, SamConst.LENGTH_HASH);
    Util.arrayCopy(entry, entryOffset, lastEntry, (short) 0, entryLength);
    lastEntryLength = entryLength;
  }

  private static void abortOpenTransaction() {
    if (JCSystem.getTransactionDepth() != (byte) 0) JCSystem.abortTransaction();
  }

  private static final short ISO_CONDITIONS = ISO7816.SW_CONDITIONS_NOT_SATISFIED;
}
