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
import javacard.framework.Util;

/**
 * Ledger events (GENESIS, ISSUE, TOPUP, TERM) and the SAM audit hash chain.
 *
 * <p>Entry format (fixed binary; the domain prefix never starts with 0x30, so an entry cannot be
 * mistaken for a certificate):
 *
 * <pre>
 * "OPSAMLE1"(8) | type(1) | samSki(20) | eventSeq(4) | prevHead(32) | payload
 *  GENESIS 01: sha256(samCert)(32) | paramsDigest(32) | quota(4) | lastTs(8)  (prevHead = 0^32, eventSeq = 1)
 *  ISSUE   02: issuanceSeq(4) | opidLen(1) = 17 | opid(17) | f9Ski(20) | capSha256(32)
 *              | cplcSha256(32) | tbsHash(32)
 *  TOPUP   03: ts(8) | added(4) | newQuota(4)
 *  TERM    04: issued(4) | quota(4)
 * </pre>
 *
 * <p>head_n = SHA-256(entry_n). The SAM key signs each entry with {@code
 * signPreComputedHash(SHA-256(entry))}, so a verifier uses plain SHA256withECDSA over the entry.
 *
 * <p>Every event follows one order: validate without state changes, compute in transient memory,
 * commit in one transaction, then sign. Any failure after the commit returns {@link
 * SamConst#SW_FAILURE_AFTER_COMMIT}; the committed entry stays recoverable with GET LAST ENTRY.
 */
final class SamLedger {
  private final SamState state;
  private final SamCrypto crypto;
  private final byte[] io;
  private final byte[] scratch;
  private final byte[] nonce;

  SamLedger(SamState state, SamCrypto crypto, byte[] io, byte[] scratch, byte[] nonce) {
    this.state = state;
    this.crypto = crypto;
    this.io = io;
    this.scratch = scratch;
    this.nonce = nonce;
  }

  /**
   * Writes the entry header with eventSeq = current eventSeq + 1 and prevHead = current chainHead.
   *
   * @return offset of the first payload octet
   */
  private short writeHeader(byte[] out, short offset, byte type) {
    short cursor =
        Util.arrayCopyNonAtomic(
            SamConst.PREFIX_ENTRY, (short) 0, out, offset, (short) SamConst.PREFIX_ENTRY.length);
    out[cursor++] = type;
    cursor = Util.arrayCopyNonAtomic(state.samSki, (short) 0, out, cursor, SamConst.LENGTH_SKI);
    if (U32.increment(state.eventSeq, (short) 0, out, cursor, SamConst.LENGTH_U32)) {
      ISOException.throwIt(SamConst.SW_EXHAUSTED);
    }
    cursor += SamConst.LENGTH_U32;
    return Util.arrayCopyNonAtomic(state.chainHead, (short) 0, out, cursor, SamConst.LENGTH_HASH);
  }

  /**
   * Appends {@code 71 L lastEntry 72 L sig}, where sig signs the persistent chain head (the hash of
   * the persistent last entry).
   *
   * @return offset following the appended data
   */
  short appendSignedEntry(short offset) {
    short cursor = offset;
    io[cursor++] = (byte) 0x71;
    cursor += TLV.writeLength(io, cursor, state.lastEntryLength);
    cursor = Util.arrayCopyNonAtomic(state.lastEntry, (short) 0, io, cursor, state.lastEntryLength);
    short sigLength = crypto.signHash(state.chainHead, (short) 0, scratch, SamConst.S_SIGNATURE);
    io[cursor++] = (byte) 0x72;
    cursor += TLV.writeLength(io, cursor, sigLength);
    return Util.arrayCopyNonAtomic(scratch, SamConst.S_SIGNATURE, io, cursor, sigLength);
  }

  /** Appends the last entry without a signature (used once the SAM key is cleared). */
  short appendEntry(short offset) {
    short cursor = offset;
    io[cursor++] = (byte) 0x71;
    cursor += TLV.writeLength(io, cursor, state.lastEntryLength);
    return Util.arrayCopyNonAtomic(state.lastEntry, (short) 0, io, cursor, state.lastEntryLength);
  }

  /** Signs and returns the committed entry; any failure is reported as 6500. */
  private short respondCommitted() {
    short length = (short) 0;
    boolean done = false;
    try {
      length = appendSignedEntry((short) 0);
      done = true;
    } catch (Exception e) {
      done = false;
    }
    if (!done) ISOException.throwIt(SamConst.SW_FAILURE_AFTER_COMMIT);
    return length;
  }

  /**
   * paramsDigest v3 = SHA-256("OPSAMPRM3" | IIN digits(4, MS first) | batch digits(4, MS first) |
   * a(8, LS first) | c(8, LS first) | x0(8, LS first) | initialQuota(u32 BE) | initialTs(u64 BE) |
   * fpeKcv(16)). Shared wire contract with the host {@code OpidSequence.paramsDigest}. It is
   * computed once at PUT PARAMETERS, while quota and lastTopUpTs still hold the initial values.
   *
   * @param work at least 69 octets of message staging
   * @param kcv the 16-octet FF1 key check value
   */
  void paramsDigest(
      byte[] work, short workOffset, byte[] kcv, short kcvOffset, byte[] out, short outOffset) {
    short k = SamConst.CIN_DIGITS;
    short cursor =
        Util.arrayCopyNonAtomic(
            SamConst.PREFIX_PARAMS,
            (short) 0,
            work,
            workOffset,
            (short) SamConst.PREFIX_PARAMS.length);
    cursor =
        Util.arrayCopyNonAtomic(
            state.issuerDigits, (short) 0, work, cursor, (short) SamConst.ISSUER_DIGITS);
    cursor =
        Util.arrayCopyNonAtomic(
            state.batchDigits, (short) 0, work, cursor, (short) SamConst.BATCH_DIGITS);
    cursor = Util.arrayCopyNonAtomic(state.lcgA, (short) 0, work, cursor, k);
    cursor = Util.arrayCopyNonAtomic(state.lcgC, (short) 0, work, cursor, k);
    cursor = Util.arrayCopyNonAtomic(state.lcgX0, (short) 0, work, cursor, k);
    cursor = Util.arrayCopyNonAtomic(state.quota, (short) 0, work, cursor, SamConst.LENGTH_U32);
    cursor =
        Util.arrayCopyNonAtomic(
            state.lastTopUpTs, (short) 0, work, cursor, SamConst.LENGTH_TIMESTAMP);
    cursor = Util.arrayCopyNonAtomic(kcv, kcvOffset, work, cursor, SamConst.LENGTH_KCV);
    short length = (short) (cursor - workOffset);
    crypto.digest(work, workOffset, length, out, outOffset);
    Util.arrayFillNonAtomic(work, workOffset, length, (byte) 0);
  }

  /**
   * LOCK: writes and commits the genesis entry (event 1, prevHead 0^32) and returns {@code 71 entry
   * 72 sig} in the I/O buffer.
   */
  short genesis() {
    short base = SamConst.S_ENTRY;
    short cursor =
        Util.arrayCopyNonAtomic(
            SamConst.PREFIX_ENTRY, (short) 0, scratch, base, (short) SamConst.PREFIX_ENTRY.length);
    scratch[cursor++] = SamConst.ENTRY_GENESIS;
    cursor = Util.arrayCopyNonAtomic(state.samSki, (short) 0, scratch, cursor, SamConst.LENGTH_SKI);
    Util.arrayFillNonAtomic(
        scratch, cursor, (short) (SamConst.LENGTH_U32 + SamConst.LENGTH_HASH), (byte) 0);
    scratch[(short) (cursor + SamConst.LENGTH_U32 - 1)] = (byte) 0x01;
    cursor += (short) (SamConst.LENGTH_U32 + SamConst.LENGTH_HASH);
    crypto.digest(state.samCert, (short) 0, state.samCertLength, scratch, cursor);
    cursor += SamConst.LENGTH_HASH;
    cursor =
        Util.arrayCopyNonAtomic(
            state.paramsDigest, (short) 0, scratch, cursor, SamConst.LENGTH_HASH);
    cursor = Util.arrayCopyNonAtomic(state.quota, (short) 0, scratch, cursor, SamConst.LENGTH_U32);
    cursor =
        Util.arrayCopyNonAtomic(
            state.lastTopUpTs, (short) 0, scratch, cursor, SamConst.LENGTH_TIMESTAMP);
    short length = (short) (cursor - base);
    crypto.digest(scratch, base, length, scratch, SamConst.S_LOCK_HEAD);
    state.commitGenesis(scratch, base, length, scratch, SamConst.S_LOCK_HEAD);
    return respondCommitted();
  }

  /**
   * TERMINATE: commits the final entry and enters TERMINATED, signs it with the SAM key and then
   * clears the key.
   */
  short terminate() {
    short base = SamConst.S_ENTRY;
    short cursor = writeHeader(scratch, base, SamConst.ENTRY_TERMINATE);
    cursor = Util.arrayCopyNonAtomic(state.issued, (short) 0, scratch, cursor, SamConst.LENGTH_U32);
    cursor = Util.arrayCopyNonAtomic(state.quota, (short) 0, scratch, cursor, SamConst.LENGTH_U32);
    short length = (short) (cursor - base);
    crypto.digest(scratch, base, length, scratch, SamConst.S_HASH_AUX);
    state.commitTerminate(scratch, base, length, scratch, SamConst.S_HASH_AUX);
    try {
      return respondCommitted();
    } finally {
      crypto.clearSamKey();
      state.clearLcgSecrets();
    }
  }

  /**
   * TOP UP: {@code 80 08 ts | 81 04 add | 9E L rootSig}, strictly ordered, nothing trailing.
   *
   * <ol>
   *   <li>Verify "OPSAMTOPUP1" | samSki | ts | add with the root key; failure is 6300.
   *   <li>Require ts &gt; lastTopUpTs (unsigned u64); otherwise 6985.
   *   <li>Require add &gt; 0, no overflow and newQuota &lt;= m; otherwise 6A80.
   *   <li>Commit quota, lastTopUpTs, eventSeq, chainHead and lastEntry in one transaction.
   * </ol>
   */
  short topUp(byte[] buffer, short offset, short length) {
    short end = (short) (offset + length);
    short ts = expectPrimitive(buffer, offset, end, (byte) 0x80, SamConst.LENGTH_TIMESTAMP);
    short tsEnd = (short) (ts + SamConst.LENGTH_TIMESTAMP);
    short add = expectPrimitive(buffer, tsEnd, end, (byte) 0x81, SamConst.LENGTH_U32);
    short addEnd = (short) (add + SamConst.LENGTH_U32);
    if (addEnd >= end || buffer[addEnd] != (byte) 0x9E) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    short sigEnd = DERValidator.derObjectEnd(buffer, addEnd, end);
    if (sigEnd != end) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    short sig = DERValidator.derContentOffset(buffer, addEnd, sigEnd);

    short cursor =
        Util.arrayCopyNonAtomic(
            SamConst.PREFIX_TOPUP,
            (short) 0,
            scratch,
            SamConst.S_TOPUP_MESSAGE,
            (short) SamConst.PREFIX_TOPUP.length);
    cursor = Util.arrayCopyNonAtomic(state.samSki, (short) 0, scratch, cursor, SamConst.LENGTH_SKI);
    cursor = Util.arrayCopyNonAtomic(buffer, ts, scratch, cursor, SamConst.LENGTH_TIMESTAMP);
    cursor = Util.arrayCopyNonAtomic(buffer, add, scratch, cursor, SamConst.LENGTH_U32);
    if (!crypto.verify(
        crypto.rootPublic,
        scratch,
        SamConst.S_TOPUP_MESSAGE,
        (short) (cursor - SamConst.S_TOPUP_MESSAGE),
        buffer,
        sig,
        (short) (sigEnd - sig))) {
      ISOException.throwIt(SamConst.SW_VERIFICATION_FAILED);
    }
    if (U32.compare(buffer, ts, state.lastTopUpTs, (short) 0, SamConst.LENGTH_TIMESTAMP) <= 0) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    if (U32.isZero(buffer, add, SamConst.LENGTH_U32)
        || U32.add(
            state.quota, (short) 0, buffer, add, scratch, SamConst.S_NEW_QUOTA, SamConst.LENGTH_U32)
        || U32.compare(
                scratch, SamConst.S_NEW_QUOTA, SamConst.MODULUS, (short) 0, SamConst.LENGTH_U32)
            > 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    short base = SamConst.S_ENTRY;
    cursor = writeHeader(scratch, base, SamConst.ENTRY_TOPUP);
    cursor = Util.arrayCopyNonAtomic(buffer, ts, scratch, cursor, SamConst.LENGTH_TIMESTAMP);
    cursor = Util.arrayCopyNonAtomic(buffer, add, scratch, cursor, SamConst.LENGTH_U32);
    cursor =
        Util.arrayCopyNonAtomic(
            scratch, SamConst.S_NEW_QUOTA, scratch, cursor, SamConst.LENGTH_U32);
    short entryLength = (short) (cursor - base);
    crypto.digest(scratch, base, entryLength, scratch, SamConst.S_HASH_AUX);
    state.commitTopUp(
        scratch,
        SamConst.S_NEW_QUOTA,
        buffer,
        ts,
        scratch,
        base,
        entryLength,
        scratch,
        SamConst.S_HASH_AUX);
    return respondCommitted();
  }

  /**
   * ISSUE F9: {@code 86 41 F9pub | 9E L PoP | 93 L Validity | 94 20 capSha256 | 95 20 cplcSha256},
   * each exactly once, in this order, with nothing trailing. Fails closed; nothing is consumed
   * before the commit in step 12.
   *
   * <p>capSha256 is the host-measured SHA-256 of the PIV CAP file installed on the card and
   * cplcSha256 the SHA-256 of the card's CPLC data. The SAM cannot measure either; it binds both,
   * as supplied, into the F9 issuance extension and the ISSUE ledger entry.
   *
   * <p>The caller has checked lifecycle, secure channel and operator PIN (step 1).
   *
   * @return response length in the I/O buffer: {@code 70 L cert | 71 L entry | 72 L sig}
   */
  short issue(DERWriter writer, byte[] buffer, short offset, short length) {
    // Step 1 (nonce) and 2: copy N and consume the nonce before anything else can fail.
    if (nonce[SamConst.OFFSET_NONCE_STATE] != SamConst.NONCE_ACTIVE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    Util.arrayCopyNonAtomic(
        SamConst.PREFIX_POP,
        (short) 0,
        scratch,
        SamConst.S_POP,
        (short) SamConst.PREFIX_POP.length);
    Util.arrayCopyNonAtomic(nonce, (short) 0, scratch, SamConst.S_POP_NONCE, SamConst.LENGTH_NONCE);
    consumeNonce();

    // Step 3: strict parse.
    short end = (short) (offset + length);
    short point = expectPrimitive(buffer, offset, end, (byte) 0x86, SamConst.LENGTH_POINT);
    short popTag = (short) (point + SamConst.LENGTH_POINT);
    if (popTag >= end || buffer[popTag] != (byte) 0x9E) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    short popEnd = DERValidator.derObjectEnd(buffer, popTag, end);
    short pop = DERValidator.derContentOffset(buffer, popTag, popEnd);
    if (popEnd >= end || buffer[popEnd] != (byte) 0x93) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    short validityEnd = DERValidator.derObjectEnd(buffer, popEnd, end);
    short validity = DERValidator.derContentOffset(buffer, popEnd, validityEnd);
    short validityLength = (short) (validityEnd - validity);
    if (validityLength > SamConst.LENGTH_VALIDITY_MAX) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    short capSha256 = expectPrimitive(buffer, validityEnd, end, (byte) 0x94, SamConst.LENGTH_HASH);
    short cplcTag = (short) (capSha256 + SamConst.LENGTH_HASH);
    short cplcSha256 = expectPrimitive(buffer, cplcTag, end, (byte) 0x95, SamConst.LENGTH_HASH);
    if ((short) (cplcSha256 + SamConst.LENGTH_HASH) != end) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Step 4: the point is on P-256 and differs from the SAM and root keys.
    Util.arrayCopyNonAtomic(buffer, point, scratch, SamConst.S_POP_POINT, SamConst.LENGTH_POINT);
    if (!crypto.isValidPoint(scratch, SamConst.S_POP_POINT, SamConst.LENGTH_POINT)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    crypto.samPublic.getW(io, SamConst.IO_POINT_COMPARE);
    if (Util.arrayCompare(
            scratch, SamConst.S_POP_POINT, io, SamConst.IO_POINT_COMPARE, SamConst.LENGTH_POINT)
        == (byte) 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    crypto.rootPublic.getW(io, SamConst.IO_POINT_COMPARE);
    if (Util.arrayCompare(
            scratch, SamConst.S_POP_POINT, io, SamConst.IO_POINT_COMPARE, SamConst.LENGTH_POINT)
        == (byte) 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Step 5: nb < na, samNotBefore <= nb and na <= samNotAfter.
    DERValidator.validateDerValidity(buffer, validity, validityLength);
    short notBefore = DERValidator.derContentOffset(buffer, validity, validityEnd);
    short notAfter = DERValidator.derObjectEnd(buffer, notBefore, validityEnd);
    short nb = SamConst.S_TIMES;
    short na = (short) (SamConst.S_TIMES + SamConst.LENGTH_TIME);
    DERValidator.normalizeTime(buffer, notBefore, scratch, nb);
    DERValidator.normalizeTime(buffer, notAfter, scratch, na);
    if (Util.arrayCompare(scratch, nb, scratch, na, SamConst.LENGTH_TIME) >= (byte) 0
        || Util.arrayCompare(scratch, nb, state.samNotBefore, (short) 0, SamConst.LENGTH_TIME)
            < (byte) 0
        || Util.arrayCompare(scratch, na, state.samNotAfter, (short) 0, SamConst.LENGTH_TIME)
            > (byte) 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Step 6: capacity pre-check.
    if (!state.hasCapacity()) ISOException.throwIt(SamConst.SW_EXHAUSTED);

    // Step 7: proof of possession over "OPF9POP" | N | F9pub with the card's own key.
    crypto.f9Public.setW(scratch, SamConst.S_POP_POINT, SamConst.LENGTH_POINT);
    if (!crypto.verify(
        crypto.f9Public,
        scratch,
        SamConst.S_POP,
        SamConst.LENGTH_POP,
        buffer,
        pop,
        (short) (popEnd - pop))) {
      ISOException.throwIt(SamConst.SW_VERIFICATION_FAILED);
    }

    // Step 8: x' = f(x), seq' = issued + 1, ev' = eventSeq + 1 (in the entry header), the OPID.
    short k = SamConst.CIN_DIGITS;
    DecimalLcg.step(
        state.lcgA,
        (short) 0,
        state.lcgX,
        (short) 0,
        state.lcgC,
        (short) 0,
        k,
        scratch,
        SamConst.S_NEXT_X);
    if (U32.increment(state.issued, (short) 0, scratch, SamConst.S_NEXT_SEQ, SamConst.LENGTH_U32)
        || U32.increment(
            state.eventSeq, (short) 0, scratch, SamConst.S_NEXT_EVENT, SamConst.LENGTH_U32)) {
      ISOException.throwIt(SamConst.SW_EXHAUSTED);
    }
    // E = FF1_K(batch | x_n, ASCII(IIN)) over 12 digits; x_n itself never leaves the SAM.
    short tweakLength = Ff1.writeTweak(state, scratch, SamConst.S_FF1_TWEAK);
    Ff1.writeNumeral(state, scratch, SamConst.S_NEXT_X, scratch, SamConst.S_FF1_DIGITS);
    Ff1.encrypt(
        crypto,
        scratch,
        SamConst.S_FF1_DIGITS,
        SamConst.ENCIPHERED_DIGITS,
        scratch,
        SamConst.S_FF1_TWEAK,
        tweakLength,
        scratch,
        SamConst.S_FF1_WORK);
    short opidLength = Opid.render(state, scratch, SamConst.S_FF1_DIGITS, scratch, SamConst.S_OPID);
    Util.arrayFillNonAtomic(
        scratch, SamConst.S_FF1_WORK, (short) (SamConst.S_FF1_END - SamConst.S_FF1_WORK), (byte) 0);

    // Step 9: positive non-zero 16-octet serial.
    crypto.randomBytes(scratch, SamConst.S_SERIAL, SamConst.LENGTH_SERIAL);
    scratch[SamConst.S_SERIAL] = (byte) (scratch[SamConst.S_SERIAL] & (byte) 0x7F);
    if (scratch[SamConst.S_SERIAL] == (byte) 0) scratch[SamConst.S_SERIAL] = (byte) 0x01;

    // Step 10: TBS inside the outer frames; f9Ski into S_HASH_AUX[0..20); tbsHash.
    crypto.keyIdentifier(
        scratch, SamConst.S_POP_POINT, scratch, SamConst.S_HASH_AUX, scratch, SamConst.S_HASH_AUX);
    short tbs =
        F9CertificateBuilder.beginAndWriteTbs(
            writer,
            io,
            state,
            scratch,
            SamConst.S_SERIAL,
            buffer,
            validity,
            validityLength,
            scratch,
            SamConst.S_OPID,
            opidLength,
            scratch,
            SamConst.S_POP_POINT,
            scratch,
            SamConst.S_HASH_AUX,
            scratch,
            SamConst.S_NEXT_SEQ,
            scratch,
            SamConst.S_NEXT_EVENT,
            buffer,
            capSha256,
            cplcSha256);
    crypto.digest(io, tbs, (short) (writer.getOffset() - tbs), scratch, SamConst.S_HASH_TBS);

    // Step 11: the entry (overwrites the dead POP region and, after f9Ski is copied, HASH_AUX)
    // and newHead. tbsHash stays the last field: step 13 signs it from the persistent entry.
    short base = SamConst.S_ENTRY;
    short cursor = writeHeader(scratch, base, SamConst.ENTRY_ISSUE);
    cursor =
        Util.arrayCopyNonAtomic(scratch, SamConst.S_NEXT_SEQ, scratch, cursor, SamConst.LENGTH_U32);
    scratch[cursor++] = (byte) opidLength;
    cursor = Util.arrayCopyNonAtomic(scratch, SamConst.S_OPID, scratch, cursor, opidLength);
    cursor =
        Util.arrayCopyNonAtomic(scratch, SamConst.S_HASH_AUX, scratch, cursor, SamConst.LENGTH_SKI);
    cursor = Util.arrayCopyNonAtomic(buffer, capSha256, scratch, cursor, SamConst.LENGTH_HASH);
    cursor = Util.arrayCopyNonAtomic(buffer, cplcSha256, scratch, cursor, SamConst.LENGTH_HASH);
    cursor =
        Util.arrayCopyNonAtomic(
            scratch, SamConst.S_HASH_TBS, scratch, cursor, SamConst.LENGTH_HASH);
    short entryLength = (short) (cursor - base);
    crypto.digest(scratch, base, entryLength, scratch, SamConst.S_ISSUE_HEAD);

    // Step 12: the only burn point.
    state.commitIssue(
        scratch,
        SamConst.S_NEXT_X,
        scratch,
        SamConst.S_NEXT_SEQ,
        scratch,
        base,
        entryLength,
        scratch,
        SamConst.S_ISSUE_HEAD);

    // Steps 13-16: any failure from here on is 6500 with the OPID burned.
    short responseLength = (short) 0;
    boolean done = false;
    try {
      short tbsHash = (short) (state.lastEntryLength - SamConst.LENGTH_HASH);
      short sigLength = crypto.signHash(state.lastEntry, tbsHash, scratch, SamConst.S_SIGNATURE);
      short certEnd = F9CertificateBuilder.finish(writer, scratch, SamConst.S_SIGNATURE, sigLength);
      responseLength = appendSignedEntry(certEnd);
      done = true;
    } catch (Exception e) {
      done = false;
    }
    if (!done) ISOException.throwIt(SamConst.SW_FAILURE_AFTER_COMMIT);
    return responseLength;
  }

  /**
   * DECIPHER: {@code 80 11 <17 ASCII digits>}, nothing trailing. Reverses an OPID of this IIN.
   *
   * <ol>
   *   <li>17 ASCII digits with a valid Luhn digit, otherwise 6A80; the IIN must be this SAM's,
   *       otherwise 6A88.
   *   <li>(B | X) = FF1.Decrypt_K(E, ASCII(IIN)) over 12 digits.
   *   <li>If B is this SAM's batch, the index n with f^n(x0) = X is recovered digit-wise with the
   *       stored jump maps.
   * </ol>
   *
   * Response: {@code 81 04 batch (ASCII) | 82 01 sameBatch | [83 04 n (u32) | 84 01 issuedFlag]},
   * the last two only for this SAM's batch; issuedFlag is 01 when 1 &lt;= n &lt;= issued. X is
   * never returned.
   *
   * @return response length in the I/O buffer
   */
  short decipher(byte[] buffer, short offset, short length) {
    short end = (short) (offset + length);
    short opid = expectPrimitive(buffer, offset, end, (byte) 0x80, SamConst.LENGTH_OPID);
    if ((short) (opid + SamConst.LENGTH_OPID) != end) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    // The 17 digit values are staged at S_FF1_DIGITS - 4: IIN at -4..-1, E at the FF1 numeral.
    short digits = (short) (SamConst.S_FF1_DIGITS - SamConst.ISSUER_DIGITS);
    if (!Opid.parse(buffer, opid, scratch, digits)) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    if (Util.arrayCompare(
            scratch, digits, state.issuerDigits, (short) 0, (short) SamConst.ISSUER_DIGITS)
        != (byte) 0) {
      Util.arrayFillNonAtomic(scratch, digits, SamConst.LENGTH_OPID, (byte) 0);
      ISOException.throwIt(SamConst.SW_FOREIGN_IIN);
    }
    // The Luhn digit at S_FF1_DIGITS + 12 overlaps the tweak region, which is written next.
    short tweakLength = Ff1.writeTweak(state, scratch, SamConst.S_FF1_TWEAK);
    Ff1.decrypt(
        crypto,
        scratch,
        SamConst.S_FF1_DIGITS,
        SamConst.ENCIPHERED_DIGITS,
        scratch,
        SamConst.S_FF1_TWEAK,
        tweakLength,
        scratch,
        SamConst.S_FF1_WORK);

    short b = SamConst.S_FF1_DIGITS;
    short cursor = 0;
    io[cursor++] = (byte) 0x81;
    io[cursor++] = (byte) SamConst.BATCH_DIGITS;
    for (short i = 0; i < SamConst.BATCH_DIGITS; i++) {
      io[cursor++] = (byte) (scratch[(short) (b + i)] + (byte) '0');
    }
    boolean sameBatch =
        Util.arrayCompare(scratch, b, state.batchDigits, (short) 0, (short) SamConst.BATCH_DIGITS)
            == (byte) 0;
    io[cursor++] = (byte) 0x82;
    io[cursor++] = (byte) 0x01;
    io[cursor++] = sameBatch ? (byte) 0x01 : (byte) 0x00;
    if (sameBatch) {
      // X as little-endian digits; then n = index of X on the orbit of x0.
      for (short i = 0; i < SamConst.CIN_DIGITS; i++) {
        scratch[(short) (SamConst.S_DEC_X + i)] =
            scratch[(short) (b + SamConst.BATCH_DIGITS + SamConst.CIN_DIGITS - 1 - i)];
      }
      boolean found =
          DecimalLcg.recoverIndex(
              state.jumpA,
              state.jumpC,
              state.lcgX0,
              scratch,
              SamConst.S_DEC_X,
              scratch,
              SamConst.S_DEC_Y,
              scratch,
              SamConst.S_DEC_N);
      if (!found) {
        clearDecipherScratch();
        ISOException.throwIt(SamConst.SW_UNEXPECTED);
      }
      U32.fromDecimal(
          scratch, SamConst.S_DEC_N, SamConst.CIN_DIGITS, scratch, SamConst.S_DEC_COUNT);
      io[cursor++] = (byte) 0x83;
      io[cursor++] = (byte) SamConst.LENGTH_U32;
      cursor =
          Util.arrayCopyNonAtomic(scratch, SamConst.S_DEC_COUNT, io, cursor, SamConst.LENGTH_U32);
      boolean issued =
          !U32.isZero(scratch, SamConst.S_DEC_COUNT, SamConst.LENGTH_U32)
              && U32.compare(
                      scratch, SamConst.S_DEC_COUNT, state.issued, (short) 0, SamConst.LENGTH_U32)
                  <= 0;
      io[cursor++] = (byte) 0x84;
      io[cursor++] = (byte) 0x01;
      io[cursor++] = issued ? (byte) 0x01 : (byte) 0x00;
    }
    clearDecipherScratch();
    return cursor;
  }

  /**
   * VOID: {@code 80 04 issuanceSeq(u32) | 81 01 reason}, nothing trailing; 1 &lt;= seq &lt;=
   * issued, otherwise 6A80. The SAM recomputes OPID_seq itself, from x_seq = f^seq(x0) reached with
   * the jump maps (digit d_j of seq applies M_j d_j times) and FF1, and appends the entry {@code 05
   * VOID: issuanceSeq(4) | opidLen(1) = 17 | opid(17) | reason(1)} in one transaction. Repeated
   * voids of the same issuance are allowed.
   *
   * @return response length in the I/O buffer: {@code 71 entry | 72 sig}
   */
  short voidIssuance(byte[] buffer, short offset, short length) {
    short end = (short) (offset + length);
    short seq = expectPrimitive(buffer, offset, end, (byte) 0x80, SamConst.LENGTH_U32);
    short reason =
        expectPrimitive(buffer, (short) (seq + SamConst.LENGTH_U32), end, (byte) 0x81, (short) 1);
    if ((short) (reason + 1) != end) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    if (U32.isZero(buffer, seq, SamConst.LENGTH_U32)
        || U32.compare(buffer, seq, state.issued, (short) 0, SamConst.LENGTH_U32) > 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // x_seq = f^seq(x0): seq < 10^8, so its 8 decimal digits select jump-map applications.
    U32.toDecimal(
        buffer,
        seq,
        scratch,
        SamConst.S_VOID_WORK,
        scratch,
        SamConst.S_VOID_SEQ_DIGITS,
        SamConst.CIN_DIGITS);
    short k = SamConst.CIN_DIGITS;
    Util.arrayCopyNonAtomic(state.lcgX0, (short) 0, scratch, SamConst.S_VOID_X, k);
    for (short j = 0; j < k; j++) {
      short count = scratch[(short) (SamConst.S_VOID_SEQ_DIGITS + j)];
      for (short t = 0; t < count; t++) {
        DecimalLcg.step(
            state.jumpA,
            (short) (j * k),
            scratch,
            SamConst.S_VOID_X,
            state.jumpC,
            (short) (j * k),
            k,
            scratch,
            SamConst.S_VOID_NEXT);
        Util.arrayCopyNonAtomic(scratch, SamConst.S_VOID_NEXT, scratch, SamConst.S_VOID_X, k);
      }
    }
    short tweakLength = Ff1.writeTweak(state, scratch, SamConst.S_FF1_TWEAK);
    Ff1.writeNumeral(state, scratch, SamConst.S_VOID_X, scratch, SamConst.S_FF1_DIGITS);
    Util.arrayFillNonAtomic(scratch, (short) 0, (short) 40, (byte) 0);
    Ff1.encrypt(
        crypto,
        scratch,
        SamConst.S_FF1_DIGITS,
        SamConst.ENCIPHERED_DIGITS,
        scratch,
        SamConst.S_FF1_TWEAK,
        tweakLength,
        scratch,
        SamConst.S_FF1_WORK);
    short opidLength = Opid.render(state, scratch, SamConst.S_FF1_DIGITS, scratch, SamConst.S_OPID);
    Util.arrayFillNonAtomic(
        scratch, SamConst.S_FF1_WORK, (short) (SamConst.S_FF1_END - SamConst.S_FF1_WORK), (byte) 0);

    short base = SamConst.S_VOID_ENTRY;
    short cursor = writeHeader(scratch, base, SamConst.ENTRY_VOID);
    cursor = Util.arrayCopyNonAtomic(buffer, seq, scratch, cursor, SamConst.LENGTH_U32);
    scratch[cursor++] = (byte) opidLength;
    cursor = Util.arrayCopyNonAtomic(scratch, SamConst.S_OPID, scratch, cursor, opidLength);
    scratch[cursor++] = buffer[reason];
    short entryLength = (short) (cursor - base);
    crypto.digest(scratch, base, entryLength, scratch, SamConst.S_HASH_AUX);
    state.commitVoid(scratch, base, entryLength, scratch, SamConst.S_HASH_AUX);
    return respondCommitted();
  }

  /**
   * CLOSE: from OPERATIONAL, commits {@code 06 CLOSE: issued(4) | quota(4)} and enters CLOSED. In
   * CLOSED it is idempotent and re-serves the stored CLOSE entry with a fresh signature.
   *
   * @return response length in the I/O buffer: {@code 71 entry | 72 sig}
   */
  short close() {
    if (state.lifecycle == SamConst.LC_CLOSED) {
      short cursor = 0;
      io[cursor++] = (byte) 0x71;
      io[cursor++] = (byte) SamConst.LENGTH_CLOSE_ENTRY;
      cursor =
          Util.arrayCopyNonAtomic(
              state.closeEntry, (short) 0, io, cursor, SamConst.LENGTH_CLOSE_ENTRY);
      crypto.digest(
          state.closeEntry, (short) 0, SamConst.LENGTH_CLOSE_ENTRY, scratch, SamConst.S_HASH_AUX);
      short sigLength =
          crypto.signHash(scratch, SamConst.S_HASH_AUX, scratch, SamConst.S_SIGNATURE);
      io[cursor++] = (byte) 0x72;
      io[cursor++] = (byte) sigLength;
      return Util.arrayCopyNonAtomic(scratch, SamConst.S_SIGNATURE, io, cursor, sigLength);
    }
    short base = SamConst.S_ENTRY;
    short cursor = writeHeader(scratch, base, SamConst.ENTRY_CLOSE);
    cursor = Util.arrayCopyNonAtomic(state.issued, (short) 0, scratch, cursor, SamConst.LENGTH_U32);
    cursor = Util.arrayCopyNonAtomic(state.quota, (short) 0, scratch, cursor, SamConst.LENGTH_U32);
    short length = (short) (cursor - base);
    crypto.digest(scratch, base, length, scratch, SamConst.S_HASH_AUX);
    state.commitClose(scratch, base, length, scratch, SamConst.S_HASH_AUX);
    return respondCommitted();
  }

  private void clearDecipherScratch() {
    Util.arrayFillNonAtomic(scratch, (short) 0, SamConst.LENGTH_SCRATCH, (byte) 0);
  }

  /** Invalidates the BEGIN ISSUANCE nonce. */
  void consumeNonce() {
    Util.arrayFillNonAtomic(nonce, (short) 0, (short) nonce.length, (byte) 0);
  }

  /** Generates a fresh 32-octet nonce and marks it active. */
  void beginIssuance() {
    crypto.randomBytes(nonce, (short) 0, SamConst.LENGTH_NONCE);
    nonce[SamConst.OFFSET_NONCE_STATE] = SamConst.NONCE_ACTIVE;
  }

  /**
   * Requires a primitive TLV with a one-octet tag and an exact short-form length at {@code offset}.
   *
   * @return the value offset
   */
  static short expectPrimitive(byte[] buffer, short offset, short end, byte tag, short length) {
    if (offset >= end || buffer[offset] != tag) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    short objectEnd = DERValidator.derObjectEnd(buffer, offset, end);
    short value = DERValidator.derContentOffset(buffer, offset, objectEnd);
    if ((short) (objectEnd - value) != length) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    return value;
  }
}
