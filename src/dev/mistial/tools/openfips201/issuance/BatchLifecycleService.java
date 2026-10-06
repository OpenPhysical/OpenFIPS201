/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.producer.BatchMetadata;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * End of a batch's life, driven by the SAM.
 *
 * <ul>
 *   <li>{@code batch close}: the SAM's signed STATUS must agree with the ledger (issued count,
 *       eventSeq and chain head); CLOSE commits the SAM's CLOSE entry, which must verify, extend
 *       the ledger and carry the ledger's issued count. It is recorded as the ledger {@code close}
 *       line and the batch becomes {@code CLOSED}. The SAM then refuses BEGIN, ISSUE and TOP UP.
 *       Repeating the command is harmless: the SAM returns its stored CLOSE entry, which must be
 *       the one recorded, or (after an interruption) the one the ledger still lacks.
 *   <li>{@code sam terminate}: from a closed batch, or from an open one (the caller warns).
 *       TERMINATE commits the SAM's final TERM entry, which must verify and extend the ledger; it
 *       is recorded as the ledger {@code term} line and the batch becomes {@code TERMINATED}. The
 *       SAM key is cleared, so the SAM signs nothing afterwards.
 * </ul>
 */
public final class BatchLifecycleService {
  /**
   * @param sam a SAM session over the issuer secure channel with the operator PIN verified
   * @return the SAM's CLOSE entry
   */
  public SamLedgerEntry close(BatchMetadata batch, SamClient sam, PublicKey samKey)
      throws Exception {
    if (!BatchMetadata.STATE_SAM_BOUND.equals(batch.state)
        && !BatchMetadata.STATE_CLOSED.equals(batch.state)) {
      throw new IllegalStateException(
          "Batch " + batch.name + " is " + batch.state + "; only a SAM-bound batch is closed");
    }
    IssuanceLedger ledger = new IssuanceLedger(batch.directory().resolve(batch.ledger));
    try (BatchLock ignored = BatchLock.acquire(batch.directory())) {
      SamStatus status = new SamOperationsService().signedStatus(sam, samKey);
      if (!HexUtil.format(status.samSki()).equals(batch.sam.ski)) {
        throw new IllegalStateException("The SAM is not the SAM bound to batch " + batch.name);
      }
      SamLedgerEntry.Signed last = ledger.lastSamEntry();
      if (last == null) {
        throw new IllegalStateException("The batch ledger has no genesis line");
      }
      IssuanceLedger.Line recorded = closeLine(ledger);
      if (recorded == null && status.isOperational()) {
        if (ledger.lastIssueSeq() != status.issued
            || last.entry.eventSeq != status.eventSeq
            || !Arrays.equals(last.entry.head(), status.chainHead())) {
          throw new IllegalStateException(
              "The batch ledger does not match the SAM; run 'ledger reconcile' before closing");
        }
      } else if (recorded == null && !status.isClosed()) {
        throw new IllegalStateException(
            "SAM is " + SamStatus.lifecycleName(status.lifecycle) + "; it cannot be closed");
      }
      SamLedgerEntry.Signed close = SamLedgerEntry.Signed.parse(sam.close());
      if (!close.verify(samKey) || close.entry.type != SamLedgerEntry.TYPE_CLOSE) {
        throw new IllegalStateException("The SAM's CLOSE entry does not verify");
      }
      if (recorded != null) {
        SamLedgerEntry.Signed stored = recorded.samEntry();
        if (stored == null || !Arrays.equals(stored.entry.head(), close.entry.head())) {
          throw new IllegalStateException("The SAM's CLOSE entry differs from the recorded one");
        }
      } else {
        if (close.entry.eventSeq != last.entry.eventSeq + 1
            || !Arrays.equals(close.entry.prevHead(), last.entry.head())
            || close.entry.issued != ledger.lastIssueSeq()) {
          throw new IllegalStateException(
              "The SAM's CLOSE entry does not extend the ledger; run 'ledger reconcile'");
        }
        ledger.appendClose(close);
      }
      if (!BatchMetadata.STATE_CLOSED.equals(batch.state)) {
        batch.state = BatchMetadata.STATE_CLOSED;
        batch.replace();
      }
      return close.entry;
    }
  }

  private static IssuanceLedger.Line closeLine(IssuanceLedger ledger) throws java.io.IOException {
    for (IssuanceLedger.Line line : ledger.read()) {
      if (IssuanceLedger.CLOSE.equals(line.type())) {
        return line;
      }
    }
    return null;
  }

  /**
   * @param sam a SAM session over the issuer secure channel with the operator PIN verified
   * @return the SAM's TERM entry
   */
  public SamLedgerEntry terminate(BatchMetadata batch, SamClient sam, PublicKey samKey)
      throws Exception {
    if (!BatchMetadata.STATE_CLOSED.equals(batch.state)
        && !BatchMetadata.STATE_SAM_BOUND.equals(batch.state)) {
      throw new IllegalStateException(
          "Batch " + batch.name + " is " + batch.state + "; its SAM cannot be terminated");
    }
    IssuanceLedger ledger = new IssuanceLedger(batch.directory().resolve(batch.ledger));
    try (BatchLock ignored = BatchLock.acquire(batch.directory())) {
      SamLedgerEntry.Signed last = ledger.lastSamEntry();
      SamLedgerEntry.Signed term = SamLedgerEntry.Signed.parse(sam.terminate());
      if (!term.verify(samKey)
          || term.entry.type != SamLedgerEntry.TYPE_TERMINATE
          || last == null
          || term.entry.eventSeq != last.entry.eventSeq + 1
          || !Arrays.equals(term.entry.prevHead(), last.entry.head())) {
        throw new IllegalStateException(
            "The SAM's TERM entry does not verify or extend the ledger");
      }
      ledger.appendTerminate(term);
      batch.state = BatchMetadata.STATE_TERMINATED;
      batch.replace();
      return term.entry;
    }
  }
}
