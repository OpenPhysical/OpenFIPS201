/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * Repairs a ledger that is one SAM event behind the SAM, which happens when an ISSUE or TOP UP
 * committed on the SAM but its response never reached the host.
 *
 * <p>The SAM's last entry (GET DATA LAST ENTRY) is accepted only when its signature verifies, it
 * names the batch SAM, and it extends the ledger's last SAM entry exactly (eventSeq + 1, prevHead =
 * head). A recovered ISSUE must carry the next issuance number and a canonical OPID; it is recorded
 * as an {@code issue} line followed by a {@code lost} line, because its certificate never reached a
 * card. A recovered TOP UP is recorded as a {@code topup} line, a recovered VOID as a {@code void}
 * line.
 */
public final class LedgerReconciler {
  private LedgerReconciler() {}

  /** What {@link #recover} did. */
  public enum Outcome {
    IN_SYNC,
    RECOVERED_ISSUE,
    RECOVERED_TOPUP,
    RECOVERED_VOID
  }

  public static Outcome recover(
      SamClient sam, IssuanceLedger ledger, PublicKey samKey, String receipt, String reason)
      throws IOException {
    SamLedgerEntry.Signed last = ledger.lastSamEntry();
    if (last == null) {
      throw new IllegalStateException("the ledger has no genesis line; it cannot be reconciled");
    }
    SamLedgerEntry.Signed current = SamLedgerEntry.Signed.parse(sam.lastEntry());
    if (!current.verify(samKey)) {
      throw new IllegalStateException("the SAM's last entry signature does not verify");
    }
    if (!Arrays.equals(current.entry.samSki(), last.entry.samSki())) {
      throw new IllegalStateException("the SAM's last entry names a different SAM");
    }
    if (Arrays.equals(current.entry.head(), last.entry.head())) {
      return Outcome.IN_SYNC;
    }
    if (current.entry.eventSeq != last.entry.eventSeq + 1
        || !Arrays.equals(current.entry.prevHead(), last.entry.head())) {
      throw new IllegalStateException(
          "the SAM is at event "
              + current.entry.eventSeq
              + " and the ledger at "
              + last.entry.eventSeq
              + "; more than one event is missing and cannot be recovered");
    }
    if (current.entry.type == SamLedgerEntry.TYPE_ISSUE) {
      long expected = ledger.lastIssueSeq() + 1;
      if (current.entry.issuanceSeq != expected) {
        throw new IllegalStateException(
            "the SAM's last issuance is "
                + current.entry.issuanceSeq
                + " where "
                + expected
                + " was due");
      }
      dev.mistial.tools.openfips201.opid.Opid.parseCanonical(current.entry.opid);
      ledger.appendIssue(current, null, receipt, true);
      ledger.appendLost(current.entry.issuanceSeq, current.entry.opid, reason);
      return Outcome.RECOVERED_ISSUE;
    }
    if (current.entry.type == SamLedgerEntry.TYPE_TOPUP) {
      ledger.appendTopUp(current);
      return Outcome.RECOVERED_TOPUP;
    }
    if (current.entry.type == SamLedgerEntry.TYPE_VOID) {
      ledger.appendVoid(current, receipt);
      return Outcome.RECOVERED_VOID;
    }
    throw new IllegalStateException(
        "the SAM's last entry is " + current.entry.typeName() + "; it cannot be reconciled");
  }
}
