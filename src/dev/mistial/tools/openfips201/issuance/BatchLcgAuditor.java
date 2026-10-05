/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import dev.mistial.tools.openfips201.opid.Opid;
import dev.mistial.tools.openfips201.opid.OpidCipher;
import dev.mistial.tools.openfips201.opid.OpidSequence;

/**
 * Root-station audit of a batch's OPIDs against its recorded OPID sequence: issuance number {@code
 * n >= 1} must carry {@code IIN || FF1_K(batch || lcg.at(n), ASCII(IIN)) || Luhn} ({@link
 * OpidSequence#opidAt}). It needs the LCG and the IIN FF1 key, so it never runs at a production
 * station.
 */
public final class BatchLcgAuditor {
  private final OpidSequence sequence;

  public BatchLcgAuditor(OpidSequence sequence) {
    this.sequence = sequence;
  }

  /** The auditor of the sequence recorded in a root LCG file, with FF1 through {@code cipher}. */
  public static BatchLcgAuditor of(RootBatchRecord.LcgFile record, OpidCipher cipher) {
    return new BatchLcgAuditor(OpidSequence.of(record.iin, record.batch, record.lcg(), cipher));
  }

  public OpidSequence sequence() {
    return sequence;
  }

  /** The OPID that issuance {@code seq} must carry. */
  public Opid expected(long seq) {
    return sequence.opidAt(seq);
  }

  /**
   * Requires {@code printed} to be the canonical OPID of issuance {@code seq}.
   *
   * @return the parsed OPID
   */
  public Opid require(long seq, String printed) {
    Opid actual = Opid.parseCanonical(printed);
    Opid expected = expected(seq);
    if (!expected.equals(actual)) {
      throw new IllegalStateException(
          "issuance "
              + seq
              + " carries OPID "
              + printed
              + ", the batch sequence gives "
              + expected.toPrinted());
    }
    return actual;
  }
}
