/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import java.io.PrintStream;
import java.nio.file.Path;

/** Operator summary of an issuance receipt. */
public final class IssuanceReceiptPrinter {
  private IssuanceReceiptPrinter() {}

  public static void printSummary(PrintStream out, IssuanceReceipt receipt, Path receiptPath) {
    out.println(
        IssuanceReceipt.STATUS_COMPLETED.equals(receipt.status)
            ? "Card produced."
            : "Card production failed.");
    out.println("  Status:          " + value(receipt.status));
    out.println("  Stage:           " + value(receipt.stage));
    out.println("  OPID:            " + value(receipt.sam.opid));
    out.println(
        "  Issuance seq:    "
            + (receipt.sam.issuanceSeq == 0 ? "(none)" : "" + receipt.sam.issuanceSeq));
    out.println("  OPID burned:     " + receipt.burned);
    out.println("  F9 SKI:          " + value(receipt.f9.ski));
    out.println("  F9 cert SHA-256: " + value(receipt.f9.certificateSha256));
    out.println("  Proof key gone:  " + receipt.proof.keyDeleted);
    if (receipt.identifiers != null) {
      out.println("  GUID:            " + value(receipt.identifiers.guid));
      out.println("  FASC-N:          " + value(receipt.identifiers.fascN));
    }
    if (receipt.failure != null) {
      out.println("  Failure:         " + value(receipt.failure.redactedMessage));
    }
    out.println("  Receipt:         " + receiptPath);
  }

  private static String value(String text) {
    return text == null || text.isEmpty() ? "(missing)" : text;
  }
}
