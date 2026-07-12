/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.cardstock;

import java.io.PrintStream;
import java.nio.file.Path;

/** Formats cardstock attestation lifecycle fields for CLI operators. */
public final class CardstockReceiptPrinter {
  private CardstockReceiptPrinter() {}

  public static void printSummary(
      PrintStream out, String headline, CardstockReceipt receipt, Path receiptPath) {
    out.println(headline);
    out.println("  Instance ID:     " + value(receipt.instanceId));
    out.println("  F9 subject:      " + value(receipt.f9Subject));
    out.println("  F9 serial:       0x" + value(receipt.f9CertificateSerialHex));
    out.println("  F9 SPKI SHA-256: " + value(receipt.f9SpkiSha256));
    out.println("  F9 cert SHA-256: " + value(receipt.f9IssuerCertificateSha256));
    out.println("  Proof slot:      " + value(receipt.f9ProofSlot));
    out.println("  Proof issuer OK: " + receipt.f9ProofIssuerMatched);
    out.println("  Proof key gone:  " + receipt.proofKeyDeleted);
    out.println("  Receipt:         " + receiptPath);
  }

  private static String value(String text) {
    return text == null || text.isEmpty() ? "(missing)" : text;
  }
}
