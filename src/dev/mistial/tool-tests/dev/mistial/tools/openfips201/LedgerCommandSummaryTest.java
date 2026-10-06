/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.issuance.IssuanceLedger;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/** {@code ledger verify} and {@code root audit-ledger} never report a warning as a clean pass. */
class LedgerCommandSummaryTest {
  private static String summarize(IssuanceLedger.Report report, int[] exit) throws Exception {
    PrintStream previous = System.out;
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8.name()));
    try {
      exit[0] = LedgerCommand.summarize(report, "Ledger valid: 0 issued.", "Ledger");
    } finally {
      System.setOut(previous);
    }
    return new String(out.toByteArray(), StandardCharsets.UTF_8);
  }

  @Test
  void cleanLedgerExitsZero() throws Exception {
    int[] exit = new int[1];
    String text = summarize(new IssuanceLedger.Report(), exit);
    assertEquals(0, exit[0]);
    assertTrue(text.contains("Ledger valid"), text);
  }

  @Test
  void legacyWarningIsPrintedAndExitsWithTheWarningCode() throws Exception {
    IssuanceLedger.Report report = new IssuanceLedger.Report();
    report.warnings.add(IssuanceLedger.LEGACY_WARNING);
    int[] exit = new int[1];
    String text = summarize(report, exit);
    assertEquals(LedgerCommand.EXIT_VALID_WITH_WARNINGS, exit[0]);
    assertTrue(text.contains("WARN  " + IssuanceLedger.LEGACY_WARNING), text);
    assertTrue(text.contains("receipts not bound"), text);
    assertTrue(text.contains("WITH 1 WARNING(S)"), text);
  }

  @Test
  void problemsWinOverWarnings() throws Exception {
    IssuanceLedger.Report report = new IssuanceLedger.Report();
    report.warnings.add(IssuanceLedger.LEGACY_WARNING);
    report.problems.add("receipt x.json is missing");
    int[] exit = new int[1];
    String text = summarize(report, exit);
    assertEquals(1, exit[0]);
    assertTrue(text.contains("FAIL  receipt x.json is missing"), text);
    assertTrue(text.contains("Ledger INVALID: 1 problem(s)."), text);
  }
}
