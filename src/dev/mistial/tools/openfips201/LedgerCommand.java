/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201;

import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.issuance.IssuanceLedger;
import dev.mistial.tools.openfips201.issuance.LedgerReconciler;
import dev.mistial.tools.openfips201.issuance.LedgerService;
import dev.mistial.tools.openfips201.issuance.ProductionContext;
import dev.mistial.tools.openfips201.producer.BatchMetadata;
import java.util.Arrays;
import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

/** Verification and repair of a batch issuance ledger. */
@Command(
    name = "ledger",
    mixinStandardHelpOptions = true,
    description = "Verify and reconcile a batch's hash-chained issuance ledger.",
    subcommands = {LedgerCommand.Verify.class, LedgerCommand.Reconcile.class})
final class LedgerCommand implements Callable<Integer> {
  /** Exit code of a ledger without problems whose verification reported warnings. */
  static final int EXIT_VALID_WITH_WARNINGS = 4;

  @Override
  public Integer call() {
    CommandLine.usage(this, System.err);
    return 2;
  }

  /**
   * Prints a verification report's problems and warnings and its summary line.
   *
   * @return 0 valid, 1 invalid, {@value #EXIT_VALID_WITH_WARNINGS} valid with warnings
   */
  static int summarize(IssuanceLedger.Report report, String validSummary, String subject) {
    for (String problem : report.problems) {
      System.out.println("FAIL  " + problem);
    }
    for (String warning : report.warnings) {
      System.out.println("WARN  " + warning);
    }
    if (!report.valid()) {
      System.out.println(subject + " INVALID: " + report.problems.size() + " problem(s).");
      return 1;
    }
    if (!report.warnings.isEmpty()) {
      System.out.println(
          validSummary + " WITH " + report.warnings.size() + " WARNING(S); not a clean pass.");
      return EXIT_VALID_WITH_WARNINGS;
    }
    System.out.println(validSummary);
    return 0;
  }

  @Command(
      name = "verify",
      mixinStandardHelpOptions = true,
      description =
          "Verify the ledger offline (hash chain, SAM signatures, entry types, seq continuity,"
              + " unique OPIDs and f9Ski, SAM chain, registry lines under root.pem). With --sam,"
              + " also require the live SAM to be at the ledger's last entry and DECIPHER-check"
              + " issued OPIDs. Every receipt the ledger names must exist and match the hash the"
              + " ledger last recorded for it. No OPID is recomputed here. Exit 0 valid, 1"
              + " invalid, 4 valid with warnings (a legacy v1 ledger: receipts not bound).")
  static final class Verify implements Callable<Integer> {
    @Option(names = "--producer", required = true)
    String producer;

    @Option(names = "--batch", required = true)
    String batch;

    @Option(names = "--sam", description = "Compare with the live SAM.")
    String sam;

    @Option(
        names = "--decipher-sample",
        defaultValue = "" + LedgerService.DEFAULT_DECIPHER_SAMPLE,
        description = "With --sam and an operator PIN: issued OPIDs DECIPHER-checked (0 disables).")
    int decipherSample;

    @Mixin ProduceOptions.OperatorPinOptions operatorPin = new ProduceOptions.OperatorPinOptions();

    @Override
    public Integer call() throws Exception {
      IssuanceLedger.Report report;
      try (ProductionContext context = ProductionContext.load(producer)) {
        context.requireProductionClean(producer);
        BatchMetadata record = BatchMetadata.read(producer, batch);
        if (sam == null) {
          report = new LedgerService().verify(record, context.rootCertificate());
        } else {
          byte[] pin =
              operatorPin.env == null && operatorPin.file == null || decipherSample <= 0
                  ? null
                  : operatorPin.pin();
          try {
            report =
                new LedgerService()
                    .verify(
                        record,
                        context.rootCertificate(),
                        CardTarget.parse(sam),
                        context,
                        pin,
                        decipherSample);
          } finally {
            if (pin != null) {
              Arrays.fill(pin, (byte) 0);
            }
          }
        }
      }
      if (report.deciphered > 0) {
        System.out.println(
            "DECIPHER: " + report.deciphered + " issued OPID(s) confirmed by the SAM.");
      }
      if (report.receiptsVerified > 0) {
        System.out.println(
            "Receipts: " + report.receiptsVerified + " match their ledger bindings.");
      }
      return LedgerCommand.summarize(
          report, "Ledger valid: " + report.issued + " issued.", "Ledger");
    }
  }

  @Command(
      name = "reconcile",
      mixinStandardHelpOptions = true,
      description =
          "Record a SAM event whose response was lost (ISSUE or TOP UP) from the SAM's signed"
              + " last entry; a recovered issuance is marked lost.")
  static final class Reconcile implements Callable<Integer> {
    @Option(names = "--producer", required = true)
    String producer;

    @Option(names = "--batch", required = true)
    String batch;

    @Option(names = "--sam", required = true)
    String sam;

    @Override
    public Integer call() throws Exception {
      LedgerReconciler.Outcome outcome =
          new LedgerService().reconcile(BatchMetadata.read(producer, batch), CardTarget.parse(sam));
      System.out.println("Reconcile: " + outcome);
      return 0;
    }
  }
}
