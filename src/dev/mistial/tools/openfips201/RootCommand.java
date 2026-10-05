/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201;

import com.google.gson.JsonObject;
import dev.mistial.tools.openfips201.issuance.IssuanceLedger;
import dev.mistial.tools.openfips201.issuance.RootContext;
import dev.mistial.tools.openfips201.issuance.RootStationService;
import dev.mistial.tools.openfips201.issuance.TopUpAuthorization;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/** Root-station operations: the allocation registry, top-up signing and the ledger audit. */
@Command(
    name = "root",
    mixinStandardHelpOptions = true,
    description = "Root station: allocation registry, top-up signing and OPID audit.",
    subcommands = {
      RootCommand.Init.class,
      RootCommand.Allocate.class,
      RootCommand.SignTopUp.class,
      RootCommand.AuditLedger.class
    })
final class RootCommand implements Callable<Integer> {
  @Override
  public Integer call() {
    CommandLine.usage(this, System.err);
    return 2;
  }

  @Command(
      name = "init",
      mixinStandardHelpOptions = true,
      description =
          "Create the root-signed allocation registry and its head object on the root token.")
  static final class Init implements Callable<Integer> {
    @Option(names = "--producer", required = true)
    String producer;

    @Override
    public Integer call() throws Exception {
      try (RootContext context = RootContext.load(producer)) {
        new RootStationService().init(producer, context);
      }
      System.out.println("Allocation registry created for " + producer + ".");
      return 0;
    }
  }

  @Command(
      name = "allocate",
      mixinStandardHelpOptions = true,
      description = "Allocate an (IIN, batch) with its initial quota (at most 10^8).")
  static final class Allocate implements Callable<Integer> {
    @Option(names = "--producer", required = true)
    String producer;

    @Option(names = "--iin", required = true)
    int iin;

    @Option(names = "--batch", required = true)
    int batch;

    @Option(names = "--quota", required = true)
    long quota;

    @Override
    public Integer call() throws Exception {
      JsonObject line;
      try (RootContext context = RootContext.load(producer)) {
        line = new RootStationService().allocate(producer, context, iin, batch, quota);
      }
      System.out.println(
          String.format(
              "IIN %04d batch %04d allocated (registry seq %d, quota %d).",
              iin, batch, line.get("seq").getAsLong(), quota));
      return 0;
    }
  }

  @Command(
      name = "sign-top-up",
      mixinStandardHelpOptions = true,
      description =
          "Check a SAM quota top-up request against the registry and the bound SAM, record it"
              + " and sign it with the root key.")
  static final class SignTopUp implements Callable<Integer> {
    @Option(names = "--producer", required = true)
    String producer;

    @Option(names = "--request", required = true)
    Path request;

    @Option(names = "--out", required = true, description = "New authorization file.")
    Path out;

    @Override
    public Integer call() throws Exception {
      TopUpAuthorization parsed = TopUpAuthorization.read(request);
      try (RootContext context = RootContext.load(producer)) {
        new RootStationService().signTopUp(producer, context, parsed).writeNew(out);
      }
      System.out.println(
          "Top-up of " + parsed.add + " for batch " + parsed.batch + " signed: " + out);
      return 0;
    }
  }

  @Command(
      name = "audit-ledger",
      mixinStandardHelpOptions = true,
      description =
          "Verify an exported production ledger and replay every issued OPID from the root's LCG"
              + " record and IIN FF1 key. Exit 0 valid, 1 invalid.")
  static final class AuditLedger implements Callable<Integer> {
    @Option(names = "--producer", required = true)
    String producer;

    @Option(names = "--ledger", required = true, description = "ledger.jsonl from production.")
    Path ledger;

    @Option(names = "--batch", required = true, description = "IIII-NNNN.")
    String batch;

    @Override
    public Integer call() throws Exception {
      int[] parsed = RootStationService.parseBatchName(batch);
      IssuanceLedger.Report report;
      try (RootContext context = RootContext.load(producer)) {
        report =
            new RootStationService().auditLedger(producer, context, ledger, parsed[0], parsed[1]);
      }
      for (String problem : report.problems) {
        System.out.println("FAIL  " + problem);
      }
      System.out.println(
          report.valid()
              ? "Ledger audit valid: " + report.audited + " OPID(s) replayed."
              : "Ledger audit INVALID: " + report.problems.size() + " problem(s).");
      return report.valid() ? 0 : 1;
    }
  }
}
