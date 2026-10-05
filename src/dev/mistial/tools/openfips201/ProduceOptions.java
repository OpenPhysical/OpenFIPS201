/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201;

import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.crypto.SecretSource;
import dev.mistial.tools.openfips201.issuance.CardIssuanceOrchestrator;
import dev.mistial.tools.openfips201.issuance.IssuanceReceiptPrinter;
import dev.mistial.tools.openfips201.issuance.IssuanceService;
import java.io.PrintStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

/** Options and execution of {@code card produce}. */
class ProduceOptions {
  static final String DEFAULT_CAP = "build/bin/OpenFIPS201-standard-CS2-attestation-true.cap";

  @Option(names = "--producer", required = true)
  String producer;

  @Option(names = "--batch", required = true)
  String batch;

  @Option(names = "--target", description = "Card reader: pcsc:<reader> or zmq:<endpoint>.")
  String target;

  @Option(
      names = "--sam",
      required = true,
      description = "Issuer SAM reader: pcsc:<reader> or zmq:<endpoint>.")
  String sam;

  @Option(names = "--cap", description = "OpenFIPS201 CAP with attestation enabled.")
  Path cap = Paths.get(DEFAULT_CAP);

  @Mixin StockKeyOptions stockKey = new StockKeyOptions();

  @Mixin OperatorPinOptions operatorPin = new OperatorPinOptions();

  @Option(names = "--yes", description = "Confirm physical-card mutations.")
  boolean yes;

  @Option(
      names = "--allow-dev-custody",
      description = "Permit a softhsm-dev producer to issue to a pcsc: card.")
  boolean allowDevCustody;

  @Option(
      names = "--reissue",
      description =
          "The card is a burned card of this batch: void its OPID on the SAM, delete and reinstall"
              + " the applet, and produce it with the next OPID.")
  boolean reissue;

  /**
   * Runs the issuance and prints the receipt summary.
   *
   * @return the orchestrator exit code (0, 1 or 3)
   */
  int run(PrintStream out) throws Exception {
    if (target == null || target.isEmpty()) {
      throw new IllegalArgumentException("--target is required");
    }
    SecretSource.of(StockKeyOptions.OPTION, stockKey.literal, stockKey.env, stockKey.file)
        .refuseLiteralFor(target);
    if (!target.startsWith("zmq:") && !yes) {
      throw new IllegalArgumentException("card produce requires --yes for a pcsc: target");
    }
    byte[] key = stockKey.keyOrPrompt(target, "Stock SCP03 master key");
    byte[] pin = null;
    try {
      pin = operatorPin.pin();
      IssuanceService.ProduceRequest request = new IssuanceService.ProduceRequest();
      request.producer = producer;
      request.batch = batch;
      request.target = CardTarget.parse(target);
      request.sam = CardTarget.parse(sam);
      request.stockScpKey = key;
      request.operatorPin = pin;
      request.cap = cap;
      request.allowDevCustody = allowDevCustody;
      request.reissue = reissue;
      CardIssuanceOrchestrator.Result result = new IssuanceService().produce(request);
      IssuanceReceiptPrinter.printSummary(out, result.record, result.receipt);
      return result.exitCode;
    } finally {
      Arrays.fill(key, (byte) 0);
      if (pin != null) {
        Arrays.fill(pin, (byte) 0);
      }
    }
  }

  /** The SAM operator PIN from the environment, an owner-only file, or the console. */
  static final class OperatorPinOptions {
    static final String OPTION = "--operator-pin";

    @Option(
        names = OPTION + "-env",
        description = "Environment variable with the SAM operator PIN.")
    String env;

    @Option(names = OPTION + "-file", description = "Owner-only file with the SAM operator PIN.")
    String file;

    byte[] pin() throws Exception {
      return pin(OPTION, env, file);
    }

    /** A SAM PIN (6 to 16 printable ASCII characters) from {@code env}, {@code file} or prompt. */
    static byte[] pin(String option, String env, String file) throws Exception {
      char[] chars = SecretSource.of(option, null, env, file).charsOrPrompt("SAM operator PIN");
      try {
        if (chars.length < 6 || chars.length > 16) {
          throw new IllegalArgumentException("the SAM operator PIN must be 6 to 16 characters");
        }
        byte[] bytes = new byte[chars.length];
        for (int i = 0; i < chars.length; i++) {
          if (chars[i] < 0x20 || chars[i] > 0x7E) {
            Arrays.fill(bytes, (byte) 0);
            throw new IllegalArgumentException("the SAM operator PIN must be printable ASCII");
          }
          bytes[i] = (byte) chars[i];
        }
        return bytes;
      } finally {
        Arrays.fill(chars, '\0');
      }
    }
  }
}
