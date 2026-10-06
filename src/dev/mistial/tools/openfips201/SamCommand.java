/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import dev.mistial.tools.openfips201.attestation.StrictDer;
import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.CardTransport;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.crypto.SecretSource;
import dev.mistial.tools.openfips201.issuance.ApduSamClient;
import dev.mistial.tools.openfips201.issuance.DecipherResult;
import dev.mistial.tools.openfips201.issuance.IssuanceService;
import dev.mistial.tools.openfips201.issuance.ProductionContext;
import dev.mistial.tools.openfips201.issuance.SamClient;
import dev.mistial.tools.openfips201.issuance.SamLedgerEntry;
import dev.mistial.tools.openfips201.issuance.SamOperationsService;
import dev.mistial.tools.openfips201.issuance.SamPersonalizationService;
import dev.mistial.tools.openfips201.issuance.SamReceiveService;
import dev.mistial.tools.openfips201.issuance.SamStatus;
import dev.mistial.tools.openfips201.issuance.TopUpAuthorization;
import dev.mistial.tools.openfips201.producer.BatchMetadata;
import dev.mistial.tools.openfips201.producer.BatchRules;
import dev.mistial.tools.openfips201.producer.ProducerSetupService;
import dev.mistial.tools.openfips201.producer.StationGuard;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import pro.javacard.gp.keys.PlaintextKeys;

/**
 * Issuer SAM lifecycle. {@code personalize} runs at the root station (root custody and SAM, never a
 * card); every other subcommand runs at the production station.
 */
@Command(
    name = "sam",
    mixinStandardHelpOptions = true,
    description = "Personalize (root station) and operate (production station) Issuer SAMs.",
    subcommands = {
      SamCommand.Personalize.class,
      SamCommand.Receive.class,
      SamCommand.Status.class,
      SamCommand.TopUp.class,
      SamCommand.Decipher.class,
      SamCommand.VoidIssuance.class,
      SamCommand.ChangePin.class,
      SamCommand.Terminate.class
    })
final class SamCommand implements Callable<Integer> {
  @Override
  public Integer call() {
    CommandLine.usage(this, System.err);
    return 2;
  }

  @Command(
      name = "personalize",
      mixinStandardHelpOptions = true,
      description =
          "Root station: bind a freshly installed Issuer SAM to an allocated (IIN, batch) in one"
              + " step (LCG, wrapped FF1 key, SAM key and certificate, LOCK) and write the"
              + " root-signed handoff bundle for a production station.")
  static final class Personalize implements Callable<Integer> {
    @Option(names = "--producer", required = true)
    String producer;

    @Option(names = "--iin", required = true)
    int iin;

    @Option(names = "--batch", required = true, description = "Batch number 0..9999.")
    int batch;

    @Option(names = "--sam", required = true, description = "SAM reader: pcsc: or zmq:.")
    String sam;

    @Option(
        names = "--station",
        required = true,
        description = "Imported production station that receives the SAM.")
    String station;

    @Option(names = "--bundle-out", required = true, description = "New sam-handoff.json file.")
    Path bundleOut;

    @Option(names = "--sam-subject", description = "SAM certificate subject template.")
    String samSubject;

    @Option(names = "--sam-validity-days", defaultValue = "" + BatchRules.DEFAULT_SAM_VALIDITY_DAYS)
    int samValidityDays;

    @Option(names = "--f9-validity-days", defaultValue = "" + BatchRules.DEFAULT_F9_VALIDITY_DAYS)
    int f9ValidityDays;

    @Option(names = "--install", description = "Install the SAM applet instance first.")
    boolean install;

    @Option(names = "--sam-cap", description = "With --install: load this SAM CAP first.")
    Path samCap;

    @Option(
        names = "--sam-stock-key-env",
        description = "Environment variable with the SAM's stock SCP03 key.")
    String samStockKeyEnv;

    @Option(names = "--sam-stock-key-file", description = "Owner-only file with that key.")
    String samStockKeyFile;

    @Option(names = "--yes", description = "Confirm mutating a physical SAM.")
    boolean yes;

    @Override
    public Integer call() throws Exception {
      if (samCap != null && !install) {
        throw new IllegalArgumentException("--sam-cap requires --install");
      }
      if (!sam.startsWith("zmq:") && !yes) {
        throw new IllegalArgumentException("sam personalize requires --yes for a pcsc: SAM");
      }
      byte[] stockKey =
          SecretSource.of("--sam-stock-key", null, samStockKeyEnv, samStockKeyFile).hex();
      if (stockKey == null) {
        if (!sam.startsWith("zmq:")) {
          throw new IllegalArgumentException(
              "--sam-stock-key-env or --sam-stock-key-file is required for a pcsc: SAM");
        }
        stockKey = PlaintextKeys.DEFAULT_KEY();
      }
      try {
        IssuanceService.PersonalizeRequest request = new IssuanceService.PersonalizeRequest();
        request.producer = producer;
        request.iin = iin;
        request.batch = batch;
        request.station = station;
        request.sam = CardTarget.parse(sam);
        request.samStockKey = stockKey;
        request.samSubjectTemplate = samSubject;
        request.samValidityDays = samValidityDays;
        request.f9ValidityDays = f9ValidityDays;
        request.install = install;
        request.samCap = samCap;
        request.bundleOut = bundleOut;
        SamPersonalizationService.Result result = new IssuanceService().personalize(request);
        System.out.println(
            "SAM " + result.samId + " bound to " + BatchRules.batchName(iin, batch) + ".");
        System.out.println("Handoff bundle: " + result.bundle + " (for station " + station + ")");
        System.out.println("Genesis head:   " + HexUtil.format(result.genesis.head()));
        return 0;
      } finally {
        Arrays.fill(stockKey, (byte) 0);
      }
    }
  }

  @Command(
      name = "receive",
      mixinStandardHelpOptions = true,
      description =
          "Production station: verify a root-signed handoff bundle, take over its SAM (rotate its"
              + " keys to this station's derived keys, set the operator PIN) and create the batch.")
  static final class Receive implements Callable<Integer> {
    @Option(names = "--producer", required = true)
    String producer;

    @Option(names = "--bundle", required = true, description = "sam-handoff.json.")
    Path bundle;

    @Option(names = "--sam", required = true)
    String sam;

    @Mixin ProduceOptions.OperatorPinOptions operatorPin = new ProduceOptions.OperatorPinOptions();

    @Option(
        names = "--stock-key-out",
        description =
            "Write the new batch stock SCP03 key to this new owner-only file instead of printing.")
    Path stockKeyOut;

    @Option(names = "--yes", description = "Confirm mutating a physical SAM.")
    boolean yes;

    @Override
    public Integer call() throws Exception {
      if (!sam.startsWith("zmq:") && !yes) {
        throw new IllegalArgumentException("sam receive requires --yes for a pcsc: SAM");
      }
      byte[] pin = operatorPin.pin();
      try {
        SamReceiveService.Result result =
            new IssuanceService()
                .receive(producer, CardTarget.parse(sam), bundle, pin, stockKeyOut);
        System.out.println(
            "Batch " + result.batch.name + " received (SAM " + result.batch.sam.samId + ").");
        if (result.stockKey != null) {
          System.out.println("Stock SCP03 master key: " + result.stockKey);
        } else {
          System.out.println("Stock SCP03 master key written to: " + stockKeyOut);
        }
        System.out.println("Stock SCP03 KCV: " + result.batch.stockScp.kcv);
        return 0;
      } finally {
        Arrays.fill(pin, (byte) 0);
      }
    }
  }

  @Command(
      name = "status",
      mixinStandardHelpOptions = true,
      description = "Read the SAM's STATUS signed over a fresh nonce and verified with sam.pem.")
  static final class Status implements Callable<Integer> {
    @Option(names = "--producer", required = true)
    String producer;

    @Option(names = "--batch", required = true)
    String batch;

    @Option(names = "--sam", required = true)
    String sam;

    @Option(names = "--json", description = "Print JSON.")
    boolean json;

    @Override
    public Integer call() throws Exception {
      StationGuard.requireStation(producer, ProducerSetupService.STATION_PRODUCTION);
      BatchMetadata metadata = BatchMetadata.read(producer, batch);
      PublicKey samKey =
          StrictDer.parseCertificate(IssuanceService.samCertificate(metadata)).getPublicKey();
      SamStatus status;
      try (CardTransport transport = CardTarget.parse(sam).openTransport()) {
        status =
            new SamOperationsService().signedStatus(ApduSamClient.selectPlain(transport), samKey);
      }
      if (json) {
        JsonObject out = new JsonObject();
        out.addProperty("lifecycle", SamStatus.lifecycleName(status.lifecycle));
        out.addProperty("iin", status.iin);
        out.addProperty("batch", status.batch);
        out.addProperty("issued", status.issued);
        out.addProperty("quota", status.quota);
        out.addProperty("lastTopUpTs", status.lastTopUpTs);
        out.addProperty("eventSeq", status.eventSeq);
        out.addProperty("chainHead", HexUtil.format(status.chainHead()));
        out.addProperty("samSki", HexUtil.format(status.samSki()));
        out.addProperty("pinTries", status.pinTries);
        out.addProperty("allocationSeq", status.allocationSeq);
        out.addProperty("registryHead", HexUtil.format(status.registryHead()));
        System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(out));
      } else {
        System.out.println("Lifecycle:  " + SamStatus.lifecycleName(status.lifecycle));
        System.out.println("Issued:     " + status.issued + " of " + status.quota);
        System.out.println("Event seq:  " + status.eventSeq);
        System.out.println("Chain head: " + HexUtil.format(status.chainHead()));
        System.out.println("SAM SKI:    " + HexUtil.format(status.samSki()));
        System.out.println("PIN tries:  " + status.pinTries);
      }
      return 0;
    }
  }

  @Command(
      name = "decipher",
      mixinStandardHelpOptions = true,
      description =
          "Reverse an OPID on the batch SAM (DECIPHER) to its batch and issuance number. The"
              + " production station holds no FF1 key; the SAM is the only authority.")
  static final class Decipher implements Callable<Integer> {
    @Option(names = "--producer", required = true)
    String producer;

    @Option(names = "--batch", required = true)
    String batch;

    @Option(names = "--sam", required = true)
    String sam;

    @Option(names = "--opid", required = true, description = "17-digit OPID.")
    String opid;

    @Mixin ProduceOptions.OperatorPinOptions operatorPin = new ProduceOptions.OperatorPinOptions();

    @Override
    public Integer call() throws Exception {
      byte[] pin = operatorPin.pin();
      try {
        DecipherResult result =
            new IssuanceService().decipher(producer, batch, CardTarget.parse(sam), pin, opid);
        System.out.println("Batch:      " + String.format("%04d", result.batch));
        System.out.println("Same batch: " + result.sameBatch);
        if (result.sameBatch) {
          System.out.println("Issuance:   " + result.count);
          System.out.println("Issued:     " + result.issued);
        }
        return 0;
      } finally {
        Arrays.fill(pin, (byte) 0);
      }
    }
  }

  @Command(
      name = "void",
      mixinStandardHelpOptions = true,
      description =
          "Void an issued OPID on the SAM: the SAM signs a VOID entry, recorded in the ledger and"
              + " exported in voids.json for relying parties.")
  static final class VoidIssuance implements Callable<Integer> {
    @Option(names = "--producer", required = true)
    String producer;

    @Option(names = "--batch", required = true)
    String batch;

    @Option(names = "--sam", required = true)
    String sam;

    @Option(names = "--seq", required = true, description = "Issuance number to void.")
    long seq;

    @Option(
        names = "--reason",
        defaultValue = "" + SamClient.VOID_UNSPECIFIED,
        description = "Reason code 0..255 (0 unspecified, 1 reissue).")
    int reason;

    @Mixin ProduceOptions.OperatorPinOptions operatorPin = new ProduceOptions.OperatorPinOptions();

    @Override
    public Integer call() throws Exception {
      byte[] pin = operatorPin.pin();
      try {
        SamLedgerEntry entry =
            new IssuanceService()
                .voidIssuance(producer, batch, CardTarget.parse(sam), pin, seq, reason);
        System.out.println("Issuance " + entry.issuanceSeq + " (" + entry.opid + ") voided.");
        return 0;
      } finally {
        Arrays.fill(pin, (byte) 0);
      }
    }
  }

  @Command(
      name = "change-pin",
      mixinStandardHelpOptions = true,
      description = "Change the SAM operator PIN.")
  static final class ChangePin implements Callable<Integer> {
    @Option(names = "--producer", required = true)
    String producer;

    @Option(names = "--batch", required = true)
    String batch;

    @Option(names = "--sam", required = true)
    String sam;

    @Mixin ProduceOptions.OperatorPinOptions operatorPin = new ProduceOptions.OperatorPinOptions();

    @Option(names = "--new-pin-env", description = "Environment variable with the new PIN.")
    String newPinEnv;

    @Option(names = "--new-pin-file", description = "Owner-only file with the new PIN.")
    String newPinFile;

    @Override
    public Integer call() throws Exception {
      byte[] pin = operatorPin.pin();
      byte[] newPin = null;
      try {
        newPin = ProduceOptions.OperatorPinOptions.pin("--new-pin", newPinEnv, newPinFile);
        new IssuanceService().changePin(producer, batch, CardTarget.parse(sam), pin, newPin);
        System.out.println("SAM operator PIN changed.");
        return 0;
      } finally {
        Arrays.fill(pin, (byte) 0);
        if (newPin != null) {
          Arrays.fill(newPin, (byte) 0);
        }
      }
    }
  }

  @Command(
      name = "terminate",
      mixinStandardHelpOptions = true,
      description =
          "Terminate the batch SAM: its final TERM entry is recorded in the ledger and its key is"
              + " cleared. Irreversible. Close the batch first ('batch close').")
  static final class Terminate implements Callable<Integer> {
    @Option(names = "--producer", required = true)
    String producer;

    @Option(names = "--batch", required = true)
    String batch;

    @Option(names = "--sam", required = true)
    String sam;

    @Mixin ProduceOptions.OperatorPinOptions operatorPin = new ProduceOptions.OperatorPinOptions();

    @Option(names = "--yes", description = "Confirm the irreversible termination.")
    boolean yes;

    @Override
    public Integer call() throws Exception {
      if (!yes) {
        throw new IllegalArgumentException("--yes is required to terminate a SAM");
      }
      if (!BatchMetadata.STATE_CLOSED.equals(BatchMetadata.read(producer, batch).state)) {
        System.err.println(
            "Warning: batch " + batch + " is not closed; terminating its operational SAM.");
      }
      byte[] pin = operatorPin.pin();
      try {
        SamLedgerEntry term =
            new IssuanceService().terminateSam(producer, batch, CardTarget.parse(sam), pin);
        System.out.println(
            "SAM terminated after " + term.issued + " issuance(s); TERM entry recorded.");
        return 0;
      } finally {
        Arrays.fill(pin, (byte) 0);
      }
    }
  }

  @Command(
      name = "top-up",
      mixinStandardHelpOptions = true,
      description =
          "Raise the SAM quota by file exchange with the root station: write a request with"
              + " --add --request-out, have it signed with 'root sign-top-up', then apply the"
              + " authorization with --authorization-in.")
  static final class TopUp implements Callable<Integer> {
    @Option(names = "--producer", required = true)
    String producer;

    @Option(names = "--batch", required = true)
    String batch;

    @Option(names = "--sam", required = true)
    String sam;

    @Option(names = "--add", description = "With --request-out: issuances to add.")
    Long add;

    @Option(names = "--request-out", description = "Write a request for the root station.")
    Path requestOut;

    @Option(names = "--authorization-in", description = "Apply a root-signed authorization.")
    Path authorizationIn;

    @Override
    public Integer call() throws Exception {
      if ((requestOut == null) == (authorizationIn == null)) {
        throw new IllegalArgumentException(
            "use exactly one of --request-out (with --add) or --authorization-in");
      }
      try (ProductionContext context = ProductionContext.load(producer)) {
        IssuanceService service = new IssuanceService();
        if (requestOut != null) {
          if (add == null) {
            throw new IllegalArgumentException("--request-out requires --add");
          }
          service
              .topUpRequest(producer, batch, CardTarget.parse(sam), add, context)
              .writeNew(requestOut);
          System.out.println("Top-up request written: " + requestOut);
          return 0;
        }
        SamStatus status =
            service.topUpApply(
                producer,
                batch,
                CardTarget.parse(sam),
                TopUpAuthorization.read(authorizationIn),
                context);
        System.out.println("SAM quota is now " + status.quota + " (" + status.issued + " issued).");
      }
      return 0;
    }
  }
}
