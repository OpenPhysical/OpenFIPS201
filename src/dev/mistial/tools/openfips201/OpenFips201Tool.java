/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201;

import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.crypto.PemFiles;
import dev.mistial.tools.openfips201.crypto.SecretSource;
import dev.mistial.tools.openfips201.emulator.ZmqApduServer;
import dev.mistial.tools.openfips201.gp.CardDiversificationDataService;
import dev.mistial.tools.openfips201.gp.CardKeyPreflightService;
import dev.mistial.tools.openfips201.gp.CardKeyRollService;
import dev.mistial.tools.openfips201.gp.CardKeyRotationService;
import dev.mistial.tools.openfips201.gp.DerivedScpKeys;
import dev.mistial.tools.openfips201.gp.IssuerCardKeyService;
import dev.mistial.tools.openfips201.gp.Scp03Kdf3DerivationService;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11AdminService;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11KeyTransport;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11Session;
import dev.mistial.tools.openfips201.producer.BatchMetadata;
import dev.mistial.tools.openfips201.producer.IinKeyService;
import dev.mistial.tools.openfips201.producer.ProducerPaths;
import dev.mistial.tools.openfips201.producer.ProducerSetupService;
import dev.mistial.tools.openfips201.producer.TrustExportService;
import dev.mistial.tools.openfips201.profiles.IssuerProfile;
import dev.mistial.tools.openfips201.profiles.ProfileLoader;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

@Command(
    name = "openfips201",
    mixinStandardHelpOptions = true,
    description = "Discover, provision, attest, and manage OpenFIPS201 cards.",
    footer = {
      "",
      "Start with 'openfips201 cards list' to find a reader.",
      "Use 'openfips201 <command> --help' for command-specific options."
    },
    subcommands = {
      CardsCommand.class,
      EmulatorCommand.class,
      AppletCommand.class,
      CryptoCommand.class,
      dev.mistial.tools.openfips201.attestation.AttestationCommand.class,
      OpenFips201Tool.Gp.class,
      OpenFips201Tool.Cardstock.class,
      OpenFips201Tool.Producer.class,
      RootCommand.class,
      StationCommand.class,
      OpenFips201Tool.Batch.class,
      SamCommand.class,
      OpenFips201Tool.Card.class,
      LedgerCommand.class,
      ProvisionCommand.class,
      OpenFips201Tool.Interactive.class
    })
public final class OpenFips201Tool implements Callable<Integer> {
  public static void main(String[] args) {
    CommandLine commandLine = new CommandLine(new OpenFips201Tool());
    commandLine.setExecutionExceptionHandler(
        (exception, parsedCommand, parseResult) -> {
          parsedCommand.getErr().println("Error: " + errorMessage(exception));
          if (Boolean.getBoolean("openfips201.debug")) {
            exception.printStackTrace(parsedCommand.getErr());
          }
          return 1;
        });
    System.exit(commandLine.execute(args));
  }

  @Override
  public Integer call() {
    CommandLine.usage(this, System.err);
    return 2;
  }

  @Command(
      name = "gp",
      mixinStandardHelpOptions = true,
      description = "Inspect and manage GlobalPlatform card keys.",
      subcommands = {Gp.Card.class, Gp.Keys.class})
  static final class Gp implements Callable<Integer> {
    @Override
    public Integer call() {
      CommandLine.usage(this, System.err);
      return 2;
    }

    @Command(
        name = "card",
        mixinStandardHelpOptions = true,
        description = "Inspect GlobalPlatform card data.",
        subcommands = Card.Kdd.class)
    static final class Card implements Callable<Integer> {
      @Override
      public Integer call() {
        CommandLine.usage(this, System.err);
        return 2;
      }

      @Command(
          name = "kdd",
          mixinStandardHelpOptions = true,
          description = "Read the 10-byte SCP key diversification data from INITIALIZE UPDATE.")
      static final class Kdd implements Callable<Integer> {
        @Option(names = "--target", required = true)
        String target;

        @Option(
            names = "--host-challenge",
            description = "8-byte host challenge hex; random by default.")
        String hostChallenge;

        @Option(
            names = "--raw",
            description = "Also print the raw INITIALIZE UPDATE response data.")
        boolean raw;

        @Override
        public Integer call() throws Exception {
          CardDiversificationDataService service = new CardDiversificationDataService();
          CardDiversificationDataService.Result result =
              hostChallenge == null
                  ? service.readKdd(CardTarget.parse(target))
                  : service.readKdd(CardTarget.parse(target), HexUtil.parse(hostChallenge));
          System.out.println("KDD " + HexUtil.format(result.kdd));
          if (raw) {
            System.out.println(
                "INITIALIZE UPDATE " + HexUtil.format(result.initializeUpdateResponse));
          }
          return 0;
        }
      }
    }

    @Command(
        name = "keys",
        mixinStandardHelpOptions = true,
        description = "Derive, validate, and rotate SCP03 keys.",
        subcommands = {
          Keys.Derive.class,
          Keys.DeriveCard.class,
          Keys.Rotate.class,
          Keys.Preflight.class,
          Keys.Keyroll.class
        })
    static final class Keys implements Callable<Integer> {
      @Override
      public Integer call() {
        CommandLine.usage(this, System.err);
        return 2;
      }

      @Command(
          name = "derive",
          mixinStandardHelpOptions = true,
          description = "Derive SCP03 KDF3 keys through PKCS#11 and print KCVs.")
      static final class Derive extends Pkcs11Options implements Callable<Integer> {
        @Option(
            names = "--kdd",
            required = true,
            description = "10-byte card key diversification data hex.")
        String kdd;

        @Option(names = "--key-version", defaultValue = "1")
        int keyVersion;

        @Override
        public Integer call() throws Exception {
          DerivedScpKeys keys =
              new Scp03Kdf3DerivationService().derive(pkcs11(), HexUtil.parse(kdd), keyVersion);
          System.out.println("ENC KCV " + keys.encKcv);
          System.out.println("MAC KCV " + keys.macKcv);
          System.out.println("DEK KCV " + keys.dekKcv);
          return 0;
        }
      }

      @Command(
          name = "derive-card",
          mixinStandardHelpOptions = true,
          description =
              "Read KDD from a card, derive SCP03 KDF3 keys through PKCS#11, and print KCVs.")
      static final class DeriveCard extends Pkcs11Options implements Callable<Integer> {
        @Option(names = "--target", required = true)
        String target;

        @Option(
            names = "--host-challenge",
            description = "8-byte host challenge hex; random by default.")
        String hostChallenge;

        @Option(names = "--key-version", defaultValue = "1")
        int keyVersion;

        @Override
        public Integer call() throws Exception {
          CardDiversificationDataService service = new CardDiversificationDataService();
          CardDiversificationDataService.Result kdd =
              hostChallenge == null
                  ? service.readKdd(CardTarget.parse(target))
                  : service.readKdd(CardTarget.parse(target), HexUtil.parse(hostChallenge));
          DerivedScpKeys keys =
              new Scp03Kdf3DerivationService().derive(pkcs11(), kdd.kdd, keyVersion);
          System.out.println("KDD " + HexUtil.format(kdd.kdd));
          System.out.println("ENC KCV " + keys.encKcv);
          System.out.println("MAC KCV " + keys.macKcv);
          System.out.println("DEK KCV " + keys.dekKcv);
          return 0;
        }
      }

      @Command(
          name = "rotate",
          mixinStandardHelpOptions = true,
          description = "Rotate card SCP keys and verify the new keyset.")
      static final class Rotate extends ScpOptions implements Callable<Integer> {
        @Mixin Pkcs11Options pkcs11 = new Pkcs11Options();

        @Option(
            names = "--kdd",
            description =
                "Expected 10-byte card key diversification data hex; the KDD is always read from"
                    + " the card and a mismatch is refused.")
        String kdd;

        @Option(names = "--new-key-version", defaultValue = "1")
        int newKeyVersion;

        @Override
        public Integer call() throws Exception {
          CardTarget card = CardTarget.parse(target);
          ScpConfig current = scp();
          byte[] cardKdd =
              CardDiversificationDataService.requireExpectedKdd(
                  new CardDiversificationDataService().readKdd(card).kdd,
                  kdd == null ? null : HexUtil.parse(kdd));
          DerivedScpKeys keys =
              new Scp03Kdf3DerivationService().derive(pkcs11.pkcs11(), cardKdd, newKeyVersion);
          new CardKeyRotationService().rotate(card, current, keys);
          System.out.println(
              "SCP keys rotated. ENC/MAC/DEK KCVs: "
                  + keys.encKcv
                  + " "
                  + keys.macKcv
                  + " "
                  + keys.dekKcv);
          return 0;
        }
      }

      @Command(
          name = "preflight",
          mixinStandardHelpOptions = true,
          description = "Validate an issuer GP key rotation without mutating the card.")
      static final class Preflight implements Callable<Integer> {
        @Option(names = "--profile", required = true)
        String profile;

        @Option(names = "--target", required = true)
        String target;

        @Option(names = "--direction", required = true, description = "forward or backward")
        String direction;

        @Option(
            names = "--kdd",
            description =
                "Expected 10-byte card key diversification data hex; the KDD is always read from"
                    + " the card and a mismatch is refused.")
        String kdd;

        @Option(names = "--stock-scp", defaultValue = "scp03")
        String stockScp;

        @Option(names = "--stock-scp-key-version", defaultValue = "1")
        int stockScpKeyVersion;

        @Mixin StockKeyOptions stockKey = new StockKeyOptions();

        @Override
        public Integer call() throws Exception {
          IssuerProfile loaded = ProfileLoader.load(profile);
          IssuerCardKeyService issuerKeys = new IssuerCardKeyService();
          CardTarget card = CardTarget.parse(target);
          ScpConfig override = stockKey.override(stockScp, stockScpKeyVersion, target);
          ScpConfig stock = override == null ? issuerKeys.stockScp(loaded) : override;
          byte[] parsedKdd = null;
          if ("backward".equalsIgnoreCase(direction)) {
            // Backward preflight authenticates with profile keys, which are derived from the
            // card's own KDD.
            parsedKdd =
                CardDiversificationDataService.requireExpectedKdd(
                    new CardDiversificationDataService().readKdd(card).kdd,
                    kdd == null ? null : HexUtil.parse(kdd));
          } else if (kdd != null) {
            parsedKdd = HexUtil.parse(kdd);
          }
          DerivedScpKeys profileKeys =
              parsedKdd == null ? null : issuerKeys.deriveCardKeys(loaded, parsedKdd);

          CardKeyPreflightService.Request request = new CardKeyPreflightService.Request();
          request.target = card;
          request.profile = loaded;
          request.profilePath = profile;
          request.kdd = parsedKdd;
          request.stockScpKeySupplied = override != null;
          if ("forward".equalsIgnoreCase(direction)) {
            request.current = stock;
            request.targetKeys = profileKeys;
          } else if ("backward".equalsIgnoreCase(direction)) {
            if (profileKeys == null) {
              throw new IllegalArgumentException("--kdd is required for backward preflight");
            }
            request.current = profileKeys.config;
            request.targetKeys = DerivedScpKeys.fromConfig(stock);
          } else {
            throw new IllegalArgumentException("--direction must be forward or backward");
          }
          CardKeyPreflightService.Result result = new CardKeyPreflightService().preflight(request);
          System.out.println("SCP key rotation preflight passed.");
          System.out.println("KDD " + HexUtil.format(result.kdd));
          System.out.println("Current key version " + result.currentKeyVersion);
          System.out.println("Target key version " + result.targetKeyVersion);
          System.out.println("ENC KCV " + result.targetEncKcv);
          System.out.println("MAC KCV " + result.targetMacKcv);
          System.out.println("DEK KCV " + result.targetDekKcv);
          if (result.rollbackCommand != null) {
            System.out.println("Rollback " + result.rollbackCommand);
            if (result.rollbackRequiresStockScpKey) {
              System.out.println("Supply the stock SCP key again when running the rollback.");
            }
          } else if (result.rollbackUnavailableReason != null) {
            System.out.println("Recovery: " + result.rollbackUnavailableReason);
          }
          return 0;
        }
      }

      @Command(
          name = "keyroll",
          mixinStandardHelpOptions = true,
          description = "Roll card SCP keys between stock/batch and profile-derived issuer keys.",
          subcommands = {Keyroll.Forward.class, Keyroll.Backward.class})
      static final class Keyroll implements Callable<Integer> {
        @Override
        public Integer call() {
          CommandLine.usage(this, System.err);
          return 2;
        }

        static class Options {
          @Option(names = "--profile", required = true)
          String profile;

          @Option(names = "--target", required = true)
          String target;

          @Option(
              names = "--kdd",
              description =
                  "Expected 10-byte card key diversification data hex; the KDD is always read from"
                      + " the card and a mismatch is refused.")
          String kdd;

          @Option(names = "--yes", description = "Confirm physical-card mutations.")
          boolean yes;

          @Option(names = "--stock-scp", defaultValue = "scp03")
          String stockScp;

          @Option(names = "--stock-scp-key-version", defaultValue = "1")
          int stockScpKeyVersion;

          @Mixin StockKeyOptions stockKey = new StockKeyOptions();

          CardKeyRollService.Request request(CardKeyRollService.Direction direction)
              throws Exception {
            CardKeyRollService.Request request = new CardKeyRollService.Request();
            request.target = CardTarget.parse(target);
            request.profile = ProfileLoader.load(profile);
            request.direction = direction;
            request.kdd = kdd == null ? null : HexUtil.parse(kdd);
            request.yes = yes;
            request.stockScpOverride = stockKey.override(stockScp, stockScpKeyVersion, target);
            return request;
          }

          void print(CardKeyRollService.Result result) {
            System.out.println("SCP keys rolled " + result.direction.name().toLowerCase() + ".");
            System.out.println("KDD " + HexUtil.format(result.kdd));
            System.out.println("Current key version " + result.currentKeyVersion);
            System.out.println("Target key version " + result.targetKeyVersion);
            System.out.println("ENC KCV " + result.targetKeys.encKcv);
            System.out.println("MAC KCV " + result.targetKeys.macKcv);
            System.out.println("DEK KCV " + result.targetKeys.dekKcv);
          }
        }

        @Command(
            name = "forward",
            mixinStandardHelpOptions = true,
            description = "Roll stock/batch keys to profile-derived issuer keys.")
        static final class Forward extends Options implements Callable<Integer> {
          @Override
          public Integer call() throws Exception {
            print(new CardKeyRollService().roll(request(CardKeyRollService.Direction.FORWARD)));
            return 0;
          }
        }

        @Command(
            name = "backward",
            mixinStandardHelpOptions = true,
            description = "Roll profile-derived issuer keys back to stock/batch keys.")
        static final class Backward extends Options implements Callable<Integer> {
          @Override
          public Integer call() throws Exception {
            print(new CardKeyRollService().roll(request(CardKeyRollService.Direction.BACKWARD)));
            return 0;
          }
        }
      }
    }
  }

  @Command(
      name = "cardstock",
      mixinStandardHelpOptions = true,
      description = "Prepare issuer cardstock (deprecated; use 'card produce').",
      subcommands = Cardstock.Prepare.class)
  static final class Cardstock implements Callable<Integer> {
    @Override
    public Integer call() {
      CommandLine.usage(this, System.err);
      return 2;
    }

    @Command(
        name = "prepare",
        mixinStandardHelpOptions = true,
        description =
            "Deprecated alias of 'card produce': issues one card through the batch Issuer SAM.")
    static final class Prepare implements Callable<Integer> {
      @Mixin ProduceOptions produce = new ProduceOptions();

      @Override
      public Integer call() throws Exception {
        System.err.println(
            "Warning: 'cardstock prepare' is deprecated; use 'openfips201 card produce'.");
        return produce.run(System.out);
      }
    }
  }

  @Command(
      name = "producer",
      mixinStandardHelpOptions = true,
      description = "Create and manage issuer producer profiles.",
      subcommands = {
        Producer.Setup.class,
        Producer.Destroy.class,
        Producer.Root.class,
        Producer.ExportTrust.class,
        Producer.Iin.class
      })
  static final class Producer implements Callable<Integer> {
    @Override
    public Integer call() {
      CommandLine.usage(this, System.err);
      return 2;
    }

    @Command(
        name = "setup",
        mixinStandardHelpOptions = true,
        description =
            "Create or complete an issuer producer profile and its root CA and card-master keys."
                + " Re-running reuses existing keys.")
    static final class Setup implements Callable<Integer> {
      @Option(names = "--name", required = true)
      String name;

      @Option(
          names = "--pkcs11-module",
          description = "PKCS#11 module of an HSM whose token is already initialized.")
      String module;

      @Option(names = "--pkcs11-token-label")
      String tokenLabel;

      @Option(names = "--pkcs11-pin-env", description = "Environment variable with the user PIN.")
      String pinEnv;

      @Option(
          names = "--pkcs11-pin-file",
          description = "Owner-only file with the user PIN. Without either, the PIN is prompted.")
      String pinFile;

      @Option(
          names = "--dev-softhsm",
          description =
              "Development custody: keys live in a SoftHSM2 file token whose user PIN is stored"
                  + " beside it. Not for production cards.")
      boolean devSoftHsm;

      @Option(
          names = "--so-pin-out",
          description =
              "With --dev-softhsm: write a new token's SO PIN to this new file (outside the"
                  + " OpenFIPS201 home) instead of showing it once.")
      Path soPinOut;

      @Option(names = "--root-subject")
      String rootSubject;

      @Option(
          names = "--root-validity-days",
          defaultValue = "" + Pkcs11AdminService.DEFAULT_ROOT_VALIDITY_DAYS)
      int rootValidityDays;

      @Option(
          names = "--f9-subject",
          description =
              "F9 subject template without serialNumber; a per-card serialNumber RDN is appended at"
                  + " produce time.")
      String f9Subject;

      @Option(
          names = "--station",
          defaultValue = ProducerSetupService.STATION_ROOT,
          description =
              "root (root CA, IIN FF1 keys, registry; personalizes SAMs) or production (card-master"
                  + " and handoff keys; produces cards).")
      String station;

      @Option(
          names = "--root-pem",
          description = "Production station: the root station's public root.pem.")
      Path rootPem;

      @Override
      public Integer call() throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        boolean exists = Files.exists(ProducerPaths.producerProfile(name));
        boolean production = ProducerSetupService.STATION_PRODUCTION.equals(station);
        String rootDefault = "CN=" + name + " OpenFIPS201 Root";
        String f9Default = "CN=" + name + " OpenFIPS201 F9";
        if (rootSubject == null && !exists && !production) {
          rootSubject = maybePrompt(in, System.out, "Root CA subject", rootDefault);
        }
        if (f9Subject == null && !exists && !production) {
          f9Subject =
              maybePrompt(
                  in,
                  System.out,
                  "F9 subject template (serialNumber RDN appended per card)",
                  f9Default);
        }
        ProducerSetupService.Request request = new ProducerSetupService.Request();
        request.name = name;
        request.module = module;
        request.tokenLabel = tokenLabel;
        request.rootSubject = rootSubject;
        request.f9Subject = f9Subject;
        request.devSoftHsm = devSoftHsm;
        request.pinEnv = pinEnv;
        request.pinFile = pinFile;
        request.soPinOut = soPinOut;
        request.rootValidityDays = rootValidityDays;
        request.station = station;
        request.rootPem = rootPem;
        if (System.console() != null) {
          request.soPinDisplay =
              soPin -> {
                PrintWriter console = System.console().writer();
                console.print("SoftHSM SO PIN (shown once; required by 'producer destroy'): ");
                console.println(soPin);
                console.flush();
              };
        }
        ProducerSetupService.Result result = new ProducerSetupService().setup(request);
        System.out.println("Producer profile: " + result.profilePath);
        System.out.println("Custody: " + result.custody);
        System.out.println("PKCS#11 module: " + result.module);
        System.out.println("PKCS#11 token: " + result.tokenLabel);
        if (result.softhsmConfig != null) {
          System.out.println("SoftHSM config: " + result.softhsmConfig);
        }
        if (result.soPinFile != null) {
          System.out.println("SO PIN file: " + result.soPinFile);
        }
        System.out.println("Station: " + station);
        if (result.root != null) {
          System.out.println("Root CA (" + result.root.outcome + "): " + result.rootCertificate);
        } else {
          System.out.println("Root certificate (public): " + result.rootCertificate);
        }
        return 0;
      }
    }

    @Command(
        name = "destroy",
        mixinStandardHelpOptions = true,
        description =
            "Erase the producer's PKCS#11 token (all keys) with its SO PIN and delete the"
                + " producer profile, PIN file and root.pem. Batches and receipts are kept.")
    static final class Destroy implements Callable<Integer> {
      @Option(names = "--name", required = true)
      String name;

      @Option(
          names = "--confirm-token-label",
          required = true,
          description = "Must equal the producer's PKCS#11 token label.")
      String confirmTokenLabel;

      @Option(names = "--so-pin-env", description = "Environment variable with the SO PIN.")
      String soPinEnv;

      @Option(
          names = "--so-pin-file",
          description = "Owner-only file with the SO PIN. Without either, the SO PIN is prompted.")
      String soPinFile;

      @Override
      public Integer call() throws Exception {
        SecretSource soPin = SecretSource.of("--so-pin", null, soPinEnv, soPinFile);
        Path producer = new ProducerSetupService().destroy(name, confirmTokenLabel, soPin);
        System.out.println("Producer destroyed: " + producer);
        return 0;
      }
    }

    @Command(
        name = "export-trust",
        mixinStandardHelpOptions = true,
        description =
            "Write root.pem, each bound batch's SAM certificate (sam-<batch>.pem) and a trust.json"
                + " manifest for relying parties. Public material only; existing files are never"
                + " overwritten.")
    static final class ExportTrust implements Callable<Integer> {
      @Option(names = "--name", required = true)
      String name;

      @Option(names = "--out", required = true, description = "Output directory.")
      Path out;

      @Override
      public Integer call() throws Exception {
        TrustExportService.Manifest manifest = new TrustExportService().export(name, out);
        System.out.println(
            "Exported root and " + manifest.sams.size() + " SAM certificate(s) to " + out);
        return 0;
      }
    }

    @Command(
        name = "root",
        mixinStandardHelpOptions = true,
        description = "Manage the producer root CA.",
        subcommands = Root.ReissueCertificate.class)
    static final class Root implements Callable<Integer> {
      @Override
      public Integer call() {
        CommandLine.usage(this, System.err);
        return 2;
      }

      @Command(
          name = "reissue-certificate",
          mixinStandardHelpOptions = true,
          description =
              "Replace the root CA certificate with a new one for the same key in the current"
                  + " root profile (with subjectKeyIdentifier), and re-export root.pem.")
      static final class ReissueCertificate implements Callable<Integer> {
        @Option(names = "--name", required = true)
        String name;

        @Option(
            names = "--root-validity-days",
            defaultValue = "" + Pkcs11AdminService.DEFAULT_ROOT_VALIDITY_DAYS)
        int rootValidityDays;

        @Option(
            names = "--yes",
            description =
                "Confirm replacing the root certificate; relying parties must be given the new"
                    + " root.pem.")
        boolean yes;

        @Override
        public Integer call() throws Exception {
          if (!yes) {
            throw new IllegalArgumentException("--yes is required to reissue the root certificate");
          }
          ProducerSetupService.Result result =
              new ProducerSetupService().reissueRootCertificate(name, rootValidityDays);
          System.out.println("Producer profile: " + result.profilePath);
          System.out.println("Root CA (" + result.root.outcome + "): " + result.rootCertificate);
          return 0;
        }
      }
    }

    @Command(
        name = "iin",
        mixinStandardHelpOptions = true,
        description = "Manage the per-IIN FF1 keys on the producer's root token.",
        subcommands = {Iin.ImportKey.class, Iin.BackupKey.class})
    static final class Iin implements Callable<Integer> {
      @Override
      public Integer call() {
        CommandLine.usage(this, System.err);
        return 2;
      }

      @Command(
          name = "import-key",
          mixinStandardHelpOptions = true,
          description =
              "Move a plaintext iin-IIII.fpe.json key into the root token as a sensitive object,"
                  + " verify its key check value, then overwrite and delete the file.")
      static final class ImportKey implements Callable<Integer> {
        @Option(names = "--name", required = true)
        String name;

        @Option(names = "--iin", required = true)
        int iin;

        @Option(names = "--yes", description = "Confirm destroying the plaintext key file.")
        boolean yes;

        @Override
        public Integer call() throws Exception {
          if (!yes) {
            throw new IllegalArgumentException(
                "--yes is required to import and delete the key file");
          }
          String kcv;
          try (Pkcs11Session session = Pkcs11Session.open(IinKeyService.profile(name).pkcs11)) {
            kcv = new IinKeyService().importKey(session, name, iin);
          }
          System.out.println("IIN " + iin + " FF1 key imported into the root token; KCV " + kcv);
          return 0;
        }
      }

      @Command(
          name = "backup-key",
          mixinStandardHelpOptions = true,
          description =
              "Wrap an IIN FF1 key to a P-256 backup public key (ECDH, X9.63 SHA-256 KDF, RFC 3394"
                  + " AES key wrap). The plaintext key is never written.")
      static final class BackupKey implements Callable<Integer> {
        @Option(names = "--name", required = true)
        String name;

        @Option(names = "--iin", required = true)
        int iin;

        @Option(
            names = "--to-pub",
            required = true,
            description = "PEM P-256 public key or certificate of the backup recipient.")
        Path toPub;

        @Option(names = "--out", required = true, description = "New backup file (0600).")
        Path out;

        @Override
        public Integer call() throws Exception {
          PublicKey recipient = readPublicKey(toPub);
          boolean dev =
              ProducerSetupService.CUSTODY_SOFTHSM_DEV.equals(IinKeyService.custody(name));
          Pkcs11KeyTransport.Wrapped wrapped;
          try (Pkcs11Session session = Pkcs11Session.open(IinKeyService.profile(name).pkcs11)) {
            wrapped = new IinKeyService().backupKey(session, name, iin, recipient, out, dev);
          }
          System.out.println(
              "IIN " + iin + " FF1 key wrapped to " + out + " (" + wrapped.kdfPath + ")");
          return 0;
        }

        private static PublicKey readPublicKey(Path path) throws Exception {
          PemFiles.ensureProvider();
          try (java.io.Reader reader = Files.newBufferedReader(path, StandardCharsets.US_ASCII);
              org.bouncycastle.openssl.PEMParser parser =
                  new org.bouncycastle.openssl.PEMParser(reader)) {
            Object object = parser.readObject();
            if (object instanceof org.bouncycastle.cert.X509CertificateHolder) {
              return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                  .getCertificate((org.bouncycastle.cert.X509CertificateHolder) object)
                  .getPublicKey();
            }
            if (object instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
              return new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter()
                  .getPublicKey((org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) object);
            }
            throw new IllegalArgumentException("--to-pub must hold a public key or certificate");
          }
        }
      }
    }
  }

  @Command(
      name = "batch",
      mixinStandardHelpOptions = true,
      description =
          "Inspect and close production batches. A batch is allocated at the root station"
              + " ('root allocate') and received here with 'sam receive'.",
      subcommands = {Batch.Show.class, Batch.Close.class})
  static final class Batch implements Callable<Integer> {
    @Override
    public Integer call() {
      CommandLine.usage(this, System.err);
      return 2;
    }

    @Command(
        name = "close",
        mixinStandardHelpOptions = true,
        description =
            "Close a batch: SAM CLOSE appends a signed CLOSE entry {issued, quota}, which is"
                + " verified and recorded in the ledger. The SAM then refuses BEGIN, ISSUE and"
                + " TOP UP. Idempotent.")
    static final class Close implements Callable<Integer> {
      @Option(names = "--producer", required = true)
      String producer;

      @Option(names = "--batch", required = true)
      String batch;

      @Option(names = "--sam", required = true)
      String sam;

      @Mixin
      ProduceOptions.OperatorPinOptions operatorPin = new ProduceOptions.OperatorPinOptions();

      @Option(names = "--yes", description = "Confirm closing the batch.")
      boolean yes;

      @Override
      public Integer call() throws Exception {
        if (!yes) {
          throw new IllegalArgumentException("--yes is required to close a batch");
        }
        byte[] pin = operatorPin.pin();
        try {
          dev.mistial.tools.openfips201.issuance.SamLedgerEntry close =
              new dev.mistial.tools.openfips201.issuance.IssuanceService()
                  .closeBatch(producer, batch, CardTarget.parse(sam), pin);
          System.out.println(
              "Batch " + batch + " closed after " + close.issued + " of " + close.quota + ".");
          return 0;
        } finally {
          java.util.Arrays.fill(pin, (byte) 0);
        }
      }
    }

    @Command(
        name = "show",
        mixinStandardHelpOptions = true,
        description =
            "Show a batch's state, OPID identity, quota, registry binding and SAM. The production"
                + " batch record holds no LCG parameters.")
    static final class Show implements Callable<Integer> {
      @Option(names = "--producer", required = true)
      String producer;

      @Option(names = "--name", required = true)
      String name;

      @Override
      public Integer call() throws Exception {
        BatchMetadata batch = BatchMetadata.read(producer, name);
        System.out.println("Batch:        " + batch.name + " (" + batch.state + ")");
        System.out.println(
            "OPID:         IIN "
                + batch.opid.iin
                + ", batch "
                + batch.opid.batch
                + ", paramsDigest "
                + batch.paramsDigest);
        System.out.println(
            "Registry:     allocationSeq "
                + batch.registry.allocationSeq
                + ", head "
                + batch.registry.head);
        System.out.println(
            "Quota:        initial "
                + batch.quota.initial
                + ", authorized "
                + batch.quota.authorizedTotal);
        System.out.println("Stock KCV:    " + batch.stockScp.kcv);
        if (batch.sam != null && batch.sam.ski != null) {
          System.out.println("SAM SKI:      " + batch.sam.ski);
          System.out.println("SAM subject:  " + batch.sam.subject);
          System.out.println("SAM validity: " + batch.sam.notBefore + " .. " + batch.sam.notAfter);
        }
        return 0;
      }
    }
  }

  @Command(
      name = "card",
      mixinStandardHelpOptions = true,
      description = "Produce cards from an issuer batch.",
      subcommands = Card.Produce.class)
  static final class Card implements Callable<Integer> {
    @Override
    public Integer call() {
      CommandLine.usage(this, System.err);
      return 2;
    }

    @Command(
        name = "produce",
        mixinStandardHelpOptions = true,
        description =
            "Produce one card: install the applet, have the batch Issuer SAM certify its on-card"
                + " F9 key, verify, and rotate its keys. Exit 0 completed, 1 failed with no OPID"
                + " burned, 3 failed after the OPID was burned.")
    static final class Produce implements Callable<Integer> {
      @Mixin ProduceOptions produce = new ProduceOptions();

      @Override
      public Integer call() throws Exception {
        if (produce.target == null) {
          produce.target =
              promptTarget(new BufferedReader(new InputStreamReader(System.in)), System.out);
        }
        return produce.run(System.out);
      }
    }
  }

  @Command(
      name = "interactive",
      mixinStandardHelpOptions = true,
      description = "Run a guided cardstock workflow.")
  static final class Interactive implements Callable<Integer> {
    @Option(
        names = "--dry-run",
        description = "Print the equivalent cardstock command without touching a card.")
    boolean dryRun;

    @Override
    public Integer call() throws Exception {
      return run(new BufferedReader(new InputStreamReader(System.in)), System.out, dryRun);
    }

    int run(BufferedReader in, PrintStream out, boolean dryRunMode) throws Exception {
      out.println("OpenFIPS201 cardstock workflow");
      out.println();

      // The batch Issuer SAM certifies every card; there is no host-held or ephemeral signer.
      ProduceOptions produce = new ProduceOptions();
      produce.producer = promptRequired(in, out, "Producer");
      produce.batch = promptRequired(in, out, "Batch");
      out.println("Card reader");
      produce.target = promptTarget(in, out);
      out.println("Issuer SAM reader");
      produce.sam = promptTarget(in, out);

      boolean physical = !produce.target.startsWith("zmq:");
      produce.yes = !physical;
      if (physical) {
        produce.yes = confirm(in, out, "This will mutate a physical card. Continue");
      }
      if (!produce.yes) {
        out.println("Cancelled.");
        return 1;
      }

      if (dryRunMode) {
        out.println(renderProduceCommand(produce, physical));
        return 0;
      }
      return produce.run(out);
    }
  }

  /** Runs of 32 or more hex digits: the length of an AES-128 key and longer. */
  private static final java.util.regex.Pattern LONG_HEX_RUN =
      java.util.regex.Pattern.compile("[0-9A-Fa-f]{32,}");

  /**
   * Joins the cause chain into one line. Runs of at least 32 hex digits are replaced with {@code
   * <redacted>} so that key material carried by any message never reaches the terminal.
   */
  static String errorMessage(Throwable exception) {
    return LONG_HEX_RUN.matcher(joinedMessages(exception)).replaceAll("<redacted>");
  }

  private static String joinedMessages(Throwable exception) {
    StringBuilder message = new StringBuilder();
    Throwable current = exception;
    while (current != null) {
      String part = current.getMessage();
      if (part == null || part.isEmpty()) {
        part = current.getClass().getSimpleName();
      }
      if (message.length() == 0) {
        message.append(part);
      } else {
        message.append(": ").append(part);
      }
      current = current.getCause();
    }
    return message.toString();
  }

  private static String promptTarget(BufferedReader in, PrintStream out) throws Exception {
    String mode = promptChoice(in, out, "Target type", new String[] {"pcsc", "zmq"}, "pcsc");
    if ("zmq".equals(mode)) {
      String endpoint = promptOptional(in, out, "ZeroMQ endpoint", ZmqApduServer.DEFAULT_ENDPOINT);
      return "zmq:" + endpoint;
    }
    String reader = promptOptional(in, out, "PC/SC reader name filter", "");
    return "pcsc:" + reader;
  }

  private static String promptChoice(
      BufferedReader in, PrintStream out, String label, String[] choices, String defaultValue)
      throws Exception {
    while (true) {
      out.print(label + " " + String.join("/", choices) + " [" + defaultValue + "]: ");
      String value = in.readLine();
      if (value == null) {
        throw new IllegalArgumentException("No input available");
      }
      value = value.trim();
      if (value.isEmpty()) {
        return defaultValue;
      }
      for (String choice : choices) {
        if (choice.equals(value)) {
          return value;
        }
      }
      out.println("Choose one of: " + String.join(", ", choices));
    }
  }

  private static String promptRequired(BufferedReader in, PrintStream out, String label)
      throws Exception {
    while (true) {
      out.print(label + ": ");
      String value = in.readLine();
      if (value == null) {
        throw new IllegalArgumentException("No input available");
      }
      value = value.trim();
      if (!value.isEmpty()) {
        return value;
      }
      out.println(label + " is required.");
    }
  }

  private static String promptOptional(
      BufferedReader in, PrintStream out, String label, String defaultValue) throws Exception {
    String suffix = defaultValue == null || defaultValue.isEmpty() ? "" : " [" + defaultValue + "]";
    out.print(label + suffix + ": ");
    String value = in.readLine();
    if (value == null) {
      throw new IllegalArgumentException("No input available");
    }
    value = value.trim();
    return value.isEmpty() ? defaultValue : value;
  }

  /** Prompts with echo; for non-secret values only. Secrets are read through SecretSource. */
  private static String maybePrompt(
      BufferedReader in, PrintStream out, String label, String defaultValue) throws Exception {
    if (System.console() == null) {
      if (defaultValue != null) {
        return defaultValue;
      }
      throw new IllegalArgumentException(label + " is required");
    }
    return promptOptional(in, out, label, defaultValue);
  }

  private static boolean confirm(BufferedReader in, PrintStream out, String label)
      throws Exception {
    out.print(label + " [yes/no]: ");
    String value = in.readLine();
    return value != null && "yes".equals(value.trim());
  }

  /** The {@code card produce} command equivalent to an interactive session; no secrets. */
  static String renderProduceCommand(ProduceOptions produce, boolean physical) {
    StringBuilder command = new StringBuilder("openfips201 card produce");
    appendArg(command, "--producer", produce.producer);
    appendArg(command, "--batch", produce.batch);
    appendArg(command, "--target", produce.target);
    appendArg(command, "--sam", produce.sam);
    command.append(" --stock-scp-key-file <file> --operator-pin-file <file>");
    if (physical) {
      command.append(" --yes");
    }
    return command.toString();
  }

  private static void appendArg(StringBuilder command, String name, String value) {
    if (value == null || value.isEmpty()) {
      return;
    }
    command.append(' ').append(name).append(' ').append(shellQuote(value));
  }

  private static String shellQuote(String value) {
    if (value.matches("[A-Za-z0-9_./:=-]+")) {
      return value;
    }
    return "'" + value.replace("'", "'\"'\"'") + "'";
  }
}
