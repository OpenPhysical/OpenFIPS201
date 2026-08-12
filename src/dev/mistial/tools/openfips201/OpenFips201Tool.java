/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201;

import com.google.gson.Gson;
import dev.mistial.tools.openfips201.applet.AppletInstallRequest;
import dev.mistial.tools.openfips201.applet.AppletInstallService;
import dev.mistial.tools.openfips201.cardstock.CardstockPreparationService;
import dev.mistial.tools.openfips201.cardstock.CardstockReceipt;
import dev.mistial.tools.openfips201.cardstock.CardstockReceiptPrinter;
import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.crypto.PemSigningKey;
import dev.mistial.tools.openfips201.crypto.SigningKey;
import dev.mistial.tools.openfips201.emulator.ZmqApduServer;
import dev.mistial.tools.openfips201.gp.CardDiversificationDataService;
import dev.mistial.tools.openfips201.gp.CardKeyPreflightService;
import dev.mistial.tools.openfips201.gp.CardKeyRollService;
import dev.mistial.tools.openfips201.gp.CardKeyRotationService;
import dev.mistial.tools.openfips201.gp.DerivedScpKeys;
import dev.mistial.tools.openfips201.gp.IssuerCardKeyService;
import dev.mistial.tools.openfips201.gp.Scp03Kdf3DerivationService;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11Config;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11SigningKey;
import dev.mistial.tools.openfips201.producer.BatchCreateService;
import dev.mistial.tools.openfips201.producer.CardProductionService;
import dev.mistial.tools.openfips201.producer.ProducerSetupService;
import dev.mistial.tools.openfips201.profiles.IssuerProfile;
import dev.mistial.tools.openfips201.profiles.ProfileLoader;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import pro.javacard.gp.keys.PlaintextKeys;

@Command(
    name = "openfips201",
    mixinStandardHelpOptions = true,
    description = "OpenFIPS201 issuer tooling.",
    subcommands = {
      OpenFips201Tool.Cards.class,
      OpenFips201Tool.Emulator.class,
      OpenFips201Tool.Applet.class,
      OpenFips201Tool.Crypto.class,
      OpenFips201Tool.Gp.class,
      OpenFips201Tool.Cardstock.class,
      OpenFips201Tool.Producer.class,
      OpenFips201Tool.Batch.class,
      OpenFips201Tool.Card.class,
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

  @Command(name = "cards", mixinStandardHelpOptions = true, subcommands = Cards.ListReaders.class)
  static final class Cards implements Callable<Integer> {
    @Override
    public Integer call() {
      CommandLine.usage(this, System.err);
      return 2;
    }

    @Command(
        name = "list",
        mixinStandardHelpOptions = true,
        description = "List PC/SC reader names.")
    static final class ListReaders implements Callable<Integer> {
      @Override
      public Integer call() throws Exception {
        CardTarget.listPcscReaders();
        return 0;
      }
    }
  }

  @Command(name = "emulator", mixinStandardHelpOptions = true, subcommands = Emulator.Serve.class)
  static final class Emulator implements Callable<Integer> {
    @Override
    public Integer call() {
      CommandLine.usage(this, System.err);
      return 2;
    }

    @Command(
        name = "serve",
        mixinStandardHelpOptions = true,
        description = "Serve an OpenFIPS201 emulator over ZeroMQ.")
    static final class Serve implements Callable<Integer> {
      @Option(names = "--endpoint", defaultValue = ZmqApduServer.DEFAULT_ENDPOINT)
      String endpoint;

      @Option(names = "--scp03-key", description = "SCP03 master key hex; defaults to GP test key.")
      String scp03Key;

      @Override
      public Integer call() {
        byte[] key = scp03Key == null ? PlaintextKeys.DEFAULT_KEY() : HexUtil.parse(scp03Key);
        try (ZmqApduServer server = new ZmqApduServer(key)) {
          server.run(
              endpoint,
              bound -> {
                System.out.println("OpenFIPS201 emulator serving on " + bound);
                Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
              });
        }
        return 0;
      }
    }
  }

  @Command(name = "applet", mixinStandardHelpOptions = true, subcommands = Applet.Install.class)
  static final class Applet implements Callable<Integer> {
    @Override
    public Integer call() {
      CommandLine.usage(this, System.err);
      return 2;
    }

    @Command(
        name = "install",
        mixinStandardHelpOptions = true,
        description = "Load and install the OpenFIPS201 CAP.")
    static final class Install extends ScpOptions implements Callable<Integer> {
      @Option(names = "--cap", required = true)
      Path cap;

      @Option(names = "--package-aid", defaultValue = "A00000030800001000")
      String packageAid;

      @Option(names = "--applet-aid", defaultValue = "A000000308000010000100")
      String appletAid;

      @Option(names = "--instance-aid", defaultValue = "A000000308000010000100")
      String instanceAid;

      @Option(names = "--delete-existing")
      boolean deleteExisting;

      @Option(
          names = "--skip-load",
          description = "Skip GP CAP LOAD and only install/select an already registered package.")
      boolean skipLoad;

      @Override
      public Integer call() throws Exception {
        AppletInstallRequest request = new AppletInstallRequest();
        request.capPath = cap;
        request.packageAid = packageAid;
        request.appletAid = appletAid;
        request.instanceAid = instanceAid;
        request.loadCap = !skipLoad;
        request.deleteExisting = deleteExisting;
        try (GlobalPlatformSession session =
            GlobalPlatformSession.open(
                CardTarget.parse(target), GlobalPlatformSession.ISD_AID, scp())) {
          new AppletInstallService().install(session, request);
        }
        System.out.println("Applet installed.");
        return 0;
      }
    }
  }

  @Command(name = "crypto", mixinStandardHelpOptions = true, subcommands = Crypto.Pkcs11.class)
  static final class Crypto implements Callable<Integer> {
    @Override
    public Integer call() {
      CommandLine.usage(this, System.err);
      return 2;
    }

    @Command(name = "pkcs11", mixinStandardHelpOptions = true, subcommands = Pkcs11.List.class)
    static final class Pkcs11 implements Callable<Integer> {
      @Override
      public Integer call() {
        CommandLine.usage(this, System.err);
        return 2;
      }

      @Command(
          name = "list",
          mixinStandardHelpOptions = true,
          description = "Validate a PKCS#11 token/key selection.")
      static final class List extends Pkcs11Options implements Callable<Integer> {
        @Override
        public Integer call() throws Exception {
          SigningKey key = new Pkcs11SigningKey(pkcs11());
          System.out.println("Selected " + key.description());
          System.out.println(key.publicKey().getAlgorithm() + " public key available");
          return 0;
        }
      }
    }
  }

  @Command(
      name = "gp",
      mixinStandardHelpOptions = true,
      subcommands = {Gp.Card.class, Gp.Keys.class})
  static final class Gp implements Callable<Integer> {
    @Override
    public Integer call() {
      CommandLine.usage(this, System.err);
      return 2;
    }

    @Command(name = "card", mixinStandardHelpOptions = true, subcommands = Card.Kdd.class)
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
            required = true,
            description = "10-byte card key diversification data hex.")
        String kdd;

        @Option(names = "--new-key-version", defaultValue = "1")
        int newKeyVersion;

        @Override
        public Integer call() throws Exception {
          DerivedScpKeys keys =
              new Scp03Kdf3DerivationService()
                  .derive(pkcs11.pkcs11(), HexUtil.parse(kdd), newKeyVersion);
          new CardKeyRotationService().rotate(CardTarget.parse(target), scp(), keys);
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
            description = "10-byte card key diversification data hex; read from card by default.")
        String kdd;

        @Option(names = "--stock-scp", defaultValue = "scp03")
        String stockScp;

        @Option(names = "--stock-scp-key-version", defaultValue = "1")
        int stockScpKeyVersion;

        @Option(
            names = "--stock-scp-key",
            description = "Override the profile stock SCP master key.")
        String stockScpKey;

        @Override
        public Integer call() throws Exception {
          IssuerProfile loaded = ProfileLoader.load(profile);
          IssuerCardKeyService issuerKeys = new IssuerCardKeyService();
          byte[] parsedKdd = kdd == null ? null : HexUtil.parse(kdd);
          ScpConfig stock =
              stockScpKey == null
                  ? issuerKeys.stockScp(loaded)
                  : ScpConfig.fromMaster(
                      ScpConfig.parseMode(stockScp),
                      stockScpKeyVersion,
                      HexUtil.parse(stockScpKey));
          DerivedScpKeys profileKeys =
              parsedKdd == null ? null : issuerKeys.deriveCardKeys(loaded, parsedKdd);

          CardKeyPreflightService.Request request = new CardKeyPreflightService.Request();
          request.target = CardTarget.parse(target);
          request.profile = loaded;
          request.profilePath = profile;
          request.kdd = parsedKdd;
          request.stockScpKey = stockScpKey;
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
              description = "10-byte card key diversification data hex; read from card by default.")
          String kdd;

          @Option(names = "--yes", description = "Confirm physical-card mutations.")
          boolean yes;

          @Option(names = "--stock-scp", defaultValue = "scp03")
          String stockScp;

          @Option(names = "--stock-scp-key-version", defaultValue = "1")
          int stockScpKeyVersion;

          @Option(
              names = "--stock-scp-key",
              description = "Override the profile stock SCP master key.")
          String stockScpKey;

          CardKeyRollService.Request request(CardKeyRollService.Direction direction)
              throws Exception {
            CardKeyRollService.Request request = new CardKeyRollService.Request();
            request.target = CardTarget.parse(target);
            request.profile = ProfileLoader.load(profile);
            request.direction = direction;
            request.kdd = kdd == null ? null : HexUtil.parse(kdd);
            request.yes = yes;
            request.stockScpOverride =
                stockScpKey == null
                    ? null
                    : ScpConfig.fromMaster(
                        ScpConfig.parseMode(stockScp),
                        stockScpKeyVersion,
                        HexUtil.parse(stockScpKey));
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
        description = "Load, attest, rotate keys, and receipt issuer cardstock.")
    static final class Prepare implements Callable<Integer> {
      @Option(names = "--profile", required = true)
      String profile;

      @Option(names = "--target", required = true)
      String target;

      @Option(names = "--yes", description = "Confirm physical-card mutations.")
      boolean yes;

      @Option(
          names = "--signer",
          defaultValue = "profile",
          description = "profile, pkcs11, softhsm, pem, or ephemeral.")
      String signerType;

      @Option(names = "--signer-key")
      Path signerKey;

      @Option(names = "--signer-cert")
      Path signerCert;

      @Option(names = "--signer-key-pass-env")
      String signerKeyPassEnv;

      @Option(names = "--stock-scp", defaultValue = "scp03")
      String stockScp;

      @Option(names = "--stock-scp-key-version", defaultValue = "1")
      int stockScpKeyVersion;

      @Option(names = "--stock-scp-key", description = "Override the profile stock SCP master key.")
      String stockScpKey;

      @Mixin Pkcs11Options pkcs11 = new Pkcs11Options();

      @Override
      public Integer call() throws Exception {
        IssuerProfile loaded = ProfileLoader.load(profile);
        SigningKey signingKey =
            signer(loaded, signerType, signerKey, signerCert, signerKeyPassEnv, pkcs11);
        ScpConfig stockOverride =
            stockScpKey == null
                ? null
                : ScpConfig.fromMaster(
                    ScpConfig.parseMode(stockScp), stockScpKeyVersion, HexUtil.parse(stockScpKey));
        Path receiptPath =
            new CardstockPreparationService()
                .prepare(
                    CardTarget.parse(target),
                    loaded,
                    signingKey,
                    yes,
                    null,
                    null,
                    stockOverride,
                    profile,
                    stockScpKey);
        printCardstockReceipt(System.out, "Cardstock prepared.", receiptPath);
        return 0;
      }
    }
  }

  @Command(name = "producer", mixinStandardHelpOptions = true, subcommands = Producer.Setup.class)
  static final class Producer implements Callable<Integer> {
    @Override
    public Integer call() {
      CommandLine.usage(this, System.err);
      return 2;
    }

    @Command(
        name = "setup",
        mixinStandardHelpOptions = true,
        description = "Create an issuer producer profile and default SoftHSM keys.")
    static final class Setup implements Callable<Integer> {
      @Option(names = "--name", required = true)
      String name;

      @Option(names = "--pkcs11-module")
      String module;

      @Option(names = "--pkcs11-token-label")
      String tokenLabel;

      @Option(names = "--root-subject")
      String rootSubject;

      @Option(
          names = "--f9-subject",
          description =
              "F9 subject template without serialNumber; a per-card serialNumber RDN is appended at"
                  + " produce time.")
      String f9Subject;

      @Option(names = "--force")
      boolean force;

      @Override
      public Integer call() throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String rootDefault = "CN=" + name + " OpenFIPS201 Root";
        String f9Default = "CN=" + name + " OpenFIPS201 F9";
        if (rootSubject == null) {
          rootSubject = maybePrompt(in, System.out, "Root CA subject", rootDefault);
        }
        if (f9Subject == null) {
          f9Subject =
              maybePrompt(
                  in,
                  System.out,
                  "F9 subject template (serialNumber RDN appended per card)",
                  f9Default);
        }
        ProducerSetupService.Result result =
            new ProducerSetupService()
                .setup(name, module, tokenLabel, rootSubject, f9Subject, force);
        System.out.println("Producer profile: " + result.profilePath);
        System.out.println("PKCS#11 module: " + result.module);
        System.out.println("PKCS#11 token: " + result.tokenLabel);
        System.out.println("SoftHSM config: " + result.softhsmConfig);
        return 0;
      }
    }
  }

  @Command(name = "batch", mixinStandardHelpOptions = true, subcommands = Batch.Create.class)
  static final class Batch implements Callable<Integer> {
    @Override
    public Integer call() {
      CommandLine.usage(this, System.err);
      return 2;
    }

    @Command(
        name = "create",
        mixinStandardHelpOptions = true,
        description = "Create an issuer batch and print its stock GP key.")
    static final class Create implements Callable<Integer> {
      @Option(names = "--producer", required = true)
      String producer;

      @Option(names = "--name", required = true)
      String name;

      @Override
      public Integer call() throws Exception {
        BatchCreateService.Result result = new BatchCreateService().create(producer, name);
        System.out.println("Batch directory: " + result.directory);
        System.out.println("Stock SCP03 master key: " + result.stockScpKey);
        System.out.println("Stock SCP03 KCV: " + result.stockScpKcv);
        return 0;
      }
    }
  }

  @Command(name = "card", mixinStandardHelpOptions = true, subcommands = Card.Produce.class)
  static final class Card implements Callable<Integer> {
    @Override
    public Integer call() {
      CommandLine.usage(this, System.err);
      return 2;
    }

    @Command(
        name = "produce",
        mixinStandardHelpOptions = true,
        description = "Produce one card into issuer cardstock.")
    static final class Produce implements Callable<Integer> {
      @Option(names = "--producer", required = true)
      String producer;

      @Option(names = "--batch", required = true)
      String batch;

      @Option(names = "--target")
      String target;

      @Option(names = "--stock-scp-key")
      String stockScpKey;

      @Option(names = "--yes", description = "Confirm physical-card mutations.")
      boolean yes;

      @Override
      public Integer call() throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        if (target == null) {
          target = promptTarget(in, System.out);
        }
        if (stockScpKey == null) {
          stockScpKey = maybePrompt(in, System.out, "Stock SCP03 master key", null);
        }
        if (target.startsWith("zmq:")) {
          yes = true;
        } else if (!yes) {
          yes = confirm(in, System.out, "This will mutate a physical card. Continue");
        }
        if (!yes) {
          System.out.println("Cancelled.");
          return 1;
        }
        Path receiptPath =
            new CardProductionService()
                .produce(producer, batch, CardTarget.parse(target), stockScpKey, yes);
        printCardstockReceipt(System.out, "Card produced.", receiptPath);
        return 0;
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

      String profilePath = promptRequired(in, out, "Issuer profile path");
      IssuerProfile profile = ProfileLoader.load(profilePath);
      out.println("Profile: " + profile.name);

      String target = promptTarget(in, out);
      String signerType =
          promptChoice(
              in,
              out,
              "Signer",
              new String[] {"profile", "pkcs11", "softhsm", "pem", "ephemeral"},
              "profile");
      Path signerKey = null;
      Path signerCert = null;
      String signerPassEnv = null;
      Pkcs11Options pkcs11Options = new Pkcs11Options();
      if ("pem".equals(signerType)) {
        signerKey = Paths.get(promptRequired(in, out, "PEM private key path"));
        signerCert = Paths.get(promptRequired(in, out, "PEM certificate path"));
        signerPassEnv = promptOptional(in, out, "PEM passphrase env var", null);
      } else if ("pkcs11".equals(signerType) || "softhsm".equals(signerType)) {
        pkcs11Options.module =
            promptOptional(in, out, "PKCS#11 module path", profile.pkcs11.module);
        pkcs11Options.tokenLabel =
            promptOptional(in, out, "PKCS#11 token label", profile.pkcs11.tokenLabel);
        pkcs11Options.keyAlias =
            promptOptional(in, out, "PKCS#11 key alias", profile.pkcs11.keyAlias);
        pkcs11Options.pinEnv =
            promptOptional(in, out, "PKCS#11 PIN env var", profile.pkcs11.pinEnv);
      }

      boolean physical = !target.startsWith("zmq:");
      boolean yes = !physical || "emulator-dev".equals(profile.name);
      if (physical && !yes) {
        yes = confirm(in, out, "This will mutate a physical card. Continue");
      }
      if (!yes) {
        out.println("Cancelled.");
        return 1;
      }

      if (dryRunMode) {
        out.println(
            renderCardstockCommand(
                profilePath,
                target,
                signerType,
                signerKey,
                signerCert,
                signerPassEnv,
                pkcs11Options,
                physical));
        return 0;
      }

      SigningKey signingKey =
          signer(profile, signerType, signerKey, signerCert, signerPassEnv, pkcs11Options);
      Path receiptPath =
          new CardstockPreparationService()
              .prepare(CardTarget.parse(target), profile, signingKey, yes);
      printCardstockReceipt(out, "Cardstock prepared.", receiptPath);
      return 0;
    }
  }

  static class ScpOptions {
    @Option(names = "--target", required = true)
    String target;

    @Option(names = "--scp", defaultValue = "auto")
    String scp;

    @Option(names = "--scp-key-version", defaultValue = "0")
    int scpKeyVersion;

    @Option(names = "--scp-key")
    String scpKey;

    @Option(names = "--scp-enc-key")
    String scpEncKey;

    @Option(names = "--scp-mac-key")
    String scpMacKey;

    @Option(names = "--scp-dek-key")
    String scpDekKey;

    ScpConfig scp() {
      if (scpKey != null) {
        return ScpConfig.fromMaster(ScpConfig.parseMode(scp), scpKeyVersion, HexUtil.parse(scpKey));
      }
      if (scpEncKey != null && scpMacKey != null && scpDekKey != null) {
        return new ScpConfig(
            ScpConfig.parseMode(scp),
            scpKeyVersion,
            HexUtil.parse(scpEncKey),
            HexUtil.parse(scpMacKey),
            HexUtil.parse(scpDekKey));
      }
      throw new IllegalArgumentException("Provide --scp-key or all split SCP keys");
    }
  }

  static class Pkcs11Options {
    @Option(names = "--pkcs11-module")
    String module;

    @Option(names = "--pkcs11-token-label")
    String tokenLabel;

    @Option(names = "--pkcs11-slot")
    Integer slot;

    @Option(names = "--pkcs11-key-alias")
    String keyAlias;

    @Option(names = "--pkcs11-key-id")
    String keyId;

    @Option(names = "--pkcs11-pin-env")
    String pinEnv;

    @Option(names = "--pkcs11-pin-file")
    String pinFile;

    @Option(names = "--softhsm-config")
    String softhsmConfig;

    Pkcs11Config pkcs11() {
      Pkcs11Config config = new Pkcs11Config();
      config.module = module;
      config.tokenLabel = tokenLabel;
      config.slot = slot;
      config.keyAlias = keyAlias;
      config.keyId = keyId;
      config.pinEnv = pinEnv;
      config.pinFile = pinFile;
      config.softhsmConfig = softhsmConfig;
      if (config.module == null || config.module.isEmpty()) {
        throw new IllegalArgumentException("--pkcs11-module is required");
      }
      return config;
    }
  }

  private static SigningKey signer(
      IssuerProfile profile,
      String type,
      Path signerKey,
      Path signerCert,
      String passEnv,
      Pkcs11Options pkcs11)
      throws Exception {
    if ("profile".equals(type)) {
      type = profile.pkcs11 != null && profile.pkcs11.module != null ? "pkcs11" : "ephemeral";
    }
    if ("pkcs11".equals(type) || "softhsm".equals(type)) {
      Pkcs11Config config = pkcs11.module == null ? profile.pkcs11 : pkcs11.pkcs11();
      return new LazyPkcs11SigningKey(config);
    }
    if ("pem".equals(type)) {
      if (signerKey == null || signerCert == null) {
        throw new IllegalArgumentException(
            "--signer-key and --signer-cert are required for PEM signing");
      }
      return new PemSigningKey(signerKey, signerCert, optionalSecretChars(passEnv));
    }
    if ("ephemeral".equals(type)) {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
      generator.initialize(new ECGenParameterSpec("secp256r1"));
      KeyPair keyPair = generator.generateKeyPair();
      return new PemSigningKey(keyPair.getPrivate(), keyPair.getPublic(), "ephemeral");
    }
    throw new IllegalArgumentException(
        "--signer must be profile, pkcs11, softhsm, pem, or ephemeral");
  }

  private static final class LazyPkcs11SigningKey implements SigningKey {
    private final Pkcs11Config config;
    private Pkcs11SigningKey delegate;

    LazyPkcs11SigningKey(Pkcs11Config config) {
      this.config = config.copy();
    }

    @Override
    public PublicKey publicKey() {
      try {
        return delegate().publicKey();
      } catch (Exception e) {
        throw new IllegalStateException("PKCS#11 signing key is unavailable", e);
      }
    }

    @Override
    public byte[] sign(String jcaAlgorithm, byte[] message) throws Exception {
      return delegate().sign(jcaAlgorithm, message);
    }

    @Override
    public String description() {
      if (delegate != null) {
        return delegate.description();
      }
      if (config.keyAlias != null && !config.keyAlias.isEmpty()) {
        return "pkcs11:" + config.keyAlias;
      }
      if (config.keyId != null && !config.keyId.isEmpty()) {
        return "pkcs11:id:" + config.keyId;
      }
      return "pkcs11:selected-key";
    }

    private synchronized Pkcs11SigningKey delegate() throws Exception {
      if (delegate == null) {
        delegate = new Pkcs11SigningKey(config);
      }
      return delegate;
    }
  }

  private static char[] optionalSecretChars(String env) {
    if (env == null || env.isEmpty()) {
      return null;
    }
    String value = System.getenv(env);
    if (value == null) {
      throw new IllegalArgumentException("Environment variable is not set: " + env);
    }
    return value.toCharArray();
  }

  private static String errorMessage(Throwable exception) {
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

  private static String renderCardstockCommand(
      String profile,
      String target,
      String signerType,
      Path signerKey,
      Path signerCert,
      String signerPassEnv,
      Pkcs11Options pkcs11,
      boolean physical) {
    StringBuilder command = new StringBuilder("openfips201 cardstock prepare");
    appendArg(command, "--profile", profile);
    appendArg(command, "--target", target);
    appendArg(command, "--signer", signerType);
    if (physical) {
      command.append(" --yes");
    }
    if ("pem".equals(signerType)) {
      appendArg(command, "--signer-key", signerKey == null ? null : signerKey.toString());
      appendArg(command, "--signer-cert", signerCert == null ? null : signerCert.toString());
      appendArg(command, "--signer-key-pass-env", signerPassEnv);
    }
    if ("pkcs11".equals(signerType) || "softhsm".equals(signerType)) {
      appendArg(command, "--pkcs11-module", pkcs11.module);
      appendArg(command, "--pkcs11-token-label", pkcs11.tokenLabel);
      appendArg(command, "--pkcs11-key-alias", pkcs11.keyAlias);
      appendArg(command, "--pkcs11-pin-env", pkcs11.pinEnv);
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

  private static void printCardstockReceipt(PrintStream out, String headline, Path receiptPath)
      throws Exception {
    CardstockReceipt receipt =
        new Gson()
            .fromJson(
                new String(Files.readAllBytes(receiptPath), StandardCharsets.UTF_8),
                CardstockReceipt.class);
    CardstockReceiptPrinter.printSummary(out, headline, receipt, receiptPath);
  }
}
