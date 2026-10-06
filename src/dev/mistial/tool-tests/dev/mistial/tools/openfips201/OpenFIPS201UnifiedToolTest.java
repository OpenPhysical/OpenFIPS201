/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.gp.CardKeyDerivationService;
import dev.mistial.tools.openfips201.gp.CardKeyPreflightService;
import dev.mistial.tools.openfips201.gp.CardKeyRotationService;
import dev.mistial.tools.openfips201.gp.DerivedScpKeys;
import dev.mistial.tools.openfips201.producer.ProducerPaths;
import dev.mistial.tools.openfips201.profiles.ProfileLoader;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

class OpenFIPS201UnifiedToolTest {
  private static final String KEY_A = "00112233445566778899AABBCCDDEEFF";
  private static final String KEY_B = "102132435465768798A9BACBDCEDFE0F";
  private static final String KEY_C = "2031425364758697A8B9CADBECFD0E1F";

  @Test
  void rootHelpShowsIssuerWorkflowCommands() {
    CommandLine commandLine = new CommandLine(new OpenFips201Tool());
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    commandLine.setOut(new PrintWriter(out, true));

    assertEquals(0, commandLine.execute("--help"));
    String help = new String(out.toByteArray(), StandardCharsets.UTF_8);
    assertTrue(help.contains("cardstock"));
    assertTrue(help.contains("emulator"));
    assertTrue(help.contains("applet"));
    assertTrue(help.contains("producer"));
    assertTrue(help.contains("batch"));
    assertTrue(help.contains("card"));
    assertTrue(help.contains("Discover available PC/SC smart-card readers."));
    assertTrue(help.contains("Install the OpenFIPS201 CAP on a GlobalPlatform card."));
    assertTrue(help.contains("deprecated; use 'card produce'"));
    assertTrue(help.contains("sam"));
    assertTrue(help.contains("ledger"));
    assertTrue(help.contains("root"));
    assertTrue(help.contains("station"));
    assertTrue(help.contains("Root station: allocation registry"), help);
  }

  @Test
  void cardstockPrepareIsAnAliasRequiringTheSam() {
    CommandLine commandLine = new CommandLine(new OpenFips201Tool());
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    commandLine.setOut(new PrintWriter(out, true));

    assertEquals(0, commandLine.execute("cardstock", "prepare", "--help"));
    String help = new String(out.toByteArray(), StandardCharsets.UTF_8);
    assertTrue(help.contains("--sam"));
    assertTrue(help.contains("--producer"));
    assertTrue(help.contains("--stock-scp-key-file"));
    assertTrue(!help.contains("--signer"), "there is no host signer to choose");

    ByteArrayOutputStream err = new ByteArrayOutputStream();
    CommandLine missingSam = new CommandLine(new OpenFips201Tool());
    missingSam.setErr(new PrintWriter(err, true));
    assertNotEquals(
        0,
        missingSam.execute(
            "cardstock", "prepare", "--producer", "p", "--batch", "b", "--target", "zmq:x"));
    assertTrue(new String(err.toByteArray(), StandardCharsets.UTF_8).contains("--sam"));
  }

  @Test
  void samLedgerAndRootCommandsExposeTheirOptions() {
    String[][] commands = {
      {"sam", "personalize", "--help"},
      {"sam", "status", "--help"},
      {"sam", "top-up", "--help"},
      {"root", "sign-top-up", "--help"},
      {"ledger", "verify", "--help"},
      {"ledger", "reconcile", "--help"},
      {"batch", "show", "--help"}
    };
    for (String[] command : commands) {
      CommandLine commandLine = new CommandLine(new OpenFips201Tool());
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      commandLine.setOut(new PrintWriter(out, true));
      assertEquals(0, commandLine.execute(command), String.join(" ", command));
      String help = new String(out.toByteArray(), StandardCharsets.UTF_8);
      assertTrue(help.contains("--producer"), String.join(" ", command));
    }
  }

  @Test
  void provisionHelpExposesSharedAndSplitScpKeys() {
    CommandLine commandLine = new CommandLine(new OpenFips201Tool());
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    commandLine.setOut(new PrintWriter(out, true));

    assertEquals(0, commandLine.execute("provision", "--help"));
    String help = new String(out.toByteArray(), StandardCharsets.UTF_8);
    assertTrue(help.contains("--scp-key"));
    assertTrue(help.contains("--scp-enc-key"));
    assertTrue(help.contains("--scp-mac-key"));
    assertTrue(help.contains("--scp-dek-key"));
  }

  @Test
  void provisionAcceptsSharedScpKey() {
    ProvisionCommand provision = new ProvisionCommand();
    provision.scpKey = KEY_A;

    ScpConfig config = provision.scp();

    assertArrayEquals(HexUtil.parse(KEY_A), config.encKey);
    assertArrayEquals(config.encKey, config.macKey);
    assertArrayEquals(config.encKey, config.dekKey);
  }

  @Test
  void provisionAcceptsThreeDistinctScpKeys() {
    ProvisionCommand provision = new ProvisionCommand();
    provision.scpEncKey = KEY_A;
    provision.scpMacKey = KEY_B;
    provision.scpDekKey = KEY_C;

    ScpConfig config = provision.scp();

    assertArrayEquals(HexUtil.parse(KEY_A), config.encKey);
    assertArrayEquals(HexUtil.parse(KEY_B), config.macKey);
    assertArrayEquals(HexUtil.parse(KEY_C), config.dekKey);
  }

  @Test
  void provisionRejectsMixedOrIncompleteScpKeys() {
    ProvisionCommand mixed = new ProvisionCommand();
    mixed.scpKey = KEY_A;
    mixed.scpEncKey = KEY_A;
    assertThrows(IllegalArgumentException.class, mixed::scp);

    ProvisionCommand incomplete = new ProvisionCommand();
    incomplete.scpEncKey = KEY_A;
    incomplete.scpMacKey = KEY_B;
    assertThrows(IllegalArgumentException.class, incomplete::scp);
  }

  @Test
  void literalScpKeysAreRefusedForPcscTargetsOnly() {
    ProvisionCommand physical = new ProvisionCommand();
    physical.target = "pcsc:Issuer Reader";
    physical.scpKey = KEY_A;
    IllegalArgumentException failure = assertThrows(IllegalArgumentException.class, physical::scp);
    assertTrue(failure.getMessage().contains("secrets on argv are refused"));
    assertTrue(failure.getMessage().contains("--scp-key-env"));
    assertTrue(!failure.getMessage().contains(KEY_A));

    ProvisionCommand emulator = new ProvisionCommand();
    emulator.target = "zmq:tcp://127.0.0.1:5555";
    emulator.scpKey = KEY_A;
    assertArrayEquals(HexUtil.parse(KEY_A), emulator.scp().encKey);
  }

  @Test
  void scpKeyFileMustBeOwnerOnly(@TempDir Path tempDir) throws Exception {
    org.junit.jupiter.api.Assumptions.assumeTrue(
        dev.mistial.tools.openfips201.common.SecureFiles.isPosix(tempDir));
    Path keyFile = tempDir.resolve("scp.key");
    Files.write(keyFile, (KEY_B + "\n").getBytes(StandardCharsets.UTF_8));
    Files.setPosixFilePermissions(
        keyFile, java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--"));
    ProvisionCommand provision = new ProvisionCommand();
    provision.target = "pcsc:Issuer Reader";
    provision.scpKeyFile = keyFile.toString();
    assertThrows(RuntimeException.class, provision::scp);

    Files.setPosixFilePermissions(
        keyFile, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
    assertArrayEquals(HexUtil.parse(KEY_B), provision.scp().macKey);
  }

  @Test
  void cardProduceRefusesLiteralStockKeyForPcscWithoutEchoingIt() {
    CommandLine commandLine = new CommandLine(new OpenFips201Tool());
    ByteArrayOutputStream err = new ByteArrayOutputStream();
    commandLine.setErr(new PrintWriter(err, true));
    commandLine.setExecutionExceptionHandler(
        (exception, parsed, result) -> {
          parsed.getErr().println("Error: " + OpenFips201Tool.errorMessage(exception));
          return 1;
        });

    int exit =
        commandLine.execute(
            "card",
            "produce",
            "--producer",
            "p",
            "--batch",
            "b",
            "--target",
            "pcsc:Issuer Reader",
            "--sam",
            "pcsc:SAM Reader",
            "--stock-scp-key",
            KEY_C,
            "--yes");

    String text = new String(err.toByteArray(), StandardCharsets.UTF_8);
    assertNotEquals(0, exit);
    assertTrue(text.contains("secrets on argv are refused"), text);
    assertTrue(text.contains("--stock-scp-key-file"), text);
    assertTrue(!text.contains(KEY_C), text);
  }

  @Test
  void errorMessageRedactsLongHexRuns() {
    Exception failure =
        new IllegalStateException(
            "outer", new IllegalArgumentException("bad key " + KEY_A + KEY_B + " at 9000"));

    String message = OpenFips201Tool.errorMessage(failure);

    assertEquals("outer: bad key <redacted> at 9000", message);
  }

  @Test
  void gpCardKddHelpExposesTargetOption() {
    CommandLine commandLine = new CommandLine(new OpenFips201Tool());
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    commandLine.setOut(new PrintWriter(out, true));

    assertEquals(0, commandLine.execute("gp", "card", "kdd", "--help"));
    String help = new String(out.toByteArray(), StandardCharsets.UTF_8);
    assertTrue(help.contains("--target"));
    assertTrue(help.contains("INITIALIZE UPDATE"));
  }

  @Test
  void gpKeysDeriveCardHelpExposesTargetAndPkcs11Options() {
    CommandLine commandLine = new CommandLine(new OpenFips201Tool());
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    commandLine.setOut(new PrintWriter(out, true));

    assertEquals(0, commandLine.execute("gp", "keys", "derive-card", "--help"));
    String help = new String(out.toByteArray(), StandardCharsets.UTF_8);
    assertTrue(help.contains("--target"));
    assertTrue(help.contains("--pkcs11-module"));
    assertTrue(help.contains("--pkcs11-key-alias"));
  }

  @Test
  void gpKeysKeyrollHelpExposesForwardAndBackward() {
    CommandLine commandLine = new CommandLine(new OpenFips201Tool());
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    commandLine.setOut(new PrintWriter(out, true));

    assertEquals(0, commandLine.execute("gp", "keys", "keyroll", "--help"));
    String help = new String(out.toByteArray(), StandardCharsets.UTF_8);
    assertTrue(help.contains("forward"));
    assertTrue(help.contains("backward"));
  }

  @Test
  void gpKeysPreflightHelpExposesDirection() {
    CommandLine commandLine = new CommandLine(new OpenFips201Tool());
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    commandLine.setOut(new PrintWriter(out, true));

    assertEquals(0, commandLine.execute("gp", "keys", "preflight", "--help"));
    String help = new String(out.toByteArray(), StandardCharsets.UTF_8);
    assertTrue(help.contains("--direction"));
    assertTrue(help.contains("--stock-scp-key-version"));
  }

  @Test
  void sameVersionRotationFailsBeforeCardAccess() throws Exception {
    ScpConfig current =
        ScpConfig.fromMaster(
            ScpConfig.Mode.SCP03, 1, HexUtil.parse("404142434445464748494A4B4C4D4E4F"));
    DerivedScpKeys target = DerivedScpKeys.fromConfig(current);

    assertThrows(
        IllegalArgumentException.class,
        () ->
            new CardKeyRotationService()
                .rotate(CardTarget.parse("pcsc:No Reader"), current, target));
  }

  @Test
  void sameVersionPreflightFailsBeforeCardAccess() throws Exception {
    ScpConfig current =
        ScpConfig.fromMaster(
            ScpConfig.Mode.SCP03, 1, HexUtil.parse("404142434445464748494A4B4C4D4E4F"));
    CardKeyPreflightService.Request request = new CardKeyPreflightService.Request();
    request.target = CardTarget.parse("pcsc:No Reader");
    request.current = current;
    request.targetKeys = DerivedScpKeys.fromConfig(current);
    request.kdd = HexUtil.parse("00002345496554204839");

    assertThrows(
        IllegalArgumentException.class, () -> new CardKeyPreflightService().preflight(request));
  }

  @Test
  void gpKeysKeyrollPhysicalTargetRequiresYesBeforeCardAccess() throws Exception {
    Path profile = Files.createTempFile("openfips201-profile", ".json");
    Files.write(
        profile,
        ("{"
                + "\"name\":\"issuer\","
                + "\"cardKeys\":{\"masterKeyAlias\":\"issuer-card-master\"},"
                + "\"pkcs11\":{\"module\":\"/does/not/matter\"}"
                + "}")
            .getBytes(StandardCharsets.UTF_8));
    CommandLine commandLine = new CommandLine(new OpenFips201Tool());
    ByteArrayOutputStream err = new ByteArrayOutputStream();
    commandLine.setErr(new PrintWriter(err, true));

    int exit =
        commandLine.execute(
            "gp",
            "keys",
            "keyroll",
            "forward",
            "--profile",
            profile.toString(),
            "--target",
            "pcsc:No Reader",
            "--kdd",
            "00002345496554204839");

    assertNotEquals(0, exit);
    assertTrue(new String(err.toByteArray(), StandardCharsets.UTF_8).contains("--yes"));
  }

  @Test
  void interactiveDryRunBuildsSamBackedProduceCommand() throws Exception {
    String input =
        "bigcorp_01\n"
            + "batch_001\n"
            + "zmq\n"
            + "tcp://127.0.0.1:35963\n"
            + "zmq\n"
            + "tcp://127.0.0.1:35964\n";
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    int exit =
        new OpenFips201Tool.Interactive()
            .run(
                new BufferedReader(new StringReader(input)),
                new PrintStream(out, true, StandardCharsets.UTF_8.name()),
                true);

    assertEquals(0, exit);
    String text = new String(out.toByteArray(), StandardCharsets.UTF_8);
    assertTrue(text.contains("openfips201 card produce"), text);
    assertTrue(text.contains("--producer bigcorp_01"));
    assertTrue(text.contains("--target zmq:tcp://127.0.0.1:35963"));
    assertTrue(text.contains("--sam zmq:tcp://127.0.0.1:35964"));
    assertTrue(!text.contains("ephemeral"), "no ephemeral signer exists");
  }

  @Test
  void interactivePhysicalCardRequiresConfirmation() throws Exception {
    String input = "p\nb\npcsc\nCard Reader\npcsc\nSAM Reader\nno\n";
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    int exit =
        new OpenFips201Tool.Interactive()
            .run(
                new BufferedReader(new StringReader(input)),
                new PrintStream(out, true, StandardCharsets.UTF_8.name()),
                true);
    assertEquals(1, exit);
    assertTrue(new String(out.toByteArray(), StandardCharsets.UTF_8).contains("Cancelled."));
  }

  @Test
  void cardTargetRequiresExplicitScheme() {
    assertThrows(IllegalArgumentException.class, () -> CardTarget.parse("Reader 1"));
    assertEquals("pcsc:Reader 1", CardTarget.parse("pcsc:Reader 1").displayName());
    assertEquals(
        "zmq:tcp://127.0.0.1:5555", CardTarget.parse("zmq:tcp://127.0.0.1:5555").displayName());
  }

  @Test
  void profileRejectsRawSecretsInEnvNameFields() throws Exception {
    Path profile = Files.createTempFile("openfips201-profile", ".json");
    Files.write(
        profile,
        ("{\"name\":\"bad\",\"stockScp\":{\"masterKeyEnv\":\"00112233445566778899AABBCCDDEEFF\"}}")
            .getBytes(StandardCharsets.UTF_8));

    assertThrows(IllegalArgumentException.class, () -> ProfileLoader.load(profile.toString()));
  }

  @Test
  void cardKeyDerivationIsDeterministicAndContextBound() throws Exception {
    CardKeyDerivationService service = new CardKeyDerivationService();
    byte[] master = HexUtil.parse("00112233445566778899AABBCCDDEEFF");

    DerivedScpKeys first = service.derive(master, "bigcorp|card-1", 1);
    DerivedScpKeys second = service.derive(master, "bigcorp|card-1", 1);
    DerivedScpKeys different = service.derive(master, "bigcorp|card-2", 1);

    assertEquals(first.encKcv, second.encKcv);
    assertEquals(first.macKcv, second.macKcv);
    assertEquals(first.dekKcv, second.dekKcv);
    assertNotEquals(first.encKcv, different.encKcv);
  }

  @Test
  void producerPathsRejectTraversalAndNestedNames() {
    assertThrows(IllegalArgumentException.class, () -> ProducerPaths.producer("../outside"));
    assertThrows(IllegalArgumentException.class, () -> ProducerPaths.producer("parent/child"));
    assertThrows(IllegalArgumentException.class, () -> ProducerPaths.producer("parent\\child"));
    assertThrows(IllegalArgumentException.class, () -> ProducerPaths.producer("."));
    assertThrows(
        IllegalArgumentException.class, () -> ProducerPaths.batch("bigcorp_01", "../batch"));
    assertThrows(
        IllegalArgumentException.class, () -> ProducerPaths.batch("bigcorp_01", "batch/001"));
  }
}
