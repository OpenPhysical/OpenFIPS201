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
import dev.mistial.tools.openfips201.producer.BatchCreateService;
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
  }

  @Test
  void cardstockHelpExposesPkcs11Options() {
    CommandLine commandLine = new CommandLine(new OpenFips201Tool());
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    commandLine.setOut(new PrintWriter(out, true));

    assertEquals(0, commandLine.execute("cardstock", "prepare", "--help"));
    String help = new String(out.toByteArray(), StandardCharsets.UTF_8);
    assertTrue(help.contains("--pkcs11-module"));
    assertTrue(help.contains("--pkcs11-key-alias"));
    assertTrue(help.contains("--signer"));
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
  void interactiveDryRunBuildsCardstockCommand() throws Exception {
    Path profile = Files.createTempFile("openfips201-profile", ".json");
    Files.write(
        profile,
        ("{"
                + "\"name\":\"emulator-dev\","
                + "\"stockScp\":{},"
                + "\"cardKeys\":{},"
                + "\"pkcs11\":{}"
                + "}")
            .getBytes(StandardCharsets.UTF_8));
    String input = profile + "\n" + "zmq\n" + "tcp://127.0.0.1:35963\n" + "ephemeral\n";
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    int exit =
        new OpenFips201Tool.Interactive()
            .run(
                new BufferedReader(new StringReader(input)),
                new PrintStream(out, true, StandardCharsets.UTF_8.name()),
                true);

    assertEquals(0, exit);
    String text = new String(out.toByteArray(), StandardCharsets.UTF_8);
    assertTrue(text.contains("openfips201 cardstock prepare"));
    assertTrue(text.contains("--profile " + profile));
    assertTrue(text.contains("--target zmq:tcp://127.0.0.1:35963"));
    assertTrue(text.contains("--signer ephemeral"));
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
  void batchCreateWritesMetadataAndCsvWithoutRawStockKey(@TempDir Path tempDir) throws Exception {
    String previous = System.getProperty("openfips201.home");
    System.setProperty("openfips201.home", tempDir.toString());
    try {
      Path producer = ProducerPaths.producer("bigcorp_01");
      Files.createDirectories(producer);
      Files.write(
          producer.resolve("producer.json"),
          "{\"name\":\"bigcorp_01\"}".getBytes(StandardCharsets.UTF_8));

      BatchCreateService.Result result = new BatchCreateService().create("bigcorp_01", "batch_001");

      String metadata =
          new String(
              Files.readAllBytes(result.directory.resolve("batch.json")), StandardCharsets.UTF_8);
      String csv =
          new String(
              Files.readAllBytes(result.directory.resolve("receipts.csv")), StandardCharsets.UTF_8);
      assertTrue(metadata.contains("\"stockScpKcv\""));
      assertTrue(metadata.contains("\"stockScpKeyVersion\": 1"));
      assertTrue(metadata.contains("\"receiptsCsv\""));
      String expectedHeader =
          "timestamp,producer,batch,target,status,cplc,kdd,new_key_version,enc_kcv,mac_kcv,dek_kcv,"
              + "root_subject,instance_id,f9_subject,f9_serial_hex,f9_spki_sha256,f9_cert_sha256,"
              + "proof_slot,proof_key_deleted,proof_issuer_matched\n";
      assertEquals(expectedHeader, csv);
      assertTrue(csv.contains("instance_id"));
      assertTrue(csv.contains("proof_issuer_matched"));
      assertTrue(result.stockScpKey.matches("[0-9A-F]{32}"));
      assertTrue(!metadata.contains(result.stockScpKey));
    } finally {
      if (previous == null) {
        System.clearProperty("openfips201.home");
      } else {
        System.setProperty("openfips201.home", previous);
      }
    }
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
