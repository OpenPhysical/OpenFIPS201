/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.gp.CardKeyDerivationService;
import dev.mistial.tools.openfips201.gp.DerivedScpKeys;
import dev.mistial.tools.openfips201.profiles.ProfileLoader;
import java.io.ByteArrayOutputStream;
import java.io.BufferedReader;
import java.io.StringReader;
import java.io.PrintWriter;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

class OpenFIPS201UnifiedToolTest {
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
    String input =
        profile
            + "\n"
            + "zmq\n"
            + "tcp://127.0.0.1:35963\n"
            + "ephemeral\n";
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
    assertEquals("zmq:tcp://127.0.0.1:5555", CardTarget.parse("zmq:tcp://127.0.0.1:5555").displayName());
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
}
