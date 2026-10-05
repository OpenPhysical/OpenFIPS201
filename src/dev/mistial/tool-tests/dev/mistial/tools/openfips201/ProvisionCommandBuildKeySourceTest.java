/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.CardTransport;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.emulator.ZmqEmulatorFixture;
import dev.mistial.tools.openfips201.provisioning.ConformanceProvisioner;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.EnumSet;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import pro.javacard.capfile.AID;
import pro.javacard.gp.GPRegistryEntry;
import pro.javacard.gp.keys.PlaintextKeys;

/**
 * {@code provision} chooses how 9A/9C reach the card from the applet's own build: generated on card
 * for a FIPS build (which refuses importable 9A/9C), imported otherwise.
 */
@Timeout(value = 120, unit = TimeUnit.SECONDS)
class ProvisionCommandBuildKeySourceTest {
  private static final Path ICAM_46 =
      Paths.get(
          "test-vectors/gsa-icam-card-builder/cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV");

  @Test
  void provisionFollowsTheAppletBuild() throws Exception {
    Assumptions.assumeTrue(Files.isDirectory(ICAM_46), "ICAM card 46 not present");
    boolean fips = Boolean.getBoolean("fips.mode");
    try (ZmqEmulatorFixture fixture = ZmqEmulatorFixture.start(PlaintextKeys.DEFAULT_KEY())) {
      CardTarget target = fixture.target();
      try (CardTransport transport = target.openTransport();
          GlobalPlatformSession isd =
              transport.openGlobalPlatformSession(
                  GlobalPlatformSession.ISD_AID, ScpConfig.defaultTestScp03())) {
        isd.gp()
            .installAndMakeSelectable(
                new AID(HexUtil.parse("A00000030800001000")),
                new AID(GlobalPlatformSession.PIV_AID),
                new AID(GlobalPlatformSession.PIV_AID),
                EnumSet.noneOf(GPRegistryEntry.Privilege.class),
                new byte[0]);
      }
      assertEquals(
          ConformanceProvisioner.KeySource.forBuild(fips),
          ConformanceProvisioner.detectKeySource(target));

      ProvisionCommand provision = new ProvisionCommand();
      provision.target = target.displayName();
      provision.icam = ICAM_46;
      provision.scpKey = HexUtil.format(PlaintextKeys.DEFAULT_KEY());
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      PrintStream previous = System.out;
      System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8.name()));
      int exit;
      try {
        exit = provision.call();
      } finally {
        System.setOut(previous);
      }
      String text = new String(out.toByteArray(), StandardCharsets.UTF_8);
      assertEquals(0, exit, text);
      if (fips) {
        assertTrue(text.contains("Generated key"), text);
        assertTrue(text.contains("2 generated on card"), text);
      } else {
        assertTrue(text.contains("0 generated on card"), text);
      }
    }
  }
}
