/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.gp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.OpenFips201Tool;
import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.emulator.ZmqEmulatorFixture;
import dev.mistial.tools.openfips201.profiles.ProfileLoader;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;
import pro.javacard.gp.keys.PlaintextKeys;

/** An operator-supplied KDD is an expectation checked against INITIALIZE UPDATE, never trusted. */
class CardKddVerificationTest {
  private static final int ISSUER_VERSION = ScpConfig.KEY_VERSION_MIN;

  @Test
  void matchingOrAbsentExpectationReturnsTheCardKdd() {
    byte[] card = HexUtil.parse("00002345496554204839");

    assertArrayEquals(card, CardDiversificationDataService.requireExpectedKdd(card, null));
    assertArrayEquals(card, CardDiversificationDataService.requireExpectedKdd(card, card.clone()));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            CardDiversificationDataService.requireExpectedKdd(
                card, HexUtil.parse("00002345496554204838")));
  }

  @Test
  void keyrollWithAnotherCardsKddIsRefusedBeforeAnyKeyChange() throws Exception {
    try (ZmqEmulatorFixture fixture = ZmqEmulatorFixture.start(PlaintextKeys.DEFAULT_KEY())) {
      CardTarget target = fixture.target();
      byte[] wrong = otherKdd(target);

      CardKeyRollService.Request request = new CardKeyRollService.Request();
      request.target = target;
      request.profile = ProfileLoader.emulatorDev();
      request.direction = CardKeyRollService.Direction.FORWARD;
      request.kdd = wrong;
      request.yes = true;

      IllegalArgumentException failure =
          assertThrows(
              IllegalArgumentException.class, () -> new CardKeyRollService().roll(request));
      assertTrue(failure.getMessage().contains("does not match the card's KDD"));
      assertStockKeysUnchanged(target);
    }
  }

  @Test
  void gpKeysRotateWithAnotherCardsKddIsRefusedBeforeAnyKeyChange() throws Exception {
    try (ZmqEmulatorFixture fixture = ZmqEmulatorFixture.start(PlaintextKeys.DEFAULT_KEY())) {
      CardTarget target = fixture.target();
      CommandLine commandLine = new CommandLine(new OpenFips201Tool());
      ByteArrayOutputStream err = new ByteArrayOutputStream();
      commandLine.setErr(new PrintWriter(err, true));

      // The PKCS#11 module is never loaded: the KDD check precedes derivation and rotation.
      int exit =
          commandLine.execute(
              "gp",
              "keys",
              "rotate",
              "--target",
              target.displayName(),
              "--scp-key",
              HexUtil.format(PlaintextKeys.DEFAULT_KEY()),
              "--pkcs11-module",
              "/does/not/exist.so",
              "--kdd",
              HexUtil.format(otherKdd(target)),
              "--new-key-version",
              Integer.toString(ISSUER_VERSION));

      assertNotEquals(0, exit);
      String message = new String(err.toByteArray(), StandardCharsets.UTF_8);
      assertTrue(message.contains("does not match the card's KDD"), message);
      assertStockKeysUnchanged(target);
    }
  }

  @Test
  void preflightWithAnotherCardsKddIsRefusedBeforeAuthentication() throws Exception {
    try (ZmqEmulatorFixture fixture = ZmqEmulatorFixture.start(PlaintextKeys.DEFAULT_KEY())) {
      CardTarget target = fixture.target();
      byte[] key = new byte[16];
      java.util.Arrays.fill(key, (byte) 0x11);

      CardKeyPreflightService.Request request = new CardKeyPreflightService.Request();
      request.target = target;
      request.current = ScpConfig.defaultTestScp03();
      request.targetKeys =
          DerivedScpKeys.fromConfig(
              ScpConfig.fromMaster(ScpConfig.Mode.SCP03, ISSUER_VERSION, key));
      request.kdd = otherKdd(target);

      assertThrows(
          IllegalArgumentException.class, () -> new CardKeyPreflightService().preflight(request));

      request.kdd = new CardDiversificationDataService().readKdd(target).kdd;
      CardKeyPreflightService.Result result = new CardKeyPreflightService().preflight(request);
      assertArrayEquals(request.kdd, result.kdd);
      assertEquals(ISSUER_VERSION, result.targetKeyVersion);
    }
  }

  private static byte[] otherKdd(CardTarget target) throws Exception {
    byte[] kdd = new CardDiversificationDataService().readKdd(target).kdd;
    kdd[kdd.length - 1] ^= 0x01;
    return kdd;
  }

  private static void assertStockKeysUnchanged(CardTarget target) throws Exception {
    try (GlobalPlatformSession session =
        GlobalPlatformSession.open(
            target, GlobalPlatformSession.ISD_AID, ScpConfig.defaultTestScp03())) {
      assertTrue(!session.hasKeyVersion(ISSUER_VERSION), "no issuer keyset was added");
    }
  }
}
