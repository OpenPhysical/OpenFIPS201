/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.gp;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.ScpConfig;
import org.junit.jupiter.api.Test;

class CardKeyPreflightServiceTest {
  @Test
  void recoveryCommandNeverContainsTheSuppliedStockKey() {
    String stockKey = "404142434445464748494A4B4C4D4E4F";
    CardKeyPreflightService.Request request = new CardKeyPreflightService.Request();
    request.target = CardTarget.parse("pcsc:Issuer Reader");
    request.profilePath = "issuer.json";
    request.stockScpKey = stockKey;
    request.current = ScpConfig.fromMaster(ScpConfig.Mode.SCP03, 1, HexUtil.parse(stockKey));

    String command =
        CardKeyPreflightService.rollbackCommand(request, HexUtil.parse("00002345558923204839"), 1);

    assertTrue(command.contains("keyroll backward"));
    assertFalse(command.contains(stockKey));
    assertFalse(command.contains("--stock-scp-key "));
    assertFalse(command.contains("--stock-scp-key="));
  }

  @Test
  void recoveryUsesAuthenticatedVersionAndOmitsUnsupportedFactoryDestinations() {
    CardKeyPreflightService.Request request = new CardKeyPreflightService.Request();
    request.target = CardTarget.parse("pcsc:Issuer Reader");
    request.profilePath = "issuer.json";
    request.current = ScpConfig.defaultTestScp03();
    byte[] kdd = HexUtil.parse("00002345558923204839");
    String recovery = CardKeyPreflightService.rollbackCommand(request, kdd, 7);
    assertTrue(recovery.contains("--stock-scp-key-version 7"));
    org.junit.jupiter.api.Assertions.assertNull(
        CardKeyPreflightService.rollbackCommand(request, kdd, 255));
    org.junit.jupiter.api.Assertions.assertNull(
        CardKeyPreflightService.rollbackCommand(request, kdd, 0));
  }
}
