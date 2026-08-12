/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.gp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import apdu4j.core.MockBIBO;
import dev.mistial.tools.openfips201.common.HexUtil;
import org.junit.jupiter.api.Test;

class CardDiversificationDataServiceTest {
  @Test
  void readsKddFromInitializeUpdateResponse() {
    MockBIBO bibo =
        MockBIBO.with("00A4040008A000000151000000", "6F108408A000000151000000A5049F6501FF9000")
            .then(
                "80500000081122334455667788",
                "00002345496554204839010200064E7703493DFAA495EFC169DCD7B89000");

    CardDiversificationDataService.Result result =
        new CardDiversificationDataService().readKdd(bibo, HexUtil.parse("1122334455667788"));

    assertArrayEquals(HexUtil.parse("00002345496554204839"), result.kdd);
    assertArrayEquals(
        HexUtil.parse("00002345496554204839010200064E7703493DFAA495EFC169DCD7B8"),
        result.initializeUpdateResponse);
  }

  @Test
  void rejectsInvalidHostChallengeLength() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new CardDiversificationDataService().readKdd(MockBIBO.of(), new byte[7]));
  }

  @Test
  void rejectsShortInitializeUpdateResponse() {
    MockBIBO bibo =
        MockBIBO.with("00A4040008A000000151000000", "6F108408A000000151000000A5049F6501FF9000")
            .then("80500000081122334455667788", "000023454965542048399000");

    assertThrows(
        IllegalStateException.class,
        () ->
            new CardDiversificationDataService().readKdd(bibo, HexUtil.parse("1122334455667788")));
  }
}
