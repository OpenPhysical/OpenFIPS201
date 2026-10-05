/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.gp;

import apdu4j.core.BIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.CardTransport;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.common.HexUtil;
import java.security.SecureRandom;
import java.util.Arrays;

public final class CardDiversificationDataService {
  private static final int KDD_LENGTH = 10;
  private static final int INITIALIZE_UPDATE_MIN_LENGTH = 28;

  public Result readKdd(CardTarget target) throws Exception {
    byte[] hostChallenge = new byte[8];
    new SecureRandom().nextBytes(hostChallenge);
    try (CardTransport transport = target.openTransport()) {
      return readKdd(transport, hostChallenge);
    }
  }

  public Result readKdd(CardTarget target, byte[] hostChallenge) throws Exception {
    try (CardTransport transport = target.openTransport()) {
      return readKdd(transport, hostChallenge);
    }
  }

  public Result readKdd(CardTransport transport) {
    byte[] hostChallenge = new byte[8];
    new SecureRandom().nextBytes(hostChallenge);
    return readKdd(transport, hostChallenge);
  }

  public Result readKdd(CardTransport transport, byte[] hostChallenge) {
    return readKdd(transport.bibo(), hostChallenge);
  }

  Result readKdd(BIBO bibo, byte[] hostChallenge) {
    if (hostChallenge == null || hostChallenge.length != 8) {
      throw new IllegalArgumentException("host challenge must be 8 bytes");
    }

    ResponseAPDU select =
        bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, GlobalPlatformSession.ISD_AID, 0));
    requireSuccess(select, "SELECT ISD");

    ResponseAPDU initializeUpdate =
        bibo.transmit(new CommandAPDU(0x80, 0x50, 0x00, 0x00, hostChallenge, 0));
    requireSuccess(initializeUpdate, "INITIALIZE UPDATE");
    byte[] response = initializeUpdate.getData();
    if (response.length < INITIALIZE_UPDATE_MIN_LENGTH) {
      throw new IllegalStateException(
          "INITIALIZE UPDATE response too short: " + response.length + " bytes");
    }

    return new Result(Arrays.copyOfRange(response, 0, KDD_LENGTH), response);
  }

  /**
   * Checks an operator-supplied KDD against the KDD the card returned in INITIALIZE UPDATE (GP
   * SCP03 v1.1.2 Section 7.1.1.6 Table 7-3: "The key diversification data is data typically used by
   * a backend system to derive the card static keys"). Keys are always derived from the card's KDD;
   * a different expected value is refused before any EXTERNAL AUTHENTICATE or PUT KEY.
   *
   * @param cardKdd KDD read from the card
   * @param expectedKdd operator-supplied KDD, or {@code null} when none was supplied
   * @return a copy of {@code cardKdd}
   */
  public static byte[] requireExpectedKdd(byte[] cardKdd, byte[] expectedKdd) {
    if (expectedKdd != null && !Arrays.equals(cardKdd, expectedKdd)) {
      throw new IllegalArgumentException(
          "--kdd "
              + HexUtil.format(expectedKdd)
              + " does not match the card's KDD "
              + HexUtil.format(cardKdd)
              + "; refusing before any EXTERNAL AUTHENTICATE or PUT KEY");
    }
    return cardKdd.clone();
  }

  private static void requireSuccess(ResponseAPDU response, String label) {
    if (response.getSW() != 0x9000) {
      throw new IllegalStateException(
          label + " failed SW=" + String.format("0x%04X", response.getSW()));
    }
  }

  public static final class Result {
    public final byte[] kdd;
    public final byte[] initializeUpdateResponse;

    Result(byte[] kdd, byte[] initializeUpdateResponse) {
      this.kdd = kdd;
      this.initializeUpdateResponse = initializeUpdateResponse;
    }
  }
}
