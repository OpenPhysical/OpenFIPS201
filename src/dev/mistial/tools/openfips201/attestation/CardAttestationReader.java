/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.attestation;

import apdu4j.core.BIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import dev.mistial.tools.openfips201.common.ApduSupport;
import dev.mistial.tools.openfips201.common.CardSession;
import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.CardTransport;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.common.LogicalResponseCollector;

/**
 * Reads, over plain PIV, what a relying party verifies: the attestation leaf of a slot ({@code 00
 * F9 <slot> 00}) and the card's F9 certificate ({@code 00 F9 F9 00}). When a PIN is supplied it is
 * verified first ({@code 00 20 00 80}), as slots whose access rule requires the PIN need.
 */
public final class CardAttestationReader {
  private static final int MAX_CERTIFICATE = 4096;

  private CardAttestationReader() {}

  /** The leaf and F9 certificate read from the card. */
  public static final class Result {
    private final byte[] leaf;
    private final byte[] f9;

    Result(byte[] leaf, byte[] f9) {
      this.leaf = leaf;
      this.f9 = f9;
    }

    public byte[] leaf() {
      return leaf.clone();
    }

    public byte[] f9Certificate() {
      return f9.clone();
    }
  }

  /**
   * @param pin the eight-octet PIV PIN, or null
   */
  public static Result read(CardTarget target, byte slot, byte[] pin) throws Exception {
    try (CardTransport transport = target.openTransport()) {
      final BIBO bibo = transport.bibo();
      CardSession session =
          new CardSession() {
            @Override
            public ResponseAPDU transmit(CommandAPDU command) {
              return bibo.transmit(command);
            }

            @Override
            public void close() {}
          };
      ApduSupport.selectApplication(bibo, GlobalPlatformSession.PIV_AID, "SELECT PIV");
      if (pin != null) {
        ResponseAPDU verified = bibo.transmit(new CommandAPDU(0x00, 0x20, 0x00, 0x80, pin));
        if (verified.getSW() != 0x9000) {
          throw new IllegalStateException(
              "VERIFY PIN failed SW=" + String.format("0x%04X", verified.getSW()));
        }
      }
      ResponseAPDU attest = bibo.transmit(new CommandAPDU(0x00, 0xF9, slot & 0xFF, 0x00, 256));
      if (attest.getSW() == 0x6982) {
        throw new IllegalStateException(
            String.format(
                "slot %02X requires the PIV PIN; supply --pin-env or --pin-file", slot & 0xFF));
      }
      byte[] leaf =
          LogicalResponseCollector.collect(
              session, attest, 0x00, MAX_CERTIFICATE, "ATTEST " + String.format("%02X", slot));
      byte[] f9 =
          LogicalResponseCollector.collect(
              session,
              bibo.transmit(new CommandAPDU(0x00, 0xF9, 0xF9, 0x00, 256)),
              0x00,
              MAX_CERTIFICATE,
              "read F9 certificate");
      return new Result(leaf, f9);
    }
  }
}
