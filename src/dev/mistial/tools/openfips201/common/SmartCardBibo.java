/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.common;

import apdu4j.core.BIBO;
import apdu4j.core.BIBOException;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public final class SmartCardBibo implements BIBO {
  private final Card card;

  public SmartCardBibo(Card card) {
    this.card = card;
  }

  @Override
  public byte[] transceive(byte[] command) throws BIBOException {
    try {
      ResponseAPDU response = card.getBasicChannel().transmit(new CommandAPDU(command));
      return response.getBytes();
    } catch (CardException e) {
      throw new BIBOException("PC/SC transmit failed", e);
    }
  }

  /**
   * Disconnects with a card reset (SCARD_RESET_CARD), so security status such as a verified PIV PIN
   * does not survive into the next PC/SC client's session.
   */
  @Override
  public void close() {
    try {
      card.disconnect(true);
    } catch (CardException ignored) {
      // Best effort close; the command that failed should report the real error.
    }
  }
}
