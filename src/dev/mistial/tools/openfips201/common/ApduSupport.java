/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.common;

import apdu4j.core.BIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import java.util.Arrays;

/** Shared host-side APDU status checking and ISO command-chain transmission. */
public final class ApduSupport {
  public interface Transmitter {
    ResponseAPDU transmit(CommandAPDU command);
  }

  private ApduSupport() {}

  public static ResponseAPDU expectSuccess(ResponseAPDU response, String context) {
    if (response.getSW() != 0x9000) {
      throw new IllegalStateException(
          String.format("%s failed with SW 0x%04X", context, response.getSW()));
    }
    return response;
  }

  /** Selects an application by DF name and requires a successful response. */
  public static ResponseAPDU selectApplication(
      Transmitter transmitter, byte[] aid, String context) {
    return expectSuccess(
        transmitter.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aid, 256)), context);
  }

  /** Selects an application on a raw transport without introducing a session wrapper. */
  public static ResponseAPDU selectApplication(BIBO bibo, byte[] aid, String context) {
    return selectApplication(bibo::transmit, aid, context);
  }

  /**
   * Sends one logical command using ISO 7816 command chaining.
   *
   * @param baseCla command class without the chaining bit
   * @param maxChunk maximum data bytes carried by each physical APDU
   */
  public static void sendChained(
      Transmitter transmitter,
      int baseCla,
      int ins,
      int p1,
      int p2,
      byte[] payload,
      int maxChunk,
      String context) {
    if (payload.length == 0 || maxChunk <= 0) {
      throw new IllegalArgumentException("Chained APDU requires payload and positive chunk size");
    }
    int offset = 0;
    while (offset < payload.length) {
      int chunkLength = Math.min(maxChunk, payload.length - offset);
      byte[] chunk = Arrays.copyOfRange(payload, offset, offset + chunkLength);
      offset += chunkLength;
      int cla = offset < payload.length ? baseCla | 0x10 : baseCla;
      expectSuccess(transmitter.transmit(new CommandAPDU(cla, ins, p1, p2, chunk)), context);
    }
  }
}
