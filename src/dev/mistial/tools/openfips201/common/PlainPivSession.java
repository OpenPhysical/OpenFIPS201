package dev.mistial.tools.openfips201.common;

import apdu4j.core.BIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;

/** A fresh, unwrapped PIV application session. */
public final class PlainPivSession implements CardSession {
  private final BIBO bibo;
  private boolean closed;

  public static PlainPivSession open(CardConnectionFactory connections, byte[] aid)
      throws Exception {
    BIBO bibo = connections.open();
    try {
      PlainPivSession session = new PlainPivSession(bibo);
      ApduSupport.selectApplication(session::transmit, aid, "SELECT PIV");
      return session;
    } catch (Exception e) {
      bibo.close();
      throw e;
    }
  }

  private PlainPivSession(BIBO bibo) {
    this.bibo = bibo;
  }

  @Override
  public ResponseAPDU transmit(CommandAPDU command) {
    if (closed) throw new IllegalStateException("Plain PIV session is closed");
    return new ResponseAPDU(bibo.transceive(command.getBytes()));
  }

  @Override
  public void close() {
    if (closed) return;
    closed = true;
    bibo.close();
  }
}
