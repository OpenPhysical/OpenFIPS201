package dev.mistial.tools.openfips201.nist;

import apdu4j.core.BIBO;
import apdu4j.core.BIBOException;
import com.makina.security.openfips201.OpenFIPS201;
import javacard.framework.AID;
import javax.smartcardio.CardException;
import pro.javacard.engine.JavaCardEngine;

final class JCardEngineNistCardTransport implements NistCardTransport {
  private static final byte[] OPENFIPS201_AID_BYTES = hex("A000000308000010000100");

  private final JavaCardEngine engine;
  private final BIBO session;

  JCardEngineNistCardTransport() {
    engine = JavaCardEngine.create();
    AID aid = new AID(OPENFIPS201_AID_BYTES, (short) 0, (byte) OPENFIPS201_AID_BYTES.length);
    engine.installApplet(aid, OpenFIPS201.class, new byte[0]);
    session = engine.connect();
  }

  @Override
  public String name() {
    return "OpenFIPS201 JCardEngine";
  }

  @Override
  public byte[] getAtr() {
    return engine.getATR();
  }

  @Override
  public byte[] transmit(byte[] command) throws CardException {
    try {
      return session.transceive(command);
    } catch (BIBOException e) {
      throw new CardException("JCardEngine APDU exchange failed", e);
    }
  }

  @Override
  public void close() {
    session.close();
  }

  private static byte[] hex(String value) {
    byte[] out = new byte[value.length() / 2];
    for (int i = 0; i < value.length(); i += 2) {
      out[i / 2] =
          (byte)
              ((Character.digit(value.charAt(i), 16) << 4)
                  | Character.digit(value.charAt(i + 1), 16));
    }
    return out;
  }
}
