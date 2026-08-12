package dev.mistial.tools.openfips201.nist;

import apdu4j.core.BIBO;
import apdu4j.core.BIBOException;
import com.makina.security.openfips201.OpenFIPS201;
import javacard.framework.AID;
import javax.smartcardio.CardException;
import pro.javacard.engine.JavaCardEngine;

final class JCardEngineNistCardTransport implements NistCardTransport {
  private static final byte[] OPENFIPS201_AID_BYTES = hex("A000000308000010000100");

  static final class SharedCard implements AutoCloseable {
    private final JavaCardEngine engine;
    private BIBO session;
    private String protocol;

    private SharedCard(JavaCardEngine engine) {
      this.engine = engine;
    }

    byte[] getAtr() {
      return engine.getATR();
    }

    byte[] transmit(String requestedProtocol, byte[] command) throws BIBOException {
      return connect(requestedProtocol, false).transceive(command);
    }

    void reset(String requestedProtocol) {
      connect(requestedProtocol, true);
    }

    BIBO openBibo(final String requestedProtocol) {
      return new BIBO() {
        @Override
        public byte[] transceive(byte[] command) throws BIBOException {
          return SharedCard.this.transmit(requestedProtocol, command);
        }

        @Override
        public void close() {
          closeSession();
        }
      };
    }

    private BIBO connect(String requestedProtocol, boolean reset) {
      if (session != null && (reset || !requestedProtocol.equals(protocol))) {
        session.close();
        session = null;
      }
      if (session == null) {
        protocol = requestedProtocol;
        session = engine.connect(protocol, true);
      }
      return session;
    }

    @Override
    public void close() {
      closeSession();
    }

    private void closeSession() {
      if (session != null) {
        session.close();
        session = null;
      }
    }
  }

  private final SharedCard card;
  private final String protocol;

  static SharedCard createCard() {
    JavaCardEngine engine = JavaCardEngine.create();
    AID aid = new AID(OPENFIPS201_AID_BYTES, (short) 0, (byte) OPENFIPS201_AID_BYTES.length);
    engine.installApplet(aid, OpenFIPS201.class, new byte[0]);
    return new SharedCard(engine);
  }

  JCardEngineNistCardTransport(SharedCard card, String protocol) {
    this.card = card;
    this.protocol = protocol;
  }

  @Override
  public String name() {
    return "OpenFIPS201 JCardEngine";
  }

  @Override
  public byte[] getAtr() {
    return card.getAtr();
  }

  @Override
  public byte[] transmit(byte[] command) throws CardException {
    try {
      return card.transmit(protocol, command);
    } catch (BIBOException e) {
      throw new CardException("JCardEngine APDU exchange failed", e);
    }
  }

  @Override
  public void reset() throws CardException {
    try {
      card.reset(protocol);
    } catch (RuntimeException e) {
      throw new CardException("JCardEngine reset failed", e);
    }
  }

  @Override
  public void close() {
    // SharedCard owns the single simulator session.
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
