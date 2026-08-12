package dev.mistial.tools.openfips201.nist;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.smartcardio.ATR;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactorySpi;

public final class OpenFips201TerminalFactorySpi extends TerminalFactorySpi {
  static final String CONTACT_READER = "OpenFIPS201 Emulator Contact";
  static final String CONTACTLESS_READER = "OpenFIPS201 Emulator Contactless";
  private static final String CONTACTLESS_INTERFACE = "CONTACTLESS";
  private static final String SECURE_MESSAGING_INTERFACE = "SECURE_MESSAGING";
  private static final String VIRTUAL_CONTACT_INTERFACE = "VIRTUAL_CONTACT";

  private static volatile OpenFips201CardTerminals terminals =
      new OpenFips201CardTerminals(Collections.emptyList());

  public OpenFips201TerminalFactorySpi() {}

  static void install(NistCardTransport contact, NistCardTransport contactless) {
    List<CardTerminal> configured = new ArrayList<CardTerminal>();
    configured.add(new OpenFips201CardTerminal(CONTACT_READER, contact));
    configured.add(new OpenFips201CardTerminal(CONTACTLESS_READER, contactless));
    terminals = new OpenFips201CardTerminals(configured);
  }

  static void reset(String testInterface) throws CardException {
    terminals.reset(testInterface);
  }

  @Override
  protected CardTerminals engineTerminals() {
    return terminals;
  }

  private static final class OpenFips201CardTerminals extends CardTerminals {
    private final List<CardTerminal> terminals;

    OpenFips201CardTerminals(List<CardTerminal> terminals) {
      this.terminals = Collections.unmodifiableList(new ArrayList<CardTerminal>(terminals));
    }

    void reset(String testInterface) throws CardException {
      boolean useContactless =
          CONTACTLESS_INTERFACE.equalsIgnoreCase(testInterface)
              || SECURE_MESSAGING_INTERFACE.equalsIgnoreCase(testInterface)
              || VIRTUAL_CONTACT_INTERFACE.equalsIgnoreCase(testInterface);
      String reader = useContactless ? CONTACTLESS_READER : CONTACT_READER;
      for (CardTerminal terminal : terminals) {
        if (reader.equals(terminal.getName())) {
          ((OpenFips201CardTerminal) terminal).reset();
          return;
        }
      }
      throw new CardException("No emulator reader for interface: " + testInterface);
    }

    @Override
    public List<CardTerminal> list(State state) {
      if (state == State.CARD_ABSENT) {
        return Collections.emptyList();
      }
      return terminals;
    }

    @Override
    public boolean waitForChange(long timeout) {
      return false;
    }
  }

  private static final class OpenFips201CardTerminal extends CardTerminal {
    private final String name;
    private final NistCardTransport transport;

    OpenFips201CardTerminal(String name, NistCardTransport transport) {
      this.name = name;
      this.transport = transport;
    }

    @Override
    public String getName() {
      return name;
    }

    @Override
    public Card connect(String protocol) throws CardException {
      if (!"*".equals(protocol)
          && !"T=1".equals(protocol)
          && !"1".equals(protocol)
          && !"SCARD_PROTOCOL_T1".equals(protocol)) {
        throw new CardException("Unsupported emulator protocol: " + protocol);
      }
      return new OpenFips201Card(transport);
    }

    @Override
    public boolean isCardPresent() {
      return true;
    }

    @Override
    public boolean waitForCardPresent(long timeout) {
      return true;
    }

    @Override
    public boolean waitForCardAbsent(long timeout) {
      return false;
    }

    void reset() throws CardException {
      transport.reset();
    }
  }

  private static final class OpenFips201Card extends Card {
    private final NistCardTransport transport;
    private final CardChannel basicChannel;
    private boolean exclusive;

    OpenFips201Card(NistCardTransport transport) {
      this.transport = transport;
      basicChannel = new OpenFips201CardChannel(this, transport);
    }

    @Override
    public ATR getATR() {
      return new ATR(transport.getAtr());
    }

    @Override
    public String getProtocol() {
      return "T=1";
    }

    @Override
    public CardChannel getBasicChannel() {
      return basicChannel;
    }

    @Override
    public CardChannel openLogicalChannel() throws CardException {
      throw new CardException("Logical channels are not supported by the emulator harness");
    }

    @Override
    public void beginExclusive() {
      exclusive = true;
    }

    @Override
    public void endExclusive() {
      exclusive = false;
    }

    @Override
    public byte[] transmitControlCommand(int controlCode, byte[] command) throws CardException {
      throw new CardException("Control commands are not supported by the emulator harness");
    }

    @Override
    public void disconnect(boolean reset) throws CardException {
      exclusive = false;
      if (reset) {
        transport.reset();
      }
    }

    @Override
    public String toString() {
      return transport.name() + (exclusive ? " exclusive" : "");
    }
  }

  private static final class OpenFips201CardChannel extends CardChannel {
    private final Card card;
    private final NistCardTransport transport;

    OpenFips201CardChannel(Card card, NistCardTransport transport) {
      this.card = card;
      this.transport = transport;
    }

    @Override
    public Card getCard() {
      return card;
    }

    @Override
    public int getChannelNumber() {
      return 0;
    }

    @Override
    public ResponseAPDU transmit(CommandAPDU command) throws CardException {
      return new ResponseAPDU(transport.transmit(command.getBytes()));
    }

    @Override
    public int transmit(java.nio.ByteBuffer command, java.nio.ByteBuffer response)
        throws CardException {
      byte[] request = new byte[command.remaining()];
      command.get(request);
      byte[] reply = transport.transmit(request);
      if (response.remaining() < reply.length) {
        throw new CardException("Response buffer too small");
      }
      response.put(reply);
      return reply.length;
    }

    @Override
    public void close() throws CardException {
      throw new CardException("Basic channel cannot be closed");
    }
  }
}
