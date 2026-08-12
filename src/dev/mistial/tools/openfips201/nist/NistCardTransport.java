package dev.mistial.tools.openfips201.nist;

import javax.smartcardio.CardException;

interface NistCardTransport extends AutoCloseable {
  String name();

  byte[] getAtr();

  byte[] transmit(byte[] command) throws CardException;

  @Override
  void close();
}
