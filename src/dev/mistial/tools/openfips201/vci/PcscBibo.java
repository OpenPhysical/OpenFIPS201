/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ******************************************************************************/

package dev.mistial.tools.openfips201.vci;

import apdu4j.core.BIBO;
import apdu4j.core.BIBOException;
import java.util.List;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.TerminalFactory;

/** apdu4j {@link BIBO} over a PC/SC reader, used when the VCI tool targets a physical card. */
final class PcscBibo implements BIBO {
  private final Card card;
  private final CardChannel channel;

  private PcscBibo(Card card) {
    this.card = card;
    this.channel = card.getBasicChannel();
  }

  static PcscBibo open(String readerFilter) throws Exception {
    List<CardTerminal> terminals = TerminalFactory.getDefault().terminals().list();
    CardTerminal selected = null;
    for (CardTerminal terminal : terminals) {
      if (readerFilter == null || readerFilter.isEmpty() || terminal.getName().contains(readerFilter)) {
        selected = terminal;
        break;
      }
    }
    if (selected == null) {
      throw new IllegalArgumentException("No PC/SC reader matched: " + readerFilter);
    }
    return new PcscBibo(selected.connect("*"));
  }

  @Override
  public byte[] transceive(byte[] command) throws BIBOException {
    try {
      return channel.transmit(new CommandAPDU(command)).getBytes();
    } catch (Exception e) {
      throw new BIBOException("PC/SC transceive failed", e);
    }
  }

  @Override
  public void close() {
    try {
      card.disconnect(false);
    } catch (Exception ignored) {
      // Best effort.
    }
  }
}
