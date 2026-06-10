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

package dev.mistial.tools.openfips201.attestation;

import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import java.util.EnumSet;
import java.util.List;
import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import pro.javacard.capfile.AID;
import pro.javacard.gp.GPSecureChannelVersion;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.keys.PlaintextKeys;

final class GlobalPlatformCardSession implements CardSession {
  private final SmartCardBibo bibo;
  private final GPSession session;
  private final ScpMode scpMode;

  private GlobalPlatformCardSession(SmartCardBibo bibo, GPSession session, ScpMode scpMode) {
    this.bibo = bibo;
    this.session = session;
    this.scpMode = scpMode;
  }

  static GlobalPlatformCardSession open(
      String readerFilter,
      ScpMode scp,
      int keyVersion,
      byte[] encKey,
      byte[] macKey,
      byte[] dekKey,
      byte[] aid)
      throws Exception {
    CardTerminal terminal = selectTerminal(readerFilter);
    Card card = terminal.connect("*");
    SmartCardBibo bibo = new SmartCardBibo(card);
    try {
      GPSession gp = GPSession.connect(bibo, new AID(aid));
      PlaintextKeys keys = PlaintextKeys.fromKeys(encKey, macKey, dekKey);
      keys.setVersion(keyVersion);
      gp.openSecureChannel(
          keys,
          scp.toSecureChannelVersion(),
          null,
          EnumSet.of(GPSession.APDUMode.MAC, GPSession.APDUMode.ENC));
      ScpMode selectedScp = ScpMode.fromSecureChannelVersion(gp.getSecureChannel());
      return new GlobalPlatformCardSession(bibo, gp, selectedScp);
    } catch (Exception e) {
      bibo.close();
      throw e;
    }
  }

  static void listReaders() throws Exception {
    List<CardTerminal> terminals = TerminalFactory.getDefault().terminals().list();
    if (terminals.isEmpty()) {
      System.out.println("No PC/SC readers found.");
      return;
    }
    for (CardTerminal terminal : terminals) {
      System.out.println(terminal.getName());
    }
  }

  @Override
  public ResponseAPDU transmit(CommandAPDU command) {
    return session.transmit(command);
  }

  ScpMode getScpMode() {
    return scpMode;
  }

  @Override
  public void close() {
    bibo.close();
  }

  private static CardTerminal selectTerminal(String readerFilter) throws Exception {
    List<CardTerminal> terminals = TerminalFactory.getDefault().terminals().list();
    if (readerFilter != null && !readerFilter.isEmpty()) {
      for (CardTerminal terminal : terminals) {
        if (terminal.getName().contains(readerFilter)) {
          return terminal;
        }
      }
      throw new IllegalArgumentException("No PC/SC reader matched: " + readerFilter);
    }
    if (terminals.size() == 1) {
      return terminals.get(0);
    }
    throw new IllegalArgumentException(
        "Specify --reader when zero or multiple PC/SC readers are present");
  }

  enum ScpMode {
    AUTO,
    SCP02,
    SCP03;

    GPSecureChannelVersion toSecureChannelVersion() {
      if (this == AUTO) {
        // A null version asks GPPro to send one INITIALIZE UPDATE and use the SCP version reported
        // by the card in that response. It does not try multiple EXTERNAL AUTHENTICATE attempts.
        return null;
      }
      return new GPSecureChannelVersion(
          this == SCP02 ? GPSecureChannelVersion.SCP.SCP02 : GPSecureChannelVersion.SCP.SCP03, 0);
    }

    static ScpMode fromSecureChannelVersion(GPSecureChannelVersion version) {
      if (version.scp == GPSecureChannelVersion.SCP.SCP02) {
        return SCP02;
      }
      if (version.scp == GPSecureChannelVersion.SCP.SCP03) {
        return SCP03;
      }
      throw new IllegalStateException("Unsupported SCP version reported by card: " + version);
    }
  }
}
