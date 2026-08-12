/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.common;

import apdu4j.core.BIBO;
import java.util.List;
import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

public final class CardTarget {
  private static final int DEFAULT_TIMEOUT_MS = 10_000;

  private final String scheme;
  private final String value;
  private final int timeoutMs;

  private CardTarget(String scheme, String value, int timeoutMs) {
    this.scheme = scheme;
    this.value = value;
    this.timeoutMs = timeoutMs;
  }

  public static CardTarget parse(String target) {
    return parse(target, DEFAULT_TIMEOUT_MS);
  }

  public static CardTarget parse(String target, int timeoutMs) {
    if (target == null || target.isEmpty()) {
      throw new IllegalArgumentException("--target is required");
    }
    if (target.startsWith("pcsc:")) {
      return new CardTarget("pcsc", target.substring(5), timeoutMs);
    }
    if (target.startsWith("zmq:")) {
      return new CardTarget("zmq", target.substring(4), timeoutMs);
    }
    throw new IllegalArgumentException("--target must start with pcsc: or zmq:");
  }

  public BIBO openBibo() throws Exception {
    if ("zmq".equals(scheme)) {
      return new ZmqBibo(value, timeoutMs);
    }
    CardTerminal terminal = selectTerminal(value);
    Card card = terminal.connect("*");
    return new SmartCardBibo(card);
  }

  public CardTransport openTransport() throws Exception {
    return new CardTransport(openBibo());
  }

  public boolean isZmq() {
    return "zmq".equals(scheme);
  }

  public String displayName() {
    return scheme + ":" + value;
  }

  public static void listPcscReaders() throws Exception {
    List<CardTerminal> terminals = TerminalFactory.getDefault().terminals().list();
    if (terminals.isEmpty()) {
      System.out.println("No PC/SC readers found.");
      return;
    }
    for (CardTerminal terminal : terminals) {
      System.out.println(terminal.getName());
    }
  }

  private static CardTerminal selectTerminal(String readerFilter) throws Exception {
    List<CardTerminal> terminals = TerminalFactory.getDefault().terminals().list();
    if (readerFilter != null && !readerFilter.isEmpty()) {
      for (CardTerminal terminal : terminals) {
        if (terminal.getName().contains(readerFilter)) {
          return terminal;
        }
      }
      throw new IllegalArgumentException(
          "No PC/SC reader matched: "
              + readerFilter
              + "; available readers: "
              + terminalNames(terminals));
    }
    if (terminals.size() == 1) {
      return terminals.get(0);
    }
    throw new IllegalArgumentException(
        "Use --target pcsc:<reader> when zero or multiple PC/SC readers are present; available"
            + " readers: "
            + terminalNames(terminals));
  }

  private static String terminalNames(List<CardTerminal> terminals) {
    if (terminals.isEmpty()) {
      return "(none)";
    }
    StringBuilder names = new StringBuilder();
    for (CardTerminal terminal : terminals) {
      if (names.length() > 0) {
        names.append(", ");
      }
      names.append(terminal.getName());
    }
    return names.toString();
  }
}
