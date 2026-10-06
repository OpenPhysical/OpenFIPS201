/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.common;

import apdu4j.core.BIBO;
import java.util.ArrayList;
import java.util.List;
import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

public final class CardTarget implements CardConnectionFactory {
  private static final int DEFAULT_TIMEOUT_MS = 10_000;

  private final String scheme;
  private final String value;
  private final int timeoutMs;
  private volatile String resolvedReader;

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
    resolvedReader = terminal.getName();
    return new SmartCardBibo(card);
  }

  @Override
  public BIBO open() throws Exception {
    return openBibo();
  }

  public CardTransport openTransport() throws Exception {
    return CardTransport.own(openBibo());
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

  /**
   * Returns the PC/SC reader name this target resolves to, or {@link #displayName()} for a {@code
   * zmq:} target. After {@link #openBibo()} it is the reader that was connected; before, the
   * readers are enumerated and selected under the same rules.
   */
  public String resolvedName() throws Exception {
    if ("zmq".equals(scheme)) {
      return displayName();
    }
    String resolved = resolvedReader;
    return resolved != null ? resolved : selectTerminal(value).getName();
  }

  private static CardTerminal selectTerminal(String readerFilter) throws Exception {
    return selectTerminal(TerminalFactory.getDefault().terminals().list(), readerFilter);
  }

  /**
   * Selects one reader. A reader whose name equals {@code readerFilter} wins. Otherwise exactly one
   * reader name must contain {@code readerFilter}; several matches are refused and listed, so a
   * mutating command never runs on whichever reader PC/SC enumerates first. With no filter, exactly
   * one reader must be present.
   */
  static CardTerminal selectTerminal(List<CardTerminal> terminals, String readerFilter) {
    if (readerFilter != null && !readerFilter.isEmpty()) {
      List<CardTerminal> matches = new ArrayList<CardTerminal>();
      for (CardTerminal terminal : terminals) {
        if (terminal.getName().equals(readerFilter)) {
          return terminal;
        }
        if (terminal.getName().contains(readerFilter)) {
          matches.add(terminal);
        }
      }
      if (matches.size() == 1) {
        return matches.get(0);
      }
      if (matches.size() > 1) {
        throw new IllegalArgumentException(
            "PC/SC reader filter is ambiguous: "
                + readerFilter
                + " matches "
                + terminalNames(matches)
                + "; use the full reader name");
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
