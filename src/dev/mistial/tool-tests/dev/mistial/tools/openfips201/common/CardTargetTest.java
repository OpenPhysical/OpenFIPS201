/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import org.junit.jupiter.api.Test;

class CardTargetTest {
  private static final List<CardTerminal> READERS =
      Arrays.<CardTerminal>asList(
          new NamedTerminal("NXP JCOP Reader 0"),
          new NamedTerminal("NXP JCOP Reader 0 Contactless"),
          new NamedTerminal("Other Reader 1"));

  @Test
  void exactNameWinsOverSubstringMatches() {
    assertEquals(
        "NXP JCOP Reader 0", CardTarget.selectTerminal(READERS, "NXP JCOP Reader 0").getName());
  }

  @Test
  void uniqueSubstringMatchIsSelected() {
    assertEquals("Other Reader 1", CardTarget.selectTerminal(READERS, "Other").getName());
  }

  @Test
  void ambiguousSubstringIsRefusedAndListsCandidates() {
    IllegalArgumentException failure =
        assertThrows(
            IllegalArgumentException.class, () -> CardTarget.selectTerminal(READERS, "JCOP"));

    assertTrue(failure.getMessage().contains("ambiguous"), failure.getMessage());
    assertTrue(failure.getMessage().contains("NXP JCOP Reader 0, NXP JCOP Reader 0 Contactless"));
  }

  @Test
  void noMatchAndUnfilteredMultipleReadersAreRefused() {
    assertThrows(
        IllegalArgumentException.class, () -> CardTarget.selectTerminal(READERS, "Missing"));
    assertThrows(IllegalArgumentException.class, () -> CardTarget.selectTerminal(READERS, ""));
    assertEquals(
        "Only",
        CardTarget.selectTerminal(
                Collections.<CardTerminal>singletonList(new NamedTerminal("Only")), "")
            .getName());
  }

  @Test
  void zmqResolvedNameIsTheEndpoint() throws Exception {
    assertEquals("zmq:tcp://127.0.0.1:1", CardTarget.parse("zmq:tcp://127.0.0.1:1").resolvedName());
  }

  private static final class NamedTerminal extends CardTerminal {
    private final String name;

    NamedTerminal(String name) {
      this.name = name;
    }

    @Override
    public String getName() {
      return name;
    }

    @Override
    public Card connect(String protocol) {
      throw new UnsupportedOperationException("selection test terminal");
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
  }
}
