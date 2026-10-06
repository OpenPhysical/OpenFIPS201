/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.common;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class HexUtilTest {
  private static final String BAD_KEY = "40414243444546474849404B4C4D4E4G";

  @Test
  void invalidCharacterMessageCarriesIndexAndLengthOnly() {
    IllegalArgumentException failure =
        assertThrows(IllegalArgumentException.class, () -> HexUtil.parse(BAD_KEY));

    String message = failure.getMessage();
    assertFalse(message.contains(BAD_KEY), message);
    assertFalse(message.contains("4041"), message);
    assertTrue(message.contains("index 31"), message);
    assertTrue(message.contains("32"), message);
  }

  @Test
  void oddLengthMessageCarriesNoDigits() {
    IllegalArgumentException failure =
        assertThrows(IllegalArgumentException.class, () -> HexUtil.parse("ABCDE"));

    assertFalse(failure.getMessage().contains("ABCDE"), failure.getMessage());
  }

  @Test
  void parseSecretDecodesWithSeparatorsAndLeavesInputToCaller() {
    char[] input = "40:41 42\t43\n".toCharArray();

    assertArrayEquals(new byte[] {0x40, 0x41, 0x42, 0x43}, HexUtil.parseSecret(input));
    assertArrayEquals("40:41 42\t43\n".toCharArray(), input);
  }

  @Test
  void rejectsNonAsciiDigits() {
    // U+0661 ARABIC-INDIC DIGIT ONE is a Unicode digit but not a hex digit.
    char[] input = {'0', (char) 0x0661};
    assertThrows(IllegalArgumentException.class, () -> HexUtil.parseSecret(input));
  }
}
