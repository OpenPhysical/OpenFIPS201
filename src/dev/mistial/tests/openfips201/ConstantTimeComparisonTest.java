package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class ConstantTimeComparisonTest {
  @Test
  void acceptsEqualRangesAtDifferentOffsets() {
    byte[] first = {0, 1, 2, 3, 4, 5};
    byte[] second = {9, 9, 1, 2, 3, 4, 9};

    assertTrue(
        PIVSecurityProvider.arrayEqualsConstantTime(
            first, (short) 1, second, (short) 2, (short) 4));
  }

  @Test
  void rejectsMismatchAtEveryPosition() {
    byte[] expected = {1, 2, 3, 4};

    for (short mismatch = 0; mismatch < expected.length; mismatch++) {
      byte[] actual = expected.clone();
      actual[mismatch] ^= 0x01;
      assertFalse(
          PIVSecurityProvider.arrayEqualsConstantTime(
              expected, (short) 0, actual, (short) 0, (short) expected.length));
    }
  }
}
