package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

class PIVAuthenticationContextTest {
  @Test
  void resetZeroisesEntireContext() {
    PIVAuthenticationContext context = PIVAuthenticationContext.createForTest((short) 21);
    Arrays.fill(context.buffer(), (byte) 0x5A);

    context.reset();

    assertArrayEquals(new byte[21], context.buffer());
  }
}
