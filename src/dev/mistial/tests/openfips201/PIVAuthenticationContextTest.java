package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.util.Arrays;
import javacard.framework.JCSystem;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class PIVAuthenticationContextTest {
  @Test
  void resetZeroisesEntireContext() {
    PIVAuthenticationContext context;
    try (MockedStatic<JCSystem> mocked = Mockito.mockStatic(JCSystem.class)) {
      mocked
          .when(() -> JCSystem.makeTransientByteArray(Mockito.anyShort(), Mockito.anyByte()))
          .thenAnswer(invocation -> new byte[(short) invocation.getArgument(0)]);
      context = new PIVAuthenticationContext((short) 21);
    }
    Arrays.fill(context.buffer(), (byte) 0x5A);

    context.reset();

    assertArrayEquals(new byte[21], context.buffer());
  }
}
