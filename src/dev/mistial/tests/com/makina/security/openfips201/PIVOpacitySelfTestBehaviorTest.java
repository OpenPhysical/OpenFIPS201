package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.JavaCardEngine;

class PIVOpacitySelfTestBehaviorTest {
  private JavaCardEngine engine;

  @BeforeEach
  void initializeCryptoProvider() throws Exception {
    engine = JavaCardEngine.create();
    try (AutoCloseable ignored = enterEngineContext()) {
      PIVCrypto.terminate();
      PIVCrypto.init();
    }
  }

  @AfterEach
  void releaseCryptoProvider() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      PIVCrypto.terminate();
    }
  }

  @Test
  void compiledSuiteKdaKnownAnswerPassesAndClearsWorkspace() throws Exception {
    byte[] output = filled((short) 768);
    byte[] workspace = filled((short) 448);

    try (AutoCloseable ignored = enterEngineContext()) {
      assertTrue(new PIVOpacity(output, workspace).runCryptographicAlgorithmSelfTest());
    }

    assertZeroised(output);
    assertZeroised(workspace);
  }

  @Test
  void incorrectKnownAnswerFailsClosed() throws Exception {
    Field expectedField = PIVOpacity.class.getDeclaredField("KDA_EXPECTED");
    expectedField.setAccessible(true);
    byte[] expected = (byte[]) expectedField.get(null);
    byte original = expected[0];
    expected[0] ^= (byte) 1;
    try {
      try (AutoCloseable ignored = enterEngineContext()) {
        assertFalse(
            new PIVOpacity(new byte[768], new byte[448]).runCryptographicAlgorithmSelfTest());
      }
    } finally {
      expected[0] = original;
    }
  }

  @Test
  void sessionKeyDerivationClearsTransientKdfInput() throws Exception {
    byte[] output = new byte[768];
    byte[] workspace = new byte[448];
    short pointOffset = 8;
    short zOffset = 73;
    short nonceOffset = 105;
    short cardIdOffset = 121;
    java.util.Arrays.fill(workspace, zOffset, zOffset + 32, (byte) 0x5A);

    try (AutoCloseable ignored = enterEngineContext()) {
      new PIVOpacity(output, workspace)
          .deriveSessionKeys(
              (short) 32,
              (short) 16,
              (byte) 0x09,
              (short) 160,
              zOffset,
              nonceOffset,
              (short) 16,
              (short) 0,
              pointOffset,
              cardIdOffset,
              (byte) 0x00);
    }

    boolean derivedKeyPresent = false;
    for (int index = 0; index < 64; index++) {
      derivedKeyPresent |= output[index] != (byte) 0;
    }
    assertTrue(derivedKeyPresent, "derived session keys must remain available");
    for (int index = 128; index < output.length; index++) {
      assertTrue(output[index] == (byte) 0, "transient KDF input must be cleared");
    }
  }

  private static byte[] filled(short length) {
    byte[] result = new byte[length];
    java.util.Arrays.fill(result, (byte) 0xA5);
    return result;
  }

  private static void assertZeroised(byte[] value) {
    for (byte item : value) {
      assertTrue(item == (byte) 0);
    }
  }

  private AutoCloseable enterEngineContext() throws Exception {
    Method asCurrent = engine.getClass().getMethod("asCurrent");
    return (AutoCloseable) asCurrent.invoke(engine);
  }
}
