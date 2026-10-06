package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
    java.util.Arrays.fill(
        workspace, PIVOpacity.OFFSET_Z, PIVOpacity.OFFSET_Z + PIVOpacity.FIELD_LENGTH, (byte) 0x5A);

    try (AutoCloseable ignored = enterEngineContext()) {
      new PIVOpacity(output, workspace).deriveSuiteSessionKeys((byte) 0x00);
    }

    boolean derivedKeyPresent = false;
    for (int index = 0; index < PIVOpacity.SESSION_KEY_LENGTH * 4; index++) {
      derivedKeyPresent |= output[index] != (byte) 0;
    }
    assertTrue(derivedKeyPresent, "derived session keys must remain available");
    for (int index = 128; index < output.length; index++) {
      assertTrue(output[index] == (byte) 0, "transient KDF input must be cleared");
    }
  }

  /**
   * The KDA CAST and OPACITY establishment derive through the one suite entry point, so the CAST
   * parameters are the production ones. This pins that suite geometry to SP 800-73-5 Part 2 Table
   * 18 and to the secure-messaging session-key length.
   */
  @Test
  void selfTestUsesProductionSuiteParameters() throws Exception {
    boolean cs7 = "CS7".equalsIgnoreCase(System.getProperty("vci.suite", "CS2"));
    short field = (short) (cs7 ? 48 : 32);
    assertEquals(field, PIVOpacity.FIELD_LENGTH);
    assertEquals((short) (cs7 ? 32 : 16), PIVOpacity.SESSION_KEY_LENGTH);
    assertEquals((short) (cs7 ? 24 : 16), PIVOpacity.NONCE_LENGTH);
    assertEquals((byte) (cs7 ? 0x0D : 0x09), PIV.OPACITY_KDF_ALG_ID);
    assertEquals(cs7 ? PIV.ID_ALG_ECC_CS7 : PIV.ID_ALG_ECC_CS2, PIV.ID_ALG_ECC_SM);

    Field sessionKeyLength = PIVSecureMessaging.class.getDeclaredField("LENGTH_SESSION_KEY");
    sessionKeyLength.setAccessible(true);
    assertEquals(PIVOpacity.SESSION_KEY_LENGTH, sessionKeyLength.getShort(null));

    // The hash output written at OPACITY_HASH_TMP and the ID_sICC field must fit the SM workspace.
    assertTrue(PIVOpacity.OFFSET_ID_SICC + 8 <= PIV.OPACITY_HASH_TMP);
    assertTrue(PIV.OPACITY_HASH_TMP + field <= PIV.LENGTH_SM_RESPONSE);
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
