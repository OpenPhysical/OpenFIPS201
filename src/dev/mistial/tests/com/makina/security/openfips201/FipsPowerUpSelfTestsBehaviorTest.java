package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.JavaCardEngine;

class FipsPowerUpSelfTestsBehaviorTest {
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
  void compiledProfileKnownAnswersPass() throws Exception {
    // FIPS 140-3 IG 10.3.A requires CASTs before first use of each approved
    // cryptographic function implemented inside the module boundary.
    try (AutoCloseable ignored = enterEngineContext()) {
      assertTrue(new FipsPowerUpSelfTests().run(new byte[128]));
    }
  }

  @Test
  void incorrectKnownAnswerFailsClosed() throws Exception {
    Field expectedField = FipsPowerUpSelfTests.class.getDeclaredField("AES_ENCRYPT_ZERO");
    expectedField.setAccessible(true);
    byte[] expected = (byte[]) expectedField.get(null);
    byte original = expected[0];
    expected[0] ^= (byte) 1;
    try {
      try (AutoCloseable ignored = enterEngineContext()) {
        assertFalse(new FipsPowerUpSelfTests().run(new byte[128]));
      }
    } finally {
      expected[0] = original;
    }
  }

  @Test
  void incorrectAesDecryptKnownAnswerFailsClosed() throws Exception {
    Field expectedField = FipsPowerUpSelfTests.class.getDeclaredField("AES_DECRYPT_PLAINTEXT");
    expectedField.setAccessible(true);
    byte[] expected = (byte[]) expectedField.get(null);
    byte original = expected[0];
    expected[0] ^= (byte) 1;
    try {
      try (AutoCloseable ignored = enterEngineContext()) {
        assertFalse(new FipsPowerUpSelfTests().run(new byte[128]));
      }
    } finally {
      expected[0] = original;
    }
  }

  private AutoCloseable enterEngineContext() throws Exception {
    Method asCurrent = engine.getClass().getMethod("asCurrent");
    return (AutoCloseable) asCurrent.invoke(engine);
  }
}
