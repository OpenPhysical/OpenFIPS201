package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.JavaCardEngine;

/**
 * SP 800-78-5 Section 3.1 Table 1 note 3: "3TDEA is Triple DES using Keying Option 1 from
 * [SP800-67], which requires that all three keys be unique".
 */
class PIVKeyObjectSYMTest {
  private final JavaCardEngine engine = JavaCardEngine.create();

  @Test
  void tdeaKeyRequiresThreeDistinctKeys() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      byte[] k1 = block((byte) 0x01);
      byte[] k2 = block((byte) 0x23);
      byte[] k3 = block((byte) 0x45);
      // k1 with every parity bit flipped is the same DES key.
      byte[] k1Parity = k1.clone();
      for (int i = 0; i < k1Parity.length; i++) k1Parity[i] ^= 0x01;

      byte[][][] degenerate = {
        {k1, k1, k1}, {k1, k1, k3}, {k1, k2, k2}, {k1, k2, k1}, {k1, k2, k1Parity}
      };
      for (byte[][] parts : degenerate) {
        PIVKeyObjectSYM key = createTdea();
        byte[] bundle = concat(parts);
        ISOException thrown =
            assertThrows(
                ISOException.class,
                () ->
                    key.updateElement(
                        PIVKeyObjectSYM.ELEMENT_KEY, bundle, (short) 0, (short) bundle.length));
        assertEquals(ISO7816.SW_WRONG_DATA, thrown.getReason());
        assertFalse(key.isInitialised(), "A degenerate 3TDEA key must not be loaded");
      }

      PIVKeyObjectSYM key = createTdea();
      byte[] bundle = concat(new byte[][] {k1, k2, k3});
      key.updateElement(PIVKeyObjectSYM.ELEMENT_KEY, bundle, (short) 0, (short) bundle.length);
      assertTrue(key.isInitialised(), "Three distinct keys are accepted");
    }
  }

  @Test
  void aes192KeyIsNotSubjectToTdeaKeyingRule() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      PIVKeyObjectSYM key =
          PIVKeyObjectSYM.create(
              (byte) 0x9B,
              PIVObject.ACCESS_MODE_ALWAYS,
              PIVObject.ACCESS_MODE_NEVER,
              (byte) 0x9B,
              PIV.ID_ALG_AES_192,
              PIVKeyObject.ROLE_AUTHENTICATE,
              (byte) (PIVKeyObject.ATTR_PERMIT_EXTERNAL | PIVKeyObject.ATTR_IMPORTABLE));
      byte[] repeated = concat(new byte[][] {block((byte) 7), block((byte) 7), block((byte) 7)});
      key.updateElement(PIVKeyObjectSYM.ELEMENT_KEY, repeated, (short) 0, (short) 24);
      assertTrue(key.isInitialised());
    }
  }

  /**
   * Key rotation reuses the two key containers built when the key object was defined: JC 3.0.5 API
   * JCSystem.isObjectDeletionSupported() exists because a container allocated per update cannot be
   * assumed reclaimable.
   */
  @Test
  void keyRotationAndClearReuseTheContainersBuiltAtDefinition() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      PIVKeyObjectSYM key =
          PIVKeyObjectSYM.create(
              (byte) 0x9B,
              PIVObject.ACCESS_MODE_ALWAYS,
              PIVObject.ACCESS_MODE_NEVER,
              (byte) 0x9B,
              PIV.ID_ALG_AES_128,
              PIVKeyObject.ROLE_AUTHENTICATE,
              (byte) (PIVKeyObject.ATTR_PERMIT_EXTERNAL | PIVKeyObject.ATTR_IMPORTABLE));
      Object first = field("keyA").get(key);
      Object second = field("keyB").get(key);
      assertNotNull(first);
      assertNotNull(second);
      assertNotSame(first, second);

      Object previous = null;
      for (int rotation = 0; rotation < 4; rotation++) {
        byte[] value = new byte[16];
        java.util.Arrays.fill(value, (byte) (rotation + 1));
        key.updateElement(PIVKeyObjectSYM.ELEMENT_KEY, value, (short) 0, (short) 16);
        Object active = field("key").get(key);
        assertTrue(active == first || active == second, "Rotation must not build a new key");
        assertNotSame(previous, active, "Each rotation publishes the inactive container");
        if (previous != null) {
          assertFalse(
              ((javacard.security.Key) previous).isInitialized(),
              "The replaced key value is cleared");
        }
        assertTrue(key.isInitialised());
        previous = active;
      }

      key.updateElement(PIVKeyObjectSYM.ELEMENT_KEY_CLEAR, new byte[0], (short) 0, (short) 0);
      assertFalse(key.isInitialised());
      assertFalse(((javacard.security.Key) first).isInitialized());
      assertFalse(((javacard.security.Key) second).isInitialized());
      assertSame(first, field("keyA").get(key));
      assertSame(second, field("keyB").get(key));

      byte[] value = new byte[16];
      key.updateElement(PIVKeyObjectSYM.ELEMENT_KEY, value, (short) 0, (short) 16);
      Object active = field("key").get(key);
      assertTrue(active == first || active == second, "Re-import after clear reuses a container");
    }
  }

  private static Field field(String name) throws NoSuchFieldException {
    Field field = PIVKeyObjectSYM.class.getDeclaredField(name);
    field.setAccessible(true);
    return field;
  }

  private static PIVKeyObjectSYM createTdea() {
    return PIVKeyObjectSYM.create(
        (byte) 0x9B,
        PIVObject.ACCESS_MODE_ALWAYS,
        PIVObject.ACCESS_MODE_NEVER,
        (byte) 0x9B,
        PIV.ID_ALG_TDEA_3KEY,
        PIVKeyObject.ROLE_AUTHENTICATE,
        (byte) (PIVKeyObject.ATTR_PERMIT_EXTERNAL | PIVKeyObject.ATTR_IMPORTABLE));
  }

  private static byte[] block(byte seed) {
    byte[] key = new byte[8];
    for (int i = 0; i < key.length; i++) key[i] = (byte) (seed + 2 * i);
    return key;
  }

  private static byte[] concat(byte[][] parts) {
    byte[] out = new byte[24];
    for (int i = 0; i < 3; i++) System.arraycopy(parts[i], 0, out, 8 * i, 8);
    return out;
  }

  private AutoCloseable enterEngineContext() throws Exception {
    Method asCurrent = engine.getClass().getMethod("asCurrent");
    return (AutoCloseable) asCurrent.invoke(engine);
  }
}
