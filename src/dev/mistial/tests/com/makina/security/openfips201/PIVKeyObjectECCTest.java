package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import pro.javacard.engine.JavaCardEngine;

class PIVKeyObjectECCTest {

  private final JavaCardEngine engine = JavaCardEngine.create();

  @Test
  void secureMessagingKeyAllocatesCvcStorageAtConstruction() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      PIVKeyObjectECC key = createEcc(PIV.ID_KEY_SECURE_MESSAGING, PIV.ID_ALG_ECC_SM);

      assertNotNull(field(key, "smCvc").get(key));

      byte[] cvc = new byte[] {0x7F, 0x21, 0x00};
      key.updateElement(PIVKeyObjectECC.ELEMENT_SM_CVC, cvc, (short) 0, (short) cvc.length);
      assertEquals((short) cvc.length, field(key, "smCvcLength").getShort(key));
    }
  }

  /**
   * Util.arrayCopyNonAtomic "does not use the transaction facility during the copy operation even
   * if a transaction is in progress" (JC 3.0.5 API). An interrupted CVC replacement must leave the
   * complete previous certificate published; a completed one publishes the complete new one.
   */
  @Test
  void interruptedCvcReplacementKeepsThePublishedCertificate() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      PIVKeyObjectECC key = createEcc(PIV.ID_KEY_SECURE_MESSAGING, PIV.ID_ALG_ECC_SM);
      byte[] previous = {0x7F, 0x21, 0x04, 0x01, 0x02, 0x03, 0x04};
      byte[] replacement = {0x7F, 0x21, 0x04, 0x05, 0x06, 0x07, 0x08};
      key.updateElement(PIVKeyObjectECC.ELEMENT_SM_CVC, previous, (short) 0, (short) 7);

      try (MockedStatic<Util> util = Mockito.mockStatic(Util.class, Mockito.CALLS_REAL_METHODS)) {
        util.when(
                () ->
                    Util.arrayCopyNonAtomic(
                        Mockito.any(byte[].class),
                        Mockito.anyShort(),
                        Mockito.any(byte[].class),
                        Mockito.anyShort(),
                        Mockito.anyShort()))
            .thenAnswer(
                invocation -> {
                  byte[] source = invocation.getArgument(0);
                  short sourceOffset = invocation.getArgument(1);
                  byte[] destination = invocation.getArgument(2);
                  short destinationOffset = invocation.getArgument(3);
                  System.arraycopy(source, sourceOffset, destination, destinationOffset, 5);
                  throw new IllegalStateException("power lost during the copy");
                });
        assertThrows(
            IllegalStateException.class,
            () ->
                key.updateElement(
                    PIVKeyObjectECC.ELEMENT_SM_CVC, replacement, (short) 0, (short) 7));
      }
      assertArrayEquals(previous, publishedCvc(key), "previous CVC stays published");

      key.updateElement(PIVKeyObjectECC.ELEMENT_SM_CVC, replacement, (short) 0, (short) 7);
      assertArrayEquals(replacement, publishedCvc(key), "completed replacement is published");
    }
  }

  private static byte[] publishedCvc(PIVKeyObjectECC key) {
    byte[] out = new byte[key.getSmCvcLength()];
    key.getSmCvc(out, (short) 0);
    return out;
  }

  @Test
  void ordinaryEccKeyDoesNotAllocateCvcStorageAndRejectsCvcUpdate() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      PIVKeyObjectECC key = createEcc((byte) 0x9A, PIV.ID_ALG_ECC_P256);

      assertNull(field(key, "smCvc").get(key));

      ISOException thrown =
          org.junit.jupiter.api.Assertions.assertThrows(
              ISOException.class,
              () ->
                  key.updateElement(
                      PIVKeyObjectECC.ELEMENT_SM_CVC,
                      new byte[] {0x7F, 0x21, 0x00},
                      (short) 0,
                      (short) 3));
      assertEquals(ISO7816.SW_WRONG_DATA, thrown.getReason());
      assertNull(field(key, "smCvc").get(key));
    }
  }

  @Test
  void importedPrivateScalarIsNotOperationalWithoutValidatedPublicPoint() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      PIVKeyObjectECC key = createEcc((byte) 0x9D, PIV.ID_ALG_ECC_P256);
      byte[] scalar = new byte[32];
      scalar[31] = 1;
      key.updateElement((byte) 0x87, scalar, (short) 0, (short) 32);
      key.completesImportedKeyPair((byte) 0x87);

      assertTrue(key.hasPrivateMaterial());
      assertFalse(key.isInitialised(), "An incomplete import must not be operational");
    }
  }

  private static PIVKeyObjectECC createEcc(byte id, byte mechanism) {
    return (PIVKeyObjectECC)
        PIVKeyObject.create(
            id,
            PIVObject.ACCESS_MODE_ALWAYS,
            PIVObject.ACCESS_MODE_ALWAYS,
            (byte) 0x00,
            mechanism,
            PIVKeyObject.ROLE_KEY_ESTABLISH,
            (byte) 0x00,
            new PIVCrypto(),
            new ECCurveRegistry());
  }

  private static Field field(Object target, String name) throws Exception {
    Field field = target.getClass().getDeclaredField(name);
    field.setAccessible(true);
    return field;
  }

  private AutoCloseable enterEngineContext() throws Exception {
    Method asCurrent = engine.getClass().getMethod("asCurrent");
    return (AutoCloseable) asCurrent.invoke(engine);
  }
}
