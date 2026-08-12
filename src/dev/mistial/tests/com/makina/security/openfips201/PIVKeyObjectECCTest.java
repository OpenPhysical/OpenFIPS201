package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import org.junit.jupiter.api.Test;
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
