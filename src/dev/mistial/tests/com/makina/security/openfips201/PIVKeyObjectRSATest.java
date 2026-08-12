package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Method;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.JavaCardEngine;

class PIVKeyObjectRSATest {
  private final JavaCardEngine engine = JavaCardEngine.create();

  @Test
  void importedPublicExponentMustBe65537() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      PIVKeyObjectRSA key =
          PIVKeyObjectRSA.create(
              (byte) 0x9A,
              PIVObject.ACCESS_MODE_PIN,
              (byte) (PIVObject.ACCESS_MODE_VCI | PIVObject.ACCESS_MODE_PIN),
              (byte) 0x9B,
              PIV.ID_ALG_RSA_2048,
              PIVKeyObject.ROLE_SIGN,
              PIVKeyObject.ATTR_IMPORTABLE);

      key.setPublicExponent(new byte[] {0x01, 0x00, 0x01}, (short) 0, (short) 3);

      ISOException wrongValue =
          assertThrows(
              ISOException.class,
              () -> key.setPublicExponent(new byte[] {0x03}, (short) 0, (short) 1));
      assertEquals(ISO7816.SW_WRONG_DATA, wrongValue.getReason());

      ISOException wrongLength =
          assertThrows(
              ISOException.class,
              () -> key.setPublicExponent(new byte[] {0x00, 0x01, 0x00, 0x01}, (short) 0, (short) 4));
      assertEquals(ISO7816.SW_WRONG_DATA, wrongLength.getReason());
    }
  }

  private AutoCloseable enterEngineContext() throws Exception {
    Method asCurrent = engine.getClass().getMethod("asCurrent");
    return (AutoCloseable) asCurrent.invoke(engine);
  }
}
