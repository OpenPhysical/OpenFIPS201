package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import java.lang.reflect.Method;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.JavaCardEngine;

/**
 * Key generation clears a partially generated pair and rethrows the original exception. JCRE 3.0.5
 * Section 3.3 returns the status word of an ISOException, but ISO7816.SW_UNKNOWN for "any other
 * exception", so the rethrown object must remain an ISOException.
 */
class PIVKeyObjectGenerateTest {
  private final JavaCardEngine engine = JavaCardEngine.create();

  @Test
  void eccGenerateRethrowsIsoExceptionWithItsStatusWord() throws Exception {
    // The FIPS profile runs the pair-wise consistency test in the output buffer first.
    assumeFalse(
        Boolean.getBoolean("fips.mode"), "Output-buffer failure precedes the PCT only here");
    try (AutoCloseable ignored = enterEngineContext()) {
      PIVKeyObjectECC key =
          (PIVKeyObjectECC)
              PIVKeyObject.create(
                  (byte) 0x9A,
                  PIVObject.ACCESS_MODE_PIN,
                  (byte) (PIVObject.ACCESS_MODE_VCI | PIVObject.ACCESS_MODE_PIN),
                  (byte) 0x9B,
                  PIV.ID_ALG_ECC_P256,
                  PIVKeyObject.ROLE_SIGN,
                  PIVKeyObject.ATTR_NONE,
                  new PIVCrypto(),
                  new ECCurveRegistry());
      TLVWriter writer = new TLVWriter();

      // One byte cannot hold the 7F49 response header, so the response writer throws 6700.
      ISOException thrown =
          assertThrows(ISOException.class, () -> key.generate(writer, new byte[1], (short) 0));
      assertEquals(ISO7816.SW_WRONG_LENGTH, thrown.getReason());
      assertFalse(key.isInitialised(), "A failed generation must leave no key pair");
    }
  }

  @Test
  void rsaGenerateRethrowsIsoExceptionWithItsStatusWord() throws Exception {
    assumeFalse(
        Boolean.getBoolean("fips.mode"), "Output-buffer failure precedes the PCT only here");
    try (AutoCloseable ignored = enterEngineContext()) {
      PIVKeyObjectRSA key =
          PIVKeyObjectRSA.create(
              (byte) 0x9A,
              PIVObject.ACCESS_MODE_PIN,
              (byte) (PIVObject.ACCESS_MODE_VCI | PIVObject.ACCESS_MODE_PIN),
              (byte) 0x9B,
              PIV.ID_ALG_RSA_2048,
              PIVKeyObject.ROLE_SIGN,
              PIVKeyObject.ATTR_NONE,
              new PIVCrypto());
      TLVWriter writer = new TLVWriter();

      // Three bytes hold the staged public exponent but not the 7F49 response header.
      ISOException thrown =
          assertThrows(ISOException.class, () -> key.generate(writer, new byte[3], (short) 0));
      assertEquals(ISO7816.SW_WRONG_LENGTH, thrown.getReason());
      assertFalse(key.isInitialised(), "A failed generation must leave no key pair");
    }
  }

  private AutoCloseable enterEngineContext() throws Exception {
    Method asCurrent = engine.getClass().getMethod("asCurrent");
    return (AutoCloseable) asCurrent.invoke(engine);
  }
}
