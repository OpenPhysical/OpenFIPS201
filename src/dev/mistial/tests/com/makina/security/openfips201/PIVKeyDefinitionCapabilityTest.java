package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import pro.javacard.engine.JavaCardEngine;

/**
 * Key definitions are checked against the platform engines and key lengths when they are created,
 * so an unusable definition is reported as an unsupported mechanism ('6A 81') instead of failing
 * later.
 */
class PIVKeyDefinitionCapabilityTest {
  private JavaCardEngine engine;
  private AutoCloseable engineContext;
  private PIVCrypto crypto;

  @BeforeEach
  void enterCardContext() throws Exception {
    engine = JavaCardEngine.create();
    Method asCurrent = engine.getClass().getMethod("asCurrent");
    asCurrent.setAccessible(true);
    engineContext = (AutoCloseable) asCurrent.invoke(engine);
    crypto = new PIVCrypto();
  }

  @AfterEach
  void leaveCardContext() throws Exception {
    engineContext.close();
  }

  @Test
  void signingKeyOnCurveWithoutItsEcdsaEngineIsUnsupported() throws Exception {
    PIVSecurityProvider provider = new PIVSecurityProvider(crypto, new ECCurveRegistry());
    Field ecdsaP384 = PIVCrypto.class.getDeclaredField("cspECCSHA384");
    ecdsaP384.setAccessible(true);
    ecdsaP384.set(crypto, null);

    assertFalse(crypto.supportsKeyRole(PIV.ID_ALG_ECC_P384, PIVKeyObject.ROLE_SIGN));
    assertTrue(crypto.supportsKeyRole(PIV.ID_ALG_ECC_P384, PIVKeyObject.ROLE_KEY_ESTABLISH));
    assertTrue(crypto.supportsKeyRole(PIV.ID_ALG_ECC_P256, PIVKeyObject.ROLE_SIGN));

    ISOException thrown =
        assertThrows(
            ISOException.class,
            () ->
                provider.createKey(
                    (byte) 0x9E,
                    PIVObject.ACCESS_MODE_ALWAYS,
                    PIVObject.ACCESS_MODE_ALWAYS,
                    (byte) 0x9B,
                    PIV.ID_ALG_ECC_P384,
                    PIVKeyObject.ROLE_SIGN,
                    PIVKeyObject.ATTR_NONE));
    assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, thrown.getReason());
    assertFalse(provider.keyExists((byte) 0x9E), "The rejected definition must not be stored");
  }

  /**
   * JC 3.0.5 API KeyBuilder.buildKey throws CryptoException.NO_SUCH_ALGORITHM "if the requested
   * algorithm associated with the specified type, size of key and key encryption interface is not
   * supported".
   */
  @Test
  void unsupportedKeyLengthIsReportedWhenTheKeyIsDefined() {
    PIVSecurityProvider provider = new PIVSecurityProvider(crypto, new ECCurveRegistry());

    try (MockedStatic<KeyBuilder> keyBuilder =
        Mockito.mockStatic(KeyBuilder.class, Mockito.CALLS_REAL_METHODS)) {
      keyBuilder
          .when(
              () ->
                  KeyBuilder.buildKey(
                      Mockito.eq(KeyBuilder.TYPE_AES),
                      Mockito.eq(KeyBuilder.LENGTH_AES_256),
                      Mockito.anyBoolean()))
          .thenThrow(new CryptoException(CryptoException.NO_SUCH_ALGORITHM));

      ISOException thrown =
          assertThrows(
              ISOException.class,
              () ->
                  provider.createKey(
                      (byte) 0x9B,
                      PIVObject.ACCESS_MODE_ALWAYS,
                      PIVObject.ACCESS_MODE_NEVER,
                      (byte) 0x9B,
                      PIV.ID_ALG_AES_256,
                      PIVKeyObject.ROLE_AUTHENTICATE,
                      (byte) (PIVKeyObject.ATTR_PERMIT_EXTERNAL | PIVKeyObject.ATTR_IMPORTABLE)));
      assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, thrown.getReason());
    }
    assertFalse(provider.keyExists((byte) 0x9B), "The rejected definition must not be stored");
  }
}
