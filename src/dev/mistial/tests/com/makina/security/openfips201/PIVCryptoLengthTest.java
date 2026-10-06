package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.JavaCardEngine;

class PIVCryptoLengthTest {
  private static final byte[] INPUT = new byte[130];
  private static final byte[] OUTPUT = new byte[384];
  private PIVCrypto crypto;

  @BeforeEach
  void createCrypto() throws Exception {
    JavaCardEngine engine = JavaCardEngine.create();
    Method asCurrent = engine.getClass().getMethod("asCurrent");
    asCurrent.setAccessible(true);
    try (AutoCloseable ignored = (AutoCloseable) asCurrent.invoke(engine)) {
      crypto = new PIVCrypto();
    }
  }

  /**
   * The canonical point validator owns the encoding-length check; SP 800-73-5 Part 2 Table 16 C4:
   * "Return '6A 80' if public-key validation fails."
   */
  @Test
  void keyAgreementRejectsWrongPointLengthThroughTheCanonicalValidator() {
    ECPrivateKey key = mock(ECPrivateKey.class);
    when(key.getSize()).thenReturn(KeyBuilder.LENGTH_EC_FP_256);
    ECParams params = mock(ECParams.class);
    when(params.getP()).thenReturn(new byte[32]);
    ECPointValidator validator = new ECPointValidator(new byte[ECPointValidator.WORKSPACE_LENGTH]);
    INPUT[0] = ECPointValidator.POINT_UNCOMPRESSED;

    assertWrongData(() -> keyAgreement(key, (short) 64, validator, params));
    assertWrongData(() -> keyAgreement(key, (short) 66, validator, params));
  }

  @Test
  void keyTransportRequiresExactModulusLength() {
    RSAPrivateKey key = mock(RSAPrivateKey.class);
    when(key.getSize()).thenReturn(KeyBuilder.LENGTH_RSA_1024);

    assertWrongLength(
        () -> crypto.doKeyTransport(key, INPUT, (short) 0, (short) 127, OUTPUT, (short) 0));
    assertWrongLength(
        () -> crypto.doKeyTransport(key, INPUT, (short) 0, (short) 129, OUTPUT, (short) 0));
  }

  private void keyAgreement(
      ECPrivateKey key, short length, ECPointValidator validator, ECParams params) {
    crypto.doKeyAgreement(key, INPUT, (short) 0, length, OUTPUT, (short) 0, validator, params);
  }

  private static void assertWrongData(Runnable operation) {
    ISOException exception = assertThrows(ISOException.class, operation::run);
    assertEquals(ISO7816.SW_WRONG_DATA, exception.getReason());
  }

  private static void assertWrongLength(Runnable operation) {
    ISOException exception = assertThrows(ISOException.class, operation::run);
    assertEquals(ISO7816.SW_WRONG_LENGTH, exception.getReason());
  }
}
