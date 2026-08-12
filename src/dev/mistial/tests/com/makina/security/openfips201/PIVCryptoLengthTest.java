package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import org.junit.jupiter.api.Test;

class PIVCryptoLengthTest {
  private static final byte[] INPUT = new byte[130];
  private static final byte[] OUTPUT = new byte[384];

  @Test
  void keyAgreementRequiresExactEncodedPointLength() {
    ECPrivateKey key = mock(ECPrivateKey.class);
    when(key.getSize()).thenReturn(KeyBuilder.LENGTH_EC_FP_256);

    assertWrongLength(() -> keyAgreement(key, (short) 64));
    assertWrongLength(() -> keyAgreement(key, (short) 66));
  }

  @Test
  void keyTransportRequiresExactModulusLength() {
    RSAPrivateKey key = mock(RSAPrivateKey.class);
    when(key.getSize()).thenReturn(KeyBuilder.LENGTH_RSA_1024);

    assertWrongLength(
        () -> PIVCrypto.doKeyTransport(key, INPUT, (short) 0, (short) 127, OUTPUT, (short) 0));
    assertWrongLength(
        () -> PIVCrypto.doKeyTransport(key, INPUT, (short) 0, (short) 129, OUTPUT, (short) 0));
  }

  private static void keyAgreement(ECPrivateKey key, short length) {
    PIVCrypto.doKeyAgreement(
        key,
        INPUT,
        (short) 0,
        length,
        OUTPUT,
        (short) 0,
        mock(ECPointValidator.class),
        mock(ECParams.class));
  }

  private static void assertWrongLength(Runnable operation) {
    ISOException exception = assertThrows(ISOException.class, operation::run);
    assertEquals(ISO7816.SW_WRONG_LENGTH, exception.getReason());
  }
}
