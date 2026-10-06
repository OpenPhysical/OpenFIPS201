package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class ECPointValidatorTest {
  private final ECCurveRegistry curves = new ECCurveRegistry();
  private final ECPointValidator validator =
      new ECPointValidator(new byte[ECPointValidator.WORKSPACE_LENGTH]);

  @Test
  void acceptsP256BasePoint() {
    ECParams params = curves.forMechanism(PIV.ID_ALG_ECC_P256);
    byte[] point = params.getG();
    assertTrue(validator.isValid(point, (short) 0, (short) point.length, params));
  }

  @Test
  void acceptsP384BasePoint() {
    ECParams params = curves.forMechanism(PIV.ID_ALG_ECC_P384);
    byte[] point = params.getG();
    assertTrue(validator.isValid(point, (short) 0, (short) point.length, params));
  }

  @Test
  void rejectsMalformedAndOffCurveP256Points() {
    ECParams params = curves.forMechanism(PIV.ID_ALG_ECC_P256);
    byte[] point = params.getG().clone();
    point[0] = 0x02;
    assertFalse(validator.isValid(point, (short) 0, (short) point.length, params));

    point = params.getG().clone();
    point[point.length - 1] ^= 0x01;
    assertFalse(validator.isValid(point, (short) 0, (short) point.length, params));

    point = new byte[65];
    point[0] = 0x04;
    assertFalse(validator.isValid(point, (short) 0, (short) point.length, params));
  }

  @Test
  void acceptsNegatedBasePointsOnBothCurves() {
    for (byte mechanism : new byte[] {PIV.ID_ALG_ECC_P256, PIV.ID_ALG_ECC_P384}) {
      ECParams params = curves.forMechanism(mechanism);
      int field = params.getP().length;
      byte[] point = params.getG().clone();
      BigInteger p = new BigInteger(1, params.getP());
      BigInteger y = new BigInteger(1, Arrays.copyOfRange(point, 1 + field, point.length));
      System.arraycopy(fixed(p.subtract(y), field), 0, point, 1 + field, field);
      assertTrue(validator.isValid(point, (short) 0, (short) point.length, params), "-G");
    }
  }

  /**
   * The a = p - 3 shortcut and the general a*x multiplication must agree. A synthetic curve over
   * the P-256 field with a = 1 exercises the general path; one with a = p - 3 and x = 0 exercises
   * the shortcut's zero case.
   */
  @Test
  void validatesCurvesWithAndWithoutTheMinusThreeCoefficient() {
    ECParams p256 = curves.forMechanism(PIV.ID_ALG_ECC_P256);
    BigInteger p = new BigInteger(1, p256.getP());
    byte[] g = p256.getG();
    BigInteger x = new BigInteger(1, Arrays.copyOfRange(g, 1, 33));
    BigInteger y = new BigInteger(1, Arrays.copyOfRange(g, 33, 65));

    BigInteger b = y.pow(2).subtract(x.pow(3)).subtract(x).mod(p);
    ECParams generalA = syntheticCurve(p256.getP(), fixed(BigInteger.ONE, 32), fixed(b, 32));
    assertTrue(validator.isValid(g, (short) 0, (short) g.length, generalA), "a = 1 on-curve");
    byte[] off = g.clone();
    off[64] ^= 0x01;
    assertFalse(validator.isValid(off, (short) 0, (short) off.length, generalA), "a = 1 off-curve");

    byte[] zeroX = new byte[65];
    zeroX[0] = ECPointValidator.POINT_UNCOMPRESSED;
    System.arraycopy(fixed(y, 32), 0, zeroX, 33, 32);
    ECParams minusThree =
        syntheticCurve(
            p256.getP(), fixed(p.subtract(BigInteger.valueOf(3)), 32), fixed(y.pow(2).mod(p), 32));
    assertTrue(validator.isValid(zeroX, (short) 0, (short) 65, minusThree), "x = 0 on-curve");
  }

  private static ECParams syntheticCurve(byte[] p, byte[] a, byte[] b) {
    ECParams params = Mockito.mock(ECParams.class);
    Mockito.when(params.getP()).thenReturn(p);
    Mockito.when(params.getA()).thenReturn(a);
    Mockito.when(params.getB()).thenReturn(b);
    return params;
  }

  private static byte[] fixed(BigInteger value, int length) {
    byte[] encoded = value.toByteArray();
    byte[] out = new byte[length];
    int copy = Math.min(encoded.length, length);
    System.arraycopy(encoded, encoded.length - copy, out, length - copy, copy);
    return out;
  }

  @Test
  void rejectsMalformedAndOffCurveP384Points() {
    ECParams params = curves.forMechanism(PIV.ID_ALG_ECC_P384);
    byte[] point = params.getG().clone();
    point[point.length - 1] ^= 0x01;
    assertFalse(validator.isValid(point, (short) 0, (short) point.length, params));

    point = new byte[97];
    point[0] = 0x04;
    assertFalse(validator.isValid(point, (short) 0, (short) point.length, params));
  }
}
