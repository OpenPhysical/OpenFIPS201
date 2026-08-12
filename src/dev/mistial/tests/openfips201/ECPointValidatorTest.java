package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

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
