package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class ECPointValidatorTest {
  private final ECPointValidator validator =
      new ECPointValidator(new byte[ECPointValidator.WORKSPACE_LENGTH]);

  @Test
  void acceptsP256BasePoint() {
    byte[] point = ECParamsP256.getInstance().getG();
    assertTrue(
        validator.isValid(
            point, (short) 0, (short) point.length, ECParamsP256.getInstance()));
  }

  @Test
  void acceptsP384BasePoint() {
    byte[] point = ECParamsP384.getInstance().getG();
    assertTrue(
        validator.isValid(
            point, (short) 0, (short) point.length, ECParamsP384.getInstance()));
  }

  @Test
  void rejectsMalformedAndOffCurveP256Points() {
    ECParams params = ECParamsP256.getInstance();
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
    ECParams params = ECParamsP384.getInstance();
    byte[] point = params.getG().clone();
    point[point.length - 1] ^= 0x01;
    assertFalse(validator.isValid(point, (short) 0, (short) point.length, params));

    point = new byte[97];
    point[0] = 0x04;
    assertFalse(validator.isValid(point, (short) 0, (short) point.length, params));
  }
}
