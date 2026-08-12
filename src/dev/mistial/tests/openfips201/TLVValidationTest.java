package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class TLVValidationTest {
  @Test
  void rejectsTruncatedAndNonMinimalLengths() {
    assertInvalid(new byte[] {(byte) 0x53});
    assertInvalid(new byte[] {(byte) 0x53, (byte) 0x82, 0x01});
    assertInvalid(new byte[] {(byte) 0x53, (byte) 0x81, 0x01, 0x00});
    assertInvalid(new byte[] {(byte) 0x53, (byte) 0x80});
  }

  @Test
  void rejectsValueAndConstructedChildOverruns() {
    assertInvalid(new byte[] {(byte) 0x53, 0x02, 0x01});
    assertInvalid(new byte[] {(byte) 0x7C, 0x02, (byte) 0x81, 0x01});
  }

  @Test
  void acceptsWellFormedNestedAndLongFormValues() {
    init(new byte[] {(byte) 0x7C, 0x03, (byte) 0x81, 0x01, 0x00});
    byte[] value = new byte[132];
    value[0] = 0x53;
    value[1] = (byte) 0x81;
    value[2] = (byte) 0x81;
    init(value);
  }

  private static void assertInvalid(byte[] encoded) {
    ISOException exception = assertThrows(ISOException.class, () -> init(encoded));
    assertEquals(ISO7816.SW_WRONG_DATA, exception.getReason());
  }

  private static void init(byte[] encoded) {
    try (MockedStatic<JCSystem> mocked = Mockito.mockStatic(JCSystem.class)) {
      mocked
          .when(() -> JCSystem.makeTransientObjectArray(Mockito.anyShort(), Mockito.anyByte()))
          .thenReturn(new Object[1]);
      mocked
          .when(() -> JCSystem.makeTransientShortArray(Mockito.anyShort(), Mockito.anyByte()))
          .thenReturn(new short[4]);
      TLVReader.getInstance().init(encoded, (short) 0, (short) encoded.length);
    }
  }
}
