package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class TLVValidationTest {
  @Test
  void rejectsTruncatedAndIndefiniteLengths() {
    assertInvalid(new byte[] {(byte) 0x53});
    assertInvalid(new byte[] {(byte) 0x53, (byte) 0x82, 0x01});
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
    byte[] twoByte = new byte[260];
    twoByte[0] = 0x53;
    twoByte[1] = (byte) 0x82;
    twoByte[2] = 0x01;
    twoByte[3] = 0x00;
    init(twoByte);
  }

  /**
   * ISO/IEC 7816-4 Section 6.3 "recommends to use the shortest possible coding of the length
   * field"; the applet requires it, so a long form that a shorter form could encode is rejected.
   */
  @Test
  void rejectsNonMinimalLengthEncodings() {
    assertInvalid(new byte[] {(byte) 0x53, (byte) 0x81, 0x01, 0x00});
    assertInvalid(new byte[] {(byte) 0x53, (byte) 0x82, 0x00, 0x01, 0x00});
    byte[] value = new byte[132];
    value[0] = 0x53;
    value[1] = (byte) 0x82;
    value[2] = 0x00;
    value[3] = (byte) 0x80;
    assertInvalid(value);
    assertInvalid(new byte[] {(byte) 0x7C, 0x04, (byte) 0x81, (byte) 0x81, 0x01, 0x00});
  }

  @Test
  void readsTypedPrimitiveValues() {
    TLVReader reader = reader(new byte[] {(byte) 0x80, 0x01, 0x01});
    assertTrue(reader.toBoolean());
    assertEquals(1, reader.toShort());

    reader = reader(new byte[] {(byte) 0x80, 0x02, 0x12, 0x34});
    assertEquals(0x1234, reader.toShort());
    byte[] copy = new byte[2];
    reader.toBytes(copy, (short) 0);
    assertArrayEquals(new byte[] {0x12, 0x34}, copy);

    TLVReader invalid = reader(new byte[] {(byte) 0x80, 0x02, 0x00, 0x01});
    ISOException exception = assertThrows(ISOException.class, invalid::toBoolean);
    assertEquals(ISO7816.SW_DATA_INVALID, exception.getReason());
  }

  @Test
  void findsTwoByteTagsAndTracksEndOfInput() {
    TLVReader reader = reader(new byte[] {(byte) 0x9F, (byte) 0x33, 0x01, 0x7A, (byte) 0x80, 0x00});
    assertTrue(reader.find((short) 0x9F33));
    assertEquals((short) 0x9F33, reader.getTagShort());
    assertTrue(reader.matchData((byte) 0x7A));
    assertTrue(reader.moveNext());
    assertTrue(reader.match((byte) 0x80));
    assertTrue(reader.isNull());
    assertFalse(reader.moveNext());
  }

  @Test
  void supportsNavigationAndReaderLifecycle() {
    TLVReader reader =
        reader(
            new byte[] {
              (byte) 0x80,
              0x02,
              0x12,
              0x34,
              (byte) 0x81,
              0x01,
              0x01,
              (byte) 0x9F,
              0x33,
              0x02,
              0x56,
              0x78
            });
    assertTrue(reader.isInitialized());
    assertFalse(reader.isEOF());
    assertTrue(reader.matchData((short) 0x1234));
    assertTrue(reader.findNext((byte) 0x81));
    assertTrue(reader.toBoolean());
    reader.resetPosition();
    assertTrue(reader.findNext((short) 0x9F33));
    assertTrue(reader.matchData((short) 0x5678, (short) 0));
    assertFalse(reader.findNext((byte) 0x7F));
    assertTrue(reader.isEOF());
    reader.clear();
    assertFalse(reader.isInitialized());
    ISOException exception = assertThrows(ISOException.class, reader::resetPosition);
    assertEquals(ISO7816.SW_DATA_INVALID, exception.getReason());
  }

  private static void assertInvalid(byte[] encoded) {
    ISOException exception = assertThrows(ISOException.class, () -> init(encoded));
    assertEquals(ISO7816.SW_WRONG_DATA, exception.getReason());
  }

  private static void init(byte[] encoded) {
    reader(encoded);
  }

  private static TLVReader reader(byte[] encoded) {
    try (MockedStatic<JCSystem> mocked = Mockito.mockStatic(JCSystem.class)) {
      mocked
          .when(() -> JCSystem.makeTransientObjectArray(Mockito.anyShort(), Mockito.anyByte()))
          .thenReturn(new Object[1]);
      mocked
          .when(() -> JCSystem.makeTransientShortArray(Mockito.anyShort(), Mockito.anyByte()))
          .thenAnswer(call -> new short[(short) call.getArgument(0)]);
      TLVReader reader = TLVReader.getInstance();
      reader.init(encoded, (short) 0, (short) encoded.length);
      return reader;
    }
  }
}
