package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import org.junit.jupiter.api.Test;

class TLVWriterBoundaryTest {
  @Test
  void writesExactlyToBufferBoundary() {
    byte[] output = new byte[5];
    TLVWriter writer = TLVWriter.createForTest();

    writer.init(output, (short) 0, (short) 3, (short) 0x53);
    writer.writeNull((short) 0x81);

    assertEquals(4, writer.finish());
    assertArrayEquals(new byte[] {0x53, 0x02, (byte) 0x81, 0x00, 0x00}, output);
  }

  @Test
  void rejectsOutputOverflowBeforeWriting() {
    byte[] output = new byte[4];
    TLVWriter writer = TLVWriter.createForTest();
    writer.init(output, (short) 0, (short) 2, (short) 0x53);

    ISOException error =
        assertThrows(ISOException.class, () -> writer.write((byte) 0x81, (byte) 0x01));
    assertEquals(ISO7816.SW_FILE_FULL, error.getReason());
    assertArrayEquals(new byte[] {0x53, 0x00, 0x00, 0x00}, output);
  }

  @Test
  void rejectsLogicalLengthOverflowWithSparePhysicalCapacity() {
    byte[] output = new byte[16];
    TLVWriter writer = TLVWriter.createForTest();
    writer.init(output, (short) 0, (short) 2, (short) 0x53);

    ISOException error =
        assertThrows(ISOException.class, () -> writer.write((byte) 0x81, (byte) 0x01));
    assertEquals(ISO7816.SW_FILE_FULL, error.getReason());
    assertArrayEquals(
        new byte[] {0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        output);
  }

  @Test
  void rejectsInvalidInputRange() {
    TLVWriter writer = TLVWriter.createForTest();
    writer.init(new byte[16], (short) 0, (short) 8, (short) 0x53);

    ISOException error =
        assertThrows(
            ISOException.class, () -> writer.write((byte) 0x81, new byte[2], (short) 1, (short) 2));
    assertEquals(ISO7816.SW_WRONG_LENGTH, error.getReason());
  }

  @Test
  void rejectsInvalidDestinationRange() {
    ISOException error =
        assertThrows(
            ISOException.class,
            () -> TLVWriter.createForTest().init(new byte[2], (short) 3, (short) 0, (short) 0x53));
    assertEquals(ISO7816.SW_WRONG_LENGTH, error.getReason());
  }

  @Test
  void writes128ByteContentWithExact81LengthHeader() {
    byte[] output = new byte[131];
    byte[] value = new byte[126];
    TLVWriter writer = TLVWriter.createForTest();

    writer.init(output, (short) 0, (short) 128, (short) 0x53);
    writer.write((byte) 0x81, value, (short) 0, (short) value.length);

    assertEquals(131, writer.finish());
    assertEquals((byte) 0x53, output[0]);
    assertEquals((byte) 0x81, output[1]);
    assertEquals((byte) 0x80, output[2]);
    assertEquals((byte) 0x81, output[3]);
    assertEquals((byte) 0x7E, output[4]);
  }

  @Test
  void writes255ByteContentWithoutUninitialisedGap() {
    byte[] output = new byte[258];
    byte[] value = new byte[252];
    TLVWriter writer = TLVWriter.createForTest();

    writer.init(output, (short) 0, (short) 255, (short) 0x53);
    writer.write((byte) 0x81, value, (short) 0, (short) value.length);

    assertEquals(258, writer.finish());
    assertEquals((byte) 0x53, output[0]);
    assertEquals((byte) 0x81, output[1]);
    assertEquals((byte) 0xFF, output[2]);
    assertEquals((byte) 0x81, output[3]);
    assertEquals((byte) 0x81, output[4]);
    assertEquals((byte) 0xFC, output[5]);
  }
}
