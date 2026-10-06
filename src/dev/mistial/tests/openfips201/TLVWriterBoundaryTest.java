package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class TLVWriterBoundaryTest {
  private static final short EMPTY_CONTENT_LENGTH = 0;
  private static final short SINGLE_BYTE_TAG_HEADER_BYTES = 2;
  private static final short PUBLIC_KEY_HEADER_BYTES = 3;
  private static final short NONZERO_PARENT_OFFSET = 6;
  private static final byte UNTOUCHED_SENTINEL = (byte) 0xA5;
  // Independent wire answer: two-byte public-key template tag, zero-length value.
  private static final byte[] EMPTY_PUBLIC_KEY_TEMPLATE = {0x7F, 0x49, 0};

  @Test
  void repeatedEmptyParentsRespectOffsetsAndHeaderCapacity() {
    TLVWriter writer = writer();
    byte[] first = new byte[NONZERO_PARENT_OFFSET + SINGLE_BYTE_TAG_HEADER_BYTES];
    writer.init(first, NONZERO_PARENT_OFFSET, EMPTY_CONTENT_LENGTH, PIV.CONST_TAG_DATA);
    assertEquals(SINGLE_BYTE_TAG_HEADER_BYTES, writer.finish());
    byte[] second = new byte[PUBLIC_KEY_HEADER_BYTES];
    writer.init(second, (short) 0, EMPTY_CONTENT_LENGTH, PIVKeyObjectPKI.CONST_TAG_RESPONSE);
    assertEquals(PUBLIC_KEY_HEADER_BYTES, writer.finish());
    assertArrayEquals(EMPTY_PUBLIC_KEY_TEMPLATE, second);

    byte[] shortBuffer = {UNTOUCHED_SENTINEL, UNTOUCHED_SENTINEL};
    ISOException error =
        assertThrows(
            ISOException.class,
            () ->
                writer.init(shortBuffer, (short) 0, (short) 0, PIVKeyObjectPKI.CONST_TAG_RESPONSE));
    assertEquals(ISO7816.SW_WRONG_LENGTH, error.getReason());
    assertArrayEquals(new byte[] {UNTOUCHED_SENTINEL, UNTOUCHED_SENTINEL}, shortBuffer);
  }

  @Test
  void writesExactlyToBufferBoundary() {
    byte[] output = new byte[5];
    TLVWriter writer = writer();

    writer.init(output, (short) 0, (short) 3, PIV.CONST_TAG_DATA);
    writer.write(PIV.CONST_TAG_AUTH_CHALLENGE, new byte[0], (short) 0, (short) 0);

    assertEquals(4, writer.finish());
    assertArrayEquals(new byte[] {0x53, 0x02, (byte) 0x81, 0x00, 0x00}, output);
  }

  @Test
  void rejectsOutputOverflowBeforeWriting() {
    byte[] output = new byte[4];
    TLVWriter writer = writer();
    writer.init(output, (short) 0, (short) 2, PIV.CONST_TAG_DATA);

    ISOException error =
        assertThrows(
            ISOException.class, () -> writer.write(PIV.CONST_TAG_AUTH_CHALLENGE, (byte) 0x01));
    assertEquals(ISO7816.SW_FILE_FULL, error.getReason());
    assertArrayEquals(new byte[] {0x53, 0x00, 0x00, 0x00}, output);
  }

  @Test
  void rejectsLogicalLengthOverflowWithSparePhysicalCapacity() {
    byte[] output = new byte[16];
    TLVWriter writer = writer();
    writer.init(output, (short) 0, (short) 2, PIV.CONST_TAG_DATA);

    ISOException error =
        assertThrows(
            ISOException.class, () -> writer.write(PIV.CONST_TAG_AUTH_CHALLENGE, (byte) 0x01));
    assertEquals(ISO7816.SW_FILE_FULL, error.getReason());
    assertArrayEquals(
        new byte[] {
          0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        output);
  }

  @Test
  void rejectsInvalidInputRange() {
    TLVWriter writer = writer();
    writer.init(new byte[16], (short) 0, (short) 8, PIV.CONST_TAG_DATA);

    ISOException error =
        assertThrows(
            ISOException.class,
            () -> writer.write(PIV.CONST_TAG_AUTH_CHALLENGE, new byte[2], (short) 1, (short) 2));
    assertEquals(ISO7816.SW_WRONG_LENGTH, error.getReason());
  }

  @Test
  void rejectsInvalidDestinationRange() {
    ISOException error =
        assertThrows(
            ISOException.class,
            () -> writer().init(new byte[2], (short) 3, (short) 0, PIV.CONST_TAG_DATA));
    assertEquals(ISO7816.SW_WRONG_LENGTH, error.getReason());
  }

  @Test
  void writes128ByteContentWithExact81LengthHeader() {
    byte[] output = new byte[131];
    byte[] value = new byte[126];
    TLVWriter writer = writer();

    writer.init(output, (short) 0, (short) 128, PIV.CONST_TAG_DATA);
    writer.write(PIV.CONST_TAG_AUTH_CHALLENGE, value, (short) 0, (short) value.length);

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
    TLVWriter writer = writer();

    writer.init(output, (short) 0, (short) 255, PIV.CONST_TAG_DATA);
    writer.write(PIV.CONST_TAG_AUTH_CHALLENGE, value, (short) 0, (short) value.length);

    assertEquals(258, writer.finish());
    assertEquals((byte) 0x53, output[0]);
    assertEquals((byte) 0x81, output[1]);
    assertEquals((byte) 0xFF, output[2]);
    assertEquals((byte) 0x81, output[3]);
    assertEquals((byte) 0x81, output[4]);
    assertEquals((byte) 0xFC, output[5]);
  }

  /**
   * ISO/IEC 7816-4 Section 6.3 recommends "the shortest possible coding of the length field". A
   * {@code maxLength} that reserves a longer form than the actual content needs must still produce
   * the shortest form, with the content moved to follow it and the vacated octets zeroised.
   */
  @Test
  void oversizedMaxLengthProducesShortestLengthEncoding() {
    int[][] cases = {
      // {maxLength, contentLength}
      {0x7FFF, 0x00},
      {0x0100, 0x7F},
      {0x0100, 0x80},
      {0x0100, 0xFF},
      {0x0100, 0x0100},
      {0x00FF, 0x7F},
      {0x00FF, 0x80},
      {0x0080, 0x7F},
      {0x7FFF, 0x0100}
    };
    for (int[] testCase : cases) {
      int maxLength = testCase[0];
      int contentLength = testCase[1];
      byte[] content = new byte[contentLength];
      for (int i = 0; i < content.length; i++) content[i] = (byte) (i + 1);
      byte[] header = minimalHeader(contentLength);
      byte[] expected = new byte[NONZERO_PARENT_OFFSET + header.length + contentLength];
      System.arraycopy(header, 0, expected, NONZERO_PARENT_OFFSET, header.length);
      System.arraycopy(content, 0, expected, NONZERO_PARENT_OFFSET + header.length, content.length);

      byte[] output = new byte[NONZERO_PARENT_OFFSET + 4 + contentLength];
      TLVWriter writer = writer();
      writer.init(output, NONZERO_PARENT_OFFSET, (short) maxLength, PIV.CONST_TAG_DATA);
      System.arraycopy(content, 0, output, writer.getOffset(), content.length);
      writer.move((short) contentLength);

      String context = "maxLength " + maxLength + ", content " + contentLength;
      assertEquals(
          (short) (header.length + contentLength), writer.finish(), context + ": returned length");
      byte[] written = java.util.Arrays.copyOf(output, expected.length);
      assertArrayEquals(expected, written, context + ": encoding");
      for (int i = expected.length; i < output.length; i++) {
        assertEquals(0, output[i], context + ": vacated octet " + i + " zeroised");
      }
    }
  }

  /** Independent wire answer: tag 53 and the shortest BER length for {@code length}. */
  private static byte[] minimalHeader(int length) {
    if (length < 0x80) return new byte[] {0x53, (byte) length};
    if (length <= 0xFF) return new byte[] {0x53, (byte) 0x81, (byte) length};
    return new byte[] {0x53, (byte) 0x82, (byte) (length >> 8), (byte) length};
  }

  private static TLVWriter writer() {
    try (MockedStatic<JCSystem> mocked = Mockito.mockStatic(JCSystem.class)) {
      mocked
          .when(() -> JCSystem.makeTransientObjectArray(Mockito.anyShort(), Mockito.anyByte()))
          .thenReturn(new Object[1]);
      mocked
          .when(() -> JCSystem.makeTransientShortArray(Mockito.anyShort(), Mockito.anyByte()))
          .thenReturn(new short[6]);
      TLVWriter writer = TLVWriter.getInstance();
      writer.reset();
      return writer;
    }
  }
}
