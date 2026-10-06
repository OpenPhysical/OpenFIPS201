package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Random;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * Differential property tests for the applet BER-TLV parsers.
 *
 * <p>Seeded random BER-TLV trees and their mutations are parsed by {@link TLV}, {@link TLVReader}
 * and the personalization structure check, and every result is compared with an independent
 * reference model of the same rules: one to three tag bytes with a minimal first subsequent byte,
 * definite lengths of at most two subsequent bytes encoding 0 to 0x7FFF in their shortest form, and
 * at most eight open non-empty constructed objects. Every rejection must be {@link
 * ISO7816#SW_WRONG_DATA}; no other exception may escape.
 */
class TlvParserPropertyTest {
  private static final long SEED = 0x5F2F_7E61_4F0BL;
  private static final int CASES = 4000;
  private static final int MAX_NESTING = 8;

  @Test
  void headerParsersAgreeWithReferenceModel() {
    Random random = new Random(SEED);
    for (int i = 0; i < CASES; i++) {
      byte[] data = mutate(random, tree(random, 0, 4), random.nextInt(4));
      int limit = data.length;
      int[] header = referenceHeader(data, 0, limit);
      short length = TLV.valueLengthOrInvalid(data, (short) 0, (short) limit);
      short offset = TLV.valueOffsetOrInvalid(data, (short) 0, (short) limit);
      short end = TLV.endOrInvalid(data, (short) 0, (short) limit);
      String label = hex(data);
      if (header == null) {
        assertEquals(TLV.INVALID, length, label);
        assertEquals(TLV.INVALID, offset, label);
        assertEquals(TLV.INVALID, end, label);
        assertWrongData(() -> TLV.readLength(data, (short) 0, (short) limit));
        assertWrongData(() -> TLV.dataOffset(data, (short) 0, (short) limit));
        assertWrongData(() -> TLV.objectEnd(data, (short) 0, (short) limit));
        continue;
      }
      assertEquals(header[1], length, label);
      assertEquals(header[0], offset, label);
      int expectedEnd = header[0] + header[1] <= limit ? header[0] + header[1] : -1;
      assertEquals(expectedEnd, end, label);
      assertEquals(header[1], TLV.readLength(data, (short) 0, (short) limit), label);
      assertEquals(header[0], TLV.dataOffset(data, (short) 0, (short) limit), label);
      if (expectedEnd < 0) {
        assertWrongData(() -> TLV.objectEnd(data, (short) 0, (short) limit));
      } else {
        assertEquals(expectedEnd, TLV.objectEnd(data, (short) 0, (short) limit), label);
      }
    }
  }

  @Test
  void readerValidationAgreesWithReferenceModel() {
    try (MockedStatic<JCSystem> system = mockTransientStorage()) {
      TLVReader reader = freshReader();
      Random random = new Random(SEED + 1);
      int accepted = 0;
      for (int i = 0; i < CASES; i++) {
        byte[] data = mutate(random, sequence(random, 0, 3), random.nextInt(3));
        boolean expected = data.length > 0 && referenceValid(data, 0, data.length, 0);
        boolean actual;
        try {
          reader.init(data, (short) 0, (short) data.length);
          actual = true;
        } catch (ISOException e) {
          assertEquals(ISO7816.SW_WRONG_DATA, e.getReason(), hex(data));
          actual = false;
        }
        assertEquals(expected, actual, hex(data));
        if (actual) accepted++;
      }
      assertTrue(accepted > CASES / 10, "the generator must produce valid inputs too");
    }
  }

  @Test
  void structureCheckAgreesWithReferenceModel() {
    Random random = new Random(SEED + 2);
    for (int i = 0; i < CASES; i++) {
      byte[] value = mutate(random, sequence(random, 0, 2), random.nextInt(3));
      byte[] content = wrap(0x53, value, random.nextInt(3));
      if (random.nextInt(8) == 0) content = mutate(random, content, 1);
      int[] header = referenceHeader(content, 0, content.length);
      boolean expected =
          content.length >= 2
              && (content[0] & 0xFF) == 0x53
              && header != null
              && header[0] + header[1] == content.length
              && referenceFlat(content, header[0], content.length);
      PIVDataObject object = Mockito.mock(PIVDataObject.class);
      object.content = content;
      Mockito.when(object.isInitialised()).thenReturn(true);
      Mockito.when(object.getLength()).thenReturn((short) content.length);
      assertEquals(
          expected,
          PIVDataCommandHandler.isStructurallyValidMandatoryObject(object, (byte) 0x07),
          hex(content));
    }
  }

  @Test
  void readerNestingLimitIsEnforcedWithoutRecursion() {
    try (MockedStatic<JCSystem> system = mockTransientStorage()) {
      TLVReader reader = freshReader();
      byte[] eight = nested(MAX_NESTING);
      reader.init(eight, (short) 0, (short) eight.length);
      byte[] nine = nested(MAX_NESTING + 1);
      assertWrongData(() -> reader.init(nine, (short) 0, (short) nine.length));
      // Deep input is rejected by the depth limit, not by exhausting the stack.
      byte[] deep = nested(2000);
      assertWrongData(() -> reader.init(deep, (short) 0, (short) deep.length));
      // Empty constructed objects do not open a nesting level.
      byte[] emptyInside = wrapNested(MAX_NESTING, new byte[] {0x7C, 0x00});
      reader.init(emptyInside, (short) 0, (short) emptyInside.length);
    }
  }

  @Test
  void tagFieldsAreLimitedToThreeMinimalBytes() {
    assertEquals(3, TLV.valueOffsetOrInvalid(hexBytes("5F2F0100"), (short) 0, (short) 4));
    assertEquals(4, TLV.valueOffsetOrInvalid(hexBytes("5FC1020100"), (short) 0, (short) 5));
    assertEquals(
        TLV.INVALID, TLV.valueOffsetOrInvalid(hexBytes("5F80010100"), (short) 0, (short) 5));
    assertEquals(
        TLV.INVALID, TLV.valueOffsetOrInvalid(hexBytes("5FC1818100"), (short) 0, (short) 5));
    assertEquals(
        TLV.INVALID, TLV.valueLengthOrInvalid(hexBytes("538280000000"), (short) 0, (short) 6));
    assertEquals(TLV.INVALID, TLV.valueLengthOrInvalid(hexBytes("53830000"), (short) 0, (short) 4));
    assertEquals(TLV.INVALID, TLV.valueLengthOrInvalid(hexBytes("538101"), (short) 0, (short) 3));
    assertFalse(TLV.endOrInvalid(hexBytes("530300"), (short) 0, (short) 3) >= 0);
  }

  // ---------------------------------------------------------------------------------------------
  // Reference model
  // ---------------------------------------------------------------------------------------------

  /** Returns {valueOffset, length} for the header at {@code offset}, or null when it is invalid. */
  private static int[] referenceHeader(byte[] data, int offset, int limit) {
    if (offset < 0 || offset >= limit) return null;
    int cursor = offset;
    if ((data[cursor] & 0x1F) == 0x1F) {
      int subsequent = 0;
      while (true) {
        cursor++;
        if (cursor >= limit || subsequent == 2) return null;
        if (subsequent == 0 && (data[cursor] & 0x7F) == 0) return null;
        subsequent++;
        if ((data[cursor] & 0x80) == 0) break;
      }
    }
    cursor++;
    if (cursor >= limit) return null;
    int first = data[cursor] & 0xFF;
    if (first < 0x80) return new int[] {cursor + 1, first};
    int count = first & 0x7F;
    if (count == 0 || count > 2 || cursor + 1 + count > limit) return null;
    int length = 0;
    for (int i = 0; i < count; i++) length = (length << 8) | (data[cursor + 1 + i] & 0xFF);
    if (length > 0x7FFF) return null;
    if (length < (count == 1 ? 0x80 : 0x100)) return null;
    return new int[] {cursor + 1 + count, length};
  }

  private static boolean referenceValid(byte[] data, int start, int end, int depth) {
    int position = start;
    while (position < end) {
      int[] header = referenceHeader(data, position, end);
      if (header == null || header[0] + header[1] > end) return false;
      int valueEnd = header[0] + header[1];
      if ((data[position] & 0x20) != 0 && header[1] != 0) {
        if (depth == MAX_NESTING) return false;
        if (!referenceValid(data, header[0], valueEnd, depth + 1)) return false;
      }
      position = valueEnd;
    }
    return true;
  }

  private static boolean referenceFlat(byte[] data, int start, int end) {
    if (start >= end) return false;
    int position = start;
    while (position < end) {
      int[] header = referenceHeader(data, position, end);
      if (header == null || header[0] + header[1] > end) return false;
      position = header[0] + header[1];
    }
    return true;
  }

  // ---------------------------------------------------------------------------------------------
  // Generators
  // ---------------------------------------------------------------------------------------------

  private static final int[][] PRIMITIVE_TAGS = {
    {0x80}, {0x81}, {0x53}, {0x5F, 0x2F}, {0x9F, 0x33}, {0x5F, 0xC1, 0x02}, {0x04}
  };
  private static final int[][] CONSTRUCTED_TAGS = {{0x7C}, {0x30}, {0xA0}, {0x7F, 0x61}};

  private static byte[] tree(Random random, int depth, int maxDepth) {
    boolean constructed = depth < maxDepth && random.nextInt(3) == 0;
    int[] tag =
        constructed
            ? CONSTRUCTED_TAGS[random.nextInt(CONSTRUCTED_TAGS.length)]
            : PRIMITIVE_TAGS[random.nextInt(PRIMITIVE_TAGS.length)];
    byte[] value;
    if (constructed) {
      value = sequence(random, depth + 1, maxDepth);
    } else {
      int size = random.nextInt(8) == 0 ? 120 + random.nextInt(200) : random.nextInt(6);
      value = new byte[size];
      random.nextBytes(value);
    }
    return encode(tag, value, random.nextInt(4));
  }

  private static byte[] sequence(Random random, int depth, int maxDepth) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    int count = 1 + random.nextInt(3);
    for (int i = 0; i < count; i++) {
      byte[] element = tree(random, depth, maxDepth);
      out.write(element, 0, element.length);
    }
    return out.toByteArray();
  }

  /** Encodes a TLV; {@code lengthForm} 0 is shortest, 1 forces '81', 2 forces '82'. */
  private static byte[] encode(int[] tag, byte[] value, int lengthForm) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (int b : tag) out.write(b);
    int length = value.length;
    if (lengthForm == 2 || length > 0xFF) {
      out.write(0x82);
      out.write(length >> 8);
      out.write(length);
    } else if (lengthForm == 1 || length > 0x7F) {
      out.write(0x81);
      out.write(length);
    } else {
      out.write(length);
    }
    out.write(value, 0, value.length);
    return out.toByteArray();
  }

  private static byte[] wrap(int tag, byte[] value, int lengthForm) {
    return encode(new int[] {tag}, value, lengthForm);
  }

  private static byte[] mutate(Random random, byte[] input, int mutations) {
    byte[] data = input;
    for (int i = 0; i < mutations && data.length > 0; i++) {
      int position = random.nextInt(data.length);
      switch (random.nextInt(5)) {
        case 0:
          data = data.clone();
          data[position] ^= (byte) (1 << random.nextInt(8));
          break;
        case 1:
          data = Arrays.copyOf(data, position);
          break;
        case 2:
          data = Arrays.copyOf(data, data.length + 1 + random.nextInt(3));
          break;
        case 3:
          data = data.clone();
          data[position] = (byte) (0x80 + random.nextInt(4));
          break;
        default:
          data = data.clone();
          data[position] = (byte) 0x1F;
          break;
      }
    }
    return data;
  }

  private static byte[] nested(int levels) {
    return wrapNested(levels - 1, new byte[] {0x7C, 0x02, (byte) 0x80, 0x00});
  }

  private static byte[] wrapNested(int levels, byte[] inner) {
    byte[] data = inner;
    for (int i = 0; i < levels; i++) data = encode(new int[] {0x7C}, data, 0);
    return data;
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------------------------

  private static TLVReader freshReader() {
    TLVReader.terminate();
    return TLVReader.getInstance();
  }

  private static MockedStatic<JCSystem> mockTransientStorage() {
    MockedStatic<JCSystem> system = Mockito.mockStatic(JCSystem.class);
    system
        .when(() -> JCSystem.makeTransientObjectArray(Mockito.anyShort(), Mockito.anyByte()))
        .thenAnswer(call -> new Object[(short) call.getArgument(0)]);
    system
        .when(() -> JCSystem.makeTransientShortArray(Mockito.anyShort(), Mockito.anyByte()))
        .thenAnswer(call -> new short[(short) call.getArgument(0)]);
    return system;
  }

  private static void assertWrongData(Runnable call) {
    try {
      call.run();
    } catch (ISOException e) {
      assertEquals(ISO7816.SW_WRONG_DATA, e.getReason());
      return;
    }
    fail("expected 6A80");
  }

  private static byte[] hexBytes(String value) {
    byte[] result = new byte[value.length() / 2];
    for (int i = 0; i < result.length; i++) {
      result[i] = (byte) Integer.parseInt(value.substring(2 * i, 2 * i + 2), 16);
    }
    return result;
  }

  private static String hex(byte[] data) {
    StringBuilder builder = new StringBuilder();
    for (byte b : data) builder.append(String.format("%02X", b));
    return builder.toString();
  }
}
