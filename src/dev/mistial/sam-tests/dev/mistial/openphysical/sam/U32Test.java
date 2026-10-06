package dev.mistial.openphysical.sam;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import javacard.framework.ISOException;
import org.junit.jupiter.api.Test;

/** White-box tests of unsigned arithmetic, decimal conversion and DER INTEGER parsing. */
class U32Test {

  static byte[] u32(long value) {
    return new byte[] {
      (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value
    };
  }

  @Test
  void compareIsUnsignedWithTheHighBitSet() {
    assertEquals(
        1, U32.compare(u32(0x80000000L), (short) 0, u32(0x7FFFFFFFL), (short) 0, (short) 4));
    assertEquals(
        -1, U32.compare(u32(0x7FFFFFFFL), (short) 0, u32(0xFFFFFFFFL), (short) 0, (short) 4));
    assertEquals(
        0, U32.compare(u32(0xFFFFFFFFL), (short) 0, u32(0xFFFFFFFFL), (short) 0, (short) 4));
    byte[] high = {(byte) 0x80, 0, 0, 0, 0, 0, 0, 0};
    byte[] low = {
      0x7F,
      (byte) 0xFF,
      (byte) 0xFF,
      (byte) 0xFF,
      (byte) 0xFF,
      (byte) 0xFF,
      (byte) 0xFF,
      (byte) 0xFF
    };
    assertEquals(1, U32.compare(high, (short) 0, low, (short) 0, (short) 8), "u64");
    byte[] a = {0, 0, 0, 0, 0, 0, 0, (byte) 0x80};
    byte[] b = {0, 0, 0, 0, 0, 0, 0, 0x7F};
    assertEquals(1, U32.compare(a, (short) 0, b, (short) 0, (short) 8), "u64 last octet");
  }

  @Test
  void addAndIncrementReportOverflow() {
    byte[] out = new byte[4];
    assertFalse(U32.add(u32(0x7FFFFFFFL), (short) 0, u32(1), (short) 0, out, (short) 0, (short) 4));
    assertArrayEquals(u32(0x80000000L), out);
    assertTrue(U32.add(u32(0xFFFFFFFFL), (short) 0, u32(1), (short) 0, out, (short) 0, (short) 4));
    assertArrayEquals(u32(0), out);
    assertFalse(
        U32.add(
            u32(0x80FF00FFL), (short) 0, u32(0x0F00FF01L), (short) 0, out, (short) 0, (short) 4));
    assertArrayEquals(u32(0x90000000L), out);
    assertFalse(U32.increment(u32(0x00FFFFFFL), (short) 0, out, (short) 0, (short) 4));
    assertArrayEquals(u32(0x01000000L), out);
    assertTrue(U32.increment(u32(0xFFFFFFFFL), (short) 0, out, (short) 0, (short) 4));
    assertTrue(U32.isZero(out, (short) 0, (short) 4));
  }

  @Test
  void decimalConversionAtTheBoundaries() {
    long[] values = {
      0, 1, 9, 10, 99_999, 100_000, 99_999_999, 100_000_000, 0xFFFFFFFFL, 0x80000000L
    };
    for (int k = 0; k <= 8; k++) {
      long m = BigInteger.TEN.pow(k).longValue();
      for (long value : values) {
        byte[] work = new byte[4];
        byte[] digits = new byte[8];
        boolean fits =
            U32.toDecimal(u32(value), (short) 0, work, (short) 0, digits, (short) 0, (short) k);
        assertEquals(value < m, fits, "value " + value + " k " + k);
        if (fits) {
          long expected = value;
          for (int i = 0; i < k; i++) {
            assertEquals(expected % 10, digits[i], "digit " + i);
            expected /= 10;
          }
          byte[] back = new byte[4];
          U32.fromDecimal(digits, (short) 0, (short) k, back, (short) 0);
          assertArrayEquals(u32(value), back);
        }
      }
    }
  }

  @Test
  void derIntegerParsingIsStrict() {
    assertEquals(0L, parse("020100"));
    assertEquals(0x7FL, parse("02017F"));
    assertEquals(0x80L, parse("02020080"));
    assertEquals(0x05F5E100L, parse("020405F5E100"));
    assertEquals(0xFFFFFFFFL, parse("020500FFFFFFFF"));
    assertEquals(0x80000000L, parse("02050080000000"));
    rejects("0200", "empty");
    rejects("02020001", "non-minimal positive");
    rejects("0202FF80", "non-minimal negative");
    rejects("020180", "negative");
    rejects("020501FFFFFFFF", "beyond 32 bits");
    rejects("0206000000000001", "too long");
    rejects("0281017F", "non-minimal length");
    rejects("030100", "wrong tag");
    rejects("0202", "truncated");
  }

  private static long parse(String hex) {
    byte[] data = hex(hex);
    byte[] out = new byte[4];
    short end = U32.parseDerInteger(data, (short) 0, (short) data.length, out, (short) 0);
    assertEquals(data.length, end);
    return new BigInteger(1, out).longValue();
  }

  private static void rejects(String hex, String reason) {
    byte[] data = hex(hex);
    ISOException e =
        assertThrows(
            ISOException.class,
            () -> U32.parseDerInteger(data, (short) 0, (short) data.length, new byte[4], (short) 0),
            reason);
    assertEquals((short) 0x6A80, e.getReason(), reason);
  }

  static byte[] hex(String value) {
    byte[] out = new byte[value.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(value.substring(2 * i, 2 * i + 2), 16);
    }
    return out;
  }
}
