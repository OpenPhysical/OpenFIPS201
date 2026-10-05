package dev.mistial.openphysical.sam;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.BitSet;
import java.util.SplittableRandom;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/** White-box tests of the decimal LCG against a BigInteger reference. */
class DecimalLcgTest {

  static byte[] digits(long value, int k) {
    byte[] out = new byte[8];
    for (int i = 0; i < k; i++) {
      out[i] = (byte) (value % 10);
      value /= 10;
    }
    return out;
  }

  static long value(byte[] digits, int offset, int k) {
    long v = 0;
    for (int i = k - 1; i >= 0; i--) v = v * 10 + digits[offset + i];
    return v;
  }

  static long reference(long a, long x, long c, int k) {
    BigInteger m = BigInteger.TEN.pow(k);
    return BigInteger.valueOf(a)
        .multiply(BigInteger.valueOf(x))
        .add(BigInteger.valueOf(c))
        .mod(m)
        .longValue();
  }

  static long step(long a, long x, long c, int k) {
    byte[] out = new byte[8];
    DecimalLcg.step(
        digits(a, k),
        (short) 0,
        digits(x, k),
        (short) 0,
        digits(c, k),
        (short) 0,
        (short) k,
        out,
        (short) 0);
    return value(out, 0, k);
  }

  @Test
  void stepMatchesBigIntegerForEveryWidth() {
    SplittableRandom random = new SplittableRandom(20261005L);
    int cases = 0;
    for (int k = 1; k <= 8; k++) {
      long m = BigInteger.TEN.pow(k).longValue();
      long[] edges = {0, 1, m - 1, m / 2, m - 2};
      for (long a : edges) {
        for (long x : edges) {
          for (long c : edges) {
            assertEquals(reference(a, x, c, k), step(a, x, c, k), "k=" + k);
            cases++;
          }
        }
      }
      for (int i = 0; i < 15_000; i++) {
        long a = random.nextLong(m);
        long x = random.nextLong(m);
        long c = random.nextLong(m);
        assertEquals(reference(a, x, c, k), step(a, x, c, k), "k=" + k);
        cases++;
      }
    }
    assertTrue(cases >= 100_000, "at least 100k cases, ran " + cases);
  }

  @Test
  void fullPeriodIsExhaustiveForTwoAndThreeDigits() {
    for (int k = 2; k <= 3; k++) {
      long m = BigInteger.TEN.pow(k).longValue();
      for (long a = 21; a < m; a += 20) {
        for (long c : new long[] {1, 3, 7, 9, m - 1}) {
          assertTrue(
              DecimalLcg.isHullDobell(digits(a, k), (short) 0, digits(c, k), (short) 0, (short) k));
          assertEquals(m, period(a, c, 0, k), "a=" + a + " c=" + c + " k=" + k);
        }
      }
    }
  }

  @Test
  void hundredThousandStepsAreDistinctAndReturnToSeedAtM() {
    assertFullPeriodWalk(4, 4321, 7, 1234);
    // k = 5: m = 100 000 steps.
    assertFullPeriodWalk(5, 86421, 9, 31415);
  }

  @Test
  @Tag("slow")
  void fullPeriodWalkForSixToEightDigits() {
    assertFullPeriodWalk(6, 20 * 31337 + 1, 3, 271828);
    assertFullPeriodWalk(7, 20 * 271828 + 1, 1, 1414213);
    assertFullPeriodWalk(8, 20 * 4321 + 1, 7, 12345678);
  }

  private static void assertFullPeriodWalk(int k, long a, long c, long x0) {
    long m = BigInteger.TEN.pow(k).longValue();
    byte[] ad = digits(a, k);
    byte[] cd = digits(c, k);
    byte[] x = digits(x0, k);
    byte[] next = new byte[8];
    BitSet seen = new BitSet((int) m);
    for (long n = 1; n <= m; n++) {
      DecimalLcg.step(ad, (short) 0, x, (short) 0, cd, (short) 0, (short) k, next, (short) 0);
      byte[] swap = x;
      x = next;
      next = swap;
      int v = (int) value(x, 0, k);
      assertFalse(seen.get(v), "repeat at n=" + n);
      seen.set(v);
    }
    // m distinct values were visited and the walk is back at x0 exactly at n = m.
    assertEquals(m, seen.cardinality());
    assertEquals(x0, value(x, 0, k), "f^m(x0) == x0");
  }

  @Test
  void multiplierElevenIsRejectedAndShowsHalfPeriod() {
    assertFalse(
        DecimalLcg.isHullDobell(digits(11, 2), (short) 0, digits(7, 2), (short) 0, (short) 2));
    assertEquals(50, period(11, 7, 0, 2));
    assertFalse(
        DecimalLcg.isHullDobell(digits(11, 5), (short) 0, digits(7, 5), (short) 0, (short) 5));
    assertTrue(period(11, 7, 0, 5) < 100_000);
  }

  @Test
  void hullDobellRejections() {
    int k = 6;
    assertTrue(hd(21, 7, k));
    assertFalse(hd(21, 8, k), "c even");
    assertFalse(hd(21, 5, k), "c multiple of 5");
    assertFalse(hd(21, 0, k), "c zero");
    assertFalse(hd(1, 7, k), "a = 1");
    assertFalse(hd(11, 7, k), "a = 1 mod 10 but not mod 20");
    assertFalse(hd(31, 7, k), "tens digit odd");
    assertFalse(hd(23, 7, k), "units digit not 1");
    assertFalse(hd(0, 7, k), "a = 0");
    assertTrue(hd(999981, 999999, k), "largest valid a and c");
    assertFalse(hd(21, 7, 1), "k = 1 has no valid multiplier");
  }

  @Test
  void eightDigitLcgVectorsJumpMapsAndIndexRecoveryMatch() throws Exception {
    String directory = System.getProperty("openfips201.testVectors", "test-vectors");
    com.google.gson.JsonObject root =
        com.google.gson.JsonParser.parseString(
                new String(
                    java.nio.file.Files.readAllBytes(
                        java.nio.file.Paths.get(directory, "opid", "lcg.json")),
                    java.nio.charset.StandardCharsets.UTF_8))
            .getAsJsonObject();
    assertEquals("openphysical.opid-vectors/2", root.get("schema").getAsString());
    int checked = 0;
    for (com.google.gson.JsonElement element : root.getAsJsonArray("vectors")) {
      com.google.gson.JsonObject vector = element.getAsJsonObject();
      if (vector.get("cinDigits").getAsInt() != 8) continue;
      byte[] a = digits(vector.get("a").getAsLong(), 8);
      byte[] c = digits(vector.get("c").getAsLong(), 8);
      byte[] x0 = digits(vector.get("x0").getAsLong(), 8);
      assertTrue(DecimalLcg.isHullDobell(a, (short) 0, c, (short) 0, (short) 8));
      byte[] x = x0.clone();
      byte[] next = new byte[8];
      com.google.gson.JsonArray first20 = vector.getAsJsonArray("first20");
      for (int n = 1; n <= 1000; n++) {
        DecimalLcg.step(a, (short) 0, x, (short) 0, c, (short) 0, (short) 8, next, (short) 0);
        System.arraycopy(next, 0, x, 0, 8);
        if (n <= 20) assertEquals(first20.get(n - 1).getAsLong(), value(x, 0, 8), "n=" + n);
      }
      assertEquals(vector.get("at1000").getAsLong(), value(x, 0, 8));

      byte[] jumpA = new byte[64];
      byte[] jumpC = new byte[64];
      byte[] work = new byte[40];
      DecimalLcg.jumpMaps(a, c, jumpA, jumpC, work, (short) 0);
      assertTrue(isZero(work));
      com.google.gson.JsonArray maps = vector.getAsJsonArray("jumpMaps");
      for (int j = 0; j < 8; j++) {
        assertEquals(maps.get(j).getAsJsonArray().get(0).getAsLong(), value(jumpA, 8 * j, 8));
        assertEquals(maps.get(j).getAsJsonArray().get(1).getAsLong(), value(jumpC, 8 * j, 8));
      }
      for (com.google.gson.JsonElement recovery : vector.getAsJsonArray("indexRecovery")) {
        com.google.gson.JsonObject pair = recovery.getAsJsonObject();
        byte[] n = new byte[8];
        assertTrue(
            DecimalLcg.recoverIndex(
                jumpA,
                jumpC,
                x0,
                digits(pair.get("x").getAsLong(), 8),
                (short) 0,
                new byte[16],
                (short) 0,
                n,
                (short) 0));
        assertEquals(pair.get("n").getAsLong(), value(n, 0, 8), pair.toString());
      }
      checked++;
    }
    assertEquals(4, checked);
  }

  @Test
  void indexRecoveryInvertsRandomOrbitPositions() {
    SplittableRandom random = new SplittableRandom(2026);
    long m = 100_000_000L;
    byte[] a = digits(87_654_321L, 8);
    byte[] c = digits(12_345_679L, 8);
    byte[] x0 = digits(31_415_926L, 8);
    byte[] jumpA = new byte[64];
    byte[] jumpC = new byte[64];
    DecimalLcg.jumpMaps(a, c, jumpA, jumpC, new byte[40], (short) 0);
    for (int i = 0; i < 200; i++) {
      long n = random.nextLong(m);
      // x_n by the affine power computed with BigInteger.
      BigInteger an =
          BigInteger.valueOf(87_654_321L).modPow(BigInteger.valueOf(n), BigInteger.valueOf(m));
      long xn = affinePower(87_654_321L, 12_345_679L, 31_415_926L, n);
      byte[] out = new byte[8];
      assertTrue(
          DecimalLcg.recoverIndex(
              jumpA, jumpC, x0, digits(xn, 8), (short) 0, new byte[16], (short) 0, out, (short) 0));
      assertEquals(n, value(out, 0, 8), "n=" + n + " a^n=" + an);
    }
  }

  private static long affinePower(long a, long c, long x0, long n) {
    BigInteger m = BigInteger.TEN.pow(8);
    BigInteger ra = BigInteger.ONE;
    BigInteger rc = BigInteger.ZERO;
    BigInteger pa = BigInteger.valueOf(a);
    BigInteger pc = BigInteger.valueOf(c);
    for (long e = n; e > 0; e >>= 1) {
      if ((e & 1) == 1) {
        rc = pa.multiply(rc).add(pc).mod(m);
        ra = pa.multiply(ra).mod(m);
      }
      pc = pa.multiply(pc).add(pc).mod(m);
      pa = pa.multiply(pa).mod(m);
    }
    return ra.multiply(BigInteger.valueOf(x0)).add(rc).mod(m).longValue();
  }

  private static boolean isZero(byte[] data) {
    for (byte b : data) if (b != 0) return false;
    return true;
  }

  @Test
  void isDigitsRejectsOutOfRangeValues() {
    assertTrue(DecimalLcg.isDigits(new byte[] {0, 9, 5}, (short) 0, (short) 3));
    assertFalse(DecimalLcg.isDigits(new byte[] {0, 10, 5}, (short) 0, (short) 3));
    assertFalse(DecimalLcg.isDigits(new byte[] {-1}, (short) 0, (short) 1));
  }

  private static boolean hd(long a, long c, int k) {
    return DecimalLcg.isHullDobell(digits(a, k), (short) 0, digits(c, k), (short) 0, (short) k);
  }

  private static long period(long a, long c, long x0, int k) {
    long m = BigInteger.TEN.pow(k).longValue();
    long x = step(a, x0, c, k);
    long n = 1;
    while (x != x0 && n <= m) {
      x = step(a, x, c, k);
      n++;
    }
    return n;
  }
}
