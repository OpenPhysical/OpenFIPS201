/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.opid;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.BitSet;
import org.junit.jupiter.api.Test;

class LcgTest {
  @Test
  void vectorsMatchSequenceAndPeriod() throws Exception {
    JsonObject root = OpidVectors.load("lcg.json");
    for (JsonElement element : root.getAsJsonArray("vectors")) {
      JsonObject v = element.getAsJsonObject();
      Lcg lcg =
          Lcg.of(
              v.get("cinDigits").getAsInt(),
              v.get("a").getAsLong(),
              v.get("c").getAsLong(),
              v.get("x0").getAsLong());
      JsonArray first20 = v.getAsJsonArray("first20");
      assertEquals(20, first20.size());
      long x = lcg.x0;
      for (int n = 1; n <= 20; n++) {
        x = lcg.next(x);
        assertEquals(first20.get(n - 1).getAsLong(), x, "next^" + n);
        assertEquals(x, lcg.at(n), "at(" + n + ")");
      }
      assertEquals(v.get("at1000").getAsLong(), lcg.at(1000));
      assertEquals(v.get("period").getAsLong(), lcg.m);
      assertFullPeriodByDivisors(lcg);

      JsonArray maps = v.getAsJsonArray("jumpMaps");
      assertEquals(lcg.cinDigits, maps.size());
      long step = 1;
      for (int j = 1; j <= lcg.cinDigits; j++) {
        JsonArray pair = maps.get(j - 1).getAsJsonArray();
        long[] map = lcg.jumpMap(j);
        assertEquals(pair.get(0).getAsLong(), map[0], "A_" + j);
        assertEquals(pair.get(1).getAsLong(), map[1], "C_" + j);
        assertEquals(lcg.at(step), (map[0] * lcg.x0 + map[1]) % lcg.m, "M_" + j + "(x0)");
        step *= 10;
      }
      for (JsonElement recovery : v.getAsJsonArray("indexRecovery")) {
        JsonObject r = recovery.getAsJsonObject();
        long n = r.get("n").getAsLong();
        long state = r.get("x").getAsLong();
        assertEquals(state, lcg.at(n));
        assertEquals(n, lcg.indexOf(state));
      }
    }
  }

  @Test
  void indexOfInvertsAtExhaustivelyForSmallModuli() {
    for (int k = 2; k <= 4; k++) {
      long m = Digits.pow10(k);
      for (long a = 21; a < m; a += k == 4 ? 20 * 41 : 20) {
        Lcg lcg = Lcg.of(k, a, m - 1, (a * 3) % m);
        long x = lcg.x0;
        for (long n = 0; n < m; n++) {
          assertEquals(n, lcg.indexOf(x), "k=" + k + " a=" + a + " n=" + n);
          x = lcg.next(x);
        }
      }
    }
  }

  @Test
  void indexOfInvertsAtForRandomOpidBatches() {
    SecureRandom rnd = deterministic(99);
    for (int i = 0; i < 50; i++) {
      Lcg lcg = Lcg.generate(rnd);
      assertEquals(Lcg.CIN_DIGITS, lcg.cinDigits);
      for (int t = 0; t < 40; t++) {
        long n = (rnd.nextLong() >>> 1) % lcg.m;
        assertEquals(n, lcg.indexOf(lcg.at(n)));
      }
      assertEquals(0, lcg.indexOf(lcg.x0));
      assertEquals(lcg.m - 1, lcg.indexOf(lcg.at(lcg.m - 1)));
    }
    Lcg lcg = Lcg.of(87654321L, 12345679L, 31415926L);
    assertThrows(IllegalArgumentException.class, () -> lcg.indexOf(lcg.m));
    assertThrows(IllegalArgumentException.class, () -> lcg.jumpMap(0));
    assertThrows(IllegalArgumentException.class, () -> lcg.jumpMap(9));
  }

  @Test
  void rejectedVectorsFailValidation() throws Exception {
    JsonObject root = OpidVectors.load("lcg.json");
    int count = 0;
    for (JsonElement element : root.getAsJsonArray("rejected")) {
      JsonObject v = element.getAsJsonObject();
      assertThrows(
          IllegalArgumentException.class,
          () -> Lcg.of(v.get("a").getAsLong(), v.get("c").getAsLong(), v.get("x0").getAsLong()),
          v.toString());
      count++;
    }
    assertTrue(count >= 5);
  }

  @Test
  void fullPeriodByExhaustionForSmallModuli() {
    // m = 10 admits no multiplier (see cinDigitsOneHasNoMultiplier). For k = 2 and 3 every
    // multiplier is exhausted; for k = 4 and 5 every 37th multiplier.
    for (int k = 2; k <= 5; k++) {
      long m = Digits.pow10(k);
      long stride = k <= 3 ? 20 : 20 * 37;
      long[] increments = k <= 3 ? new long[] {1, 3, 7, 9, m - 1} : new long[] {1, m - 1};
      for (long a = 21; a < m; a += stride) {
        for (long c : increments) {
          Lcg lcg = Lcg.of(k, a, c, (a * 7 + c) % m);
          BitSet seen = new BitSet((int) m);
          long x = lcg.x0;
          for (long n = 0; n < m; n++) {
            assertFalse(seen.get((int) x), "value repeated before the full period");
            seen.set((int) x);
            if (n < 64 || n % 997 == 0) {
              assertEquals(x, lcg.at(n));
            }
            x = lcg.next(x);
          }
          assertEquals(m, seen.cardinality());
          assertEquals(lcg.x0, x);
          assertEquals(lcg.x0, lcg.at(m));
          assertEquals(lcg.at(1), lcg.at(m + 1));
        }
      }
    }
  }

  @Test
  void cinDigitsOneHasNoMultiplier() {
    for (long a = 0; a < 10; a++) {
      final long multiplier = a;
      assertThrows(IllegalArgumentException.class, () -> Lcg.of(1, multiplier, 3, 0));
    }
    assertThrows(IllegalArgumentException.class, () -> Lcg.generate(1, new SecureRandom()));
    assertThrows(IllegalArgumentException.class, () -> Lcg.of(0, 21, 3, 0));
    assertThrows(IllegalArgumentException.class, () -> Lcg.of(9, 21, 3, 0));
  }

  @Test
  void hullDobellRejections() {
    long m = 10000;
    Lcg.requireHullDobell(m, 21, 1);
    Lcg.requireHullDobell(m, 9981, 9999);
    long[][] rejected = {
      {2341, 7778}, // c even
      {2341, 7775}, // c divisible by 5
      {2341, 0}, // c = 0
      {2341, m}, // c = m
      {2341, -1}, // c negative
      {2331, 7777}, // a = 1 (mod 10) but not (mod 20)
      {2351, 7777}, // a = 11 (mod 20)
      {1, 7777}, // a = 1
      {0, 7777}, // a = 0
      {m + 1, 7777}, // a > m, a = 1 (mod 20)
      {m + 21, 7777}, // a > m, a = 1 (mod 20)
      {2342, 7777}, // a - 1 odd
    };
    for (long[] params : rejected) {
      assertThrows(
          IllegalArgumentException.class,
          () -> Lcg.requireHullDobell(m, params[0], params[1]),
          "a=" + params[0] + " c=" + params[1]);
    }
    assertThrows(IllegalArgumentException.class, () -> Lcg.of(4, 2341, 7777, m));
    assertThrows(IllegalArgumentException.class, () -> Lcg.of(4, 2341, 7777, -1));
    assertThrows(IllegalArgumentException.class, () -> Lcg.of(4, 2341, 7777, 0).next(m));
    assertThrows(IllegalArgumentException.class, () -> Lcg.of(4, 2341, 7777, 0).at(-1));
  }

  @Test
  void atMatchesBigIntegerClosedForm() {
    SecureRandom rnd = deterministic(7);
    for (int k = 2; k <= 8; k++) {
      for (int i = 0; i < 200; i++) {
        Lcg lcg = Lcg.generate(k, rnd);
        long n = (rnd.nextLong() >>> 1) % (lcg.m * 3);
        assertEquals(closedForm(lcg, n), lcg.at(n), "k=" + k + " n=" + n);
      }
      Lcg lcg = Lcg.generate(k, rnd);
      assertEquals(lcg.x0, lcg.at(0));
      assertEquals(lcg.x0, lcg.at(lcg.m));
      assertEquals(closedForm(lcg, Long.MAX_VALUE), lcg.at(Long.MAX_VALUE));
      // next() at the top of the range is exact.
      long top = lcg.m - 1;
      assertEquals(
          BigInteger.valueOf(lcg.a)
              .multiply(BigInteger.valueOf(top))
              .add(BigInteger.valueOf(lcg.c))
              .mod(BigInteger.valueOf(lcg.m))
              .longValue(),
          lcg.next(top));
    }
  }

  @Test
  void generateProducesValidParametersAcrossSeeds() {
    for (int seed = 0; seed < 300; seed++) {
      SecureRandom rnd = deterministic(seed);
      for (int k = 2; k <= 8; k++) {
        Lcg lcg = Lcg.generate(k, rnd);
        assertEquals(k, lcg.cinDigits);
        Lcg.requireHullDobell(lcg.m, lcg.a, lcg.c);
        assertTrue(lcg.x0 >= 0 && lcg.x0 < lcg.m);
        assertNotEquals(0, (lcg.a - 1) % 100, "generator quality filter");
        if (k <= 4) {
          assertFullPeriodByDivisors(lcg);
        }
      }
    }
    SecureRandom live = new SecureRandom();
    for (int i = 0; i < 100; i++) {
      Lcg lcg = Lcg.generate(8, live);
      assertFullPeriodByDivisors(lcg);
    }
  }

  @Test
  void generateIsDeterministicForAFixedStream() {
    Lcg first = Lcg.generate(8, deterministic(42));
    Lcg second = Lcg.generate(8, deterministic(42));
    assertEquals(first.a, second.a);
    assertEquals(first.c, second.c);
    assertEquals(first.x0, second.x0);
    assertEquals("Lcg(k=8)", first.toString());
  }

  /** Period divides m = 2^k 5^k; it equals m iff f^m = id at x0 and neither f^(m/2) nor f^(m/5). */
  private static void assertFullPeriodByDivisors(Lcg lcg) {
    assertEquals(lcg.x0, lcg.at(lcg.m));
    assertNotEquals(lcg.x0, lcg.at(lcg.m / 2));
    assertNotEquals(lcg.x0, lcg.at(lcg.m / 5));
  }

  /**
   * f^n(x0) = a^n x0 + c (a^n - 1)/(a - 1) mod m, evaluated mod m(a - 1) to keep division exact.
   */
  private static long closedForm(Lcg lcg, long n) {
    BigInteger a = BigInteger.valueOf(lcg.a);
    BigInteger m = BigInteger.valueOf(lcg.m);
    BigInteger aMinus1 = a.subtract(BigInteger.ONE);
    BigInteger an = a.modPow(BigInteger.valueOf(n), m.multiply(aMinus1));
    BigInteger geometric = an.subtract(BigInteger.ONE).mod(m.multiply(aMinus1)).divide(aMinus1);
    return an.multiply(BigInteger.valueOf(lcg.x0))
        .add(BigInteger.valueOf(lcg.c).multiply(geometric))
        .mod(m)
        .longValue();
  }

  private static SecureRandom deterministic(long seed) {
    try {
      SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG");
      rnd.setSeed(seed);
      return rnd;
    } catch (java.security.NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}
