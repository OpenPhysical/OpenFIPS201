/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.opid;

import java.security.SecureRandom;

/**
 * Decimal linear congruential generator {@code f(x) = (a*x + c) mod m} with {@code m = 10^k}. OPID
 * batches use {@code k = 8} ({@link #of(long, long, long)}, {@link #generate(SecureRandom)});
 * smaller k exist only so tests can exhaust the period.
 *
 * <p>Arithmetic is exact: {@code a, c, x < m <= 10^8}, so {@code a*x + c < 10^16} fits a signed
 * 64-bit long, and {@link Math#multiplyExact} / {@link Math#addExact} enforce that bound.
 *
 * <p>Sequence semantics: issuance number {@code n >= 1} has state {@code x_n = f^n(x0) = at(n)};
 * the seed {@code x0} is never issued.
 */
public final class Lcg {
  /** CIN width of every OPID batch. */
  public static final int CIN_DIGITS = 8;

  public static final int MIN_CIN_DIGITS = 1;
  public static final int MAX_CIN_DIGITS = 8;

  public final int cinDigits;
  public final long m;
  public final long a;
  public final long c;
  public final long x0;

  /** {@code jumps[j-1] = M_j}, precomputed at construction. */
  private final long[][] jumps;

  private Lcg(int cinDigits, long m, long a, long c, long x0) {
    this.cinDigits = cinDigits;
    this.m = m;
    this.a = a;
    this.c = c;
    this.x0 = x0;
    this.jumps = precomputeJumps();
  }

  /** Builds an OPID batch generator over {@code m = 10^8}. */
  public static Lcg of(long a, long c, long x0) {
    return of(CIN_DIGITS, a, c, x0);
  }

  /**
   * Builds a generator over {@code m = 10^cinDigits}.
   *
   * @throws IllegalArgumentException unless {@code 1 <= cinDigits <= 8}, the parameters satisfy
   *     {@link #requireHullDobell} and {@code 0 <= x0 < m}
   */
  public static Lcg of(int cinDigits, long a, long c, long x0) {
    long m = modulus(cinDigits);
    requireHullDobell(m, a, c);
    if (x0 < 0 || x0 >= m) {
      throw new IllegalArgumentException("LCG seed x0 must satisfy 0 <= x0 < m");
    }
    return new Lcg(cinDigits, m, a, c, x0);
  }

  /**
   * Hull–Dobell full-period conditions for {@code m = 10^k}: {@code 1 <= c < m} with {@code gcd(c,
   * 10) == 1}, and {@code 1 < a < m} with {@code (a - 1) % 20 == 0} (a - 1 divisible by every prime
   * factor of m, and by 4 because 4 divides m for k >= 2).
   */
  public static void requireHullDobell(long m, long a, long c) {
    if (c < 1 || c >= m) {
      throw new IllegalArgumentException("LCG increment c must satisfy 1 <= c < m");
    }
    if (c % 2 == 0 || c % 5 == 0) {
      throw new IllegalArgumentException("LCG increment c must be coprime to 10");
    }
    if (a <= 1 || a >= m) {
      throw new IllegalArgumentException("LCG multiplier a must satisfy 1 < a < m");
    }
    if ((a - 1) % 20 != 0) {
      throw new IllegalArgumentException("LCG multiplier a must satisfy a = 1 (mod 20)");
    }
  }

  /** Returns {@code (a*x + c) mod m} for {@code 0 <= x < m}. */
  public long next(long x) {
    requireState(x);
    return Math.addExact(Math.multiplyExact(a, x), c) % m;
  }

  /**
   * Returns {@code f^n(x0)} by repeated squaring of the affine map {@code x -> A*x + C}. Equal to
   * applying {@link #next} {@code n} times; {@code at(0) == x0} and, by the full period, {@code
   * at(m) == x0}.
   */
  public long at(long n) {
    if (n < 0) {
      throw new IllegalArgumentException("LCG step count must be non-negative");
    }
    long[] map = power(n);
    return apply(map, x0);
  }

  /**
   * Returns the jump map {@code M_j = f^(10^(j-1))} for {@code 1 <= j <= cinDigits} as the affine
   * pair {@code {A_j, C_j}} mod m, so {@code M_j(x) = (A_j*x + C_j) mod m}. {@code M_1 = (a, c)}
   * and {@code M_(j+1) = M_j^10}. These maps are as secret as the LCG parameters.
   */
  public long[] jumpMap(int j) {
    if (j < 1 || j > cinDigits) {
      throw new IllegalArgumentException("jump map index must be 1..cinDigits");
    }
    return jumps[j - 1].clone();
  }

  private long[][] precomputeJumps() {
    long[][] maps = new long[cinDigits][];
    maps[0] = new long[] {a, c};
    for (int j = 1; j < cinDigits; j++) {
      long[] tenth = {1L, 0L};
      for (int t = 0; t < 10; t++) {
        tenth = compose(maps[j - 1], tenth);
      }
      maps[j] = tenth;
    }
    return maps;
  }

  /**
   * Recovers the step count {@code n} in {@code [0, m)} with {@code f^n(x0) == x}, digit by digit.
   *
   * <p>A full-period LCG mod {@code 10^k} also has full period {@code 10^j} mod {@code 10^j} for
   * every {@code j <= k}, so {@code x_n mod 10^j} depends only on {@code n mod 10^j}. Starting from
   * {@code y = x0, n = 0}, for {@code j = 1..k} and {@code t = 0..9}: if the low j digits of y
   * equal those of x, record digit t ({@code n += t*10^(j-1)}); otherwise apply {@code y = M_j(y)}
   * and try the next t. This is the recovery the Issuer SAM DECIPHER command performs.
   */
  public long indexOf(long x) {
    requireState(x);
    long y = x0;
    long n = 0;
    long place = 1;
    for (int j = 1; j <= cinDigits; j++) {
      long mod = place * 10;
      long[] map = jumps[j - 1];
      int t = 0;
      while (y % mod != x % mod) {
        if (++t == 10) {
          throw new IllegalStateException("LCG digit recovery failed; parameters lack full period");
        }
        y = apply(map, y);
      }
      n += t * place;
      place = mod;
    }
    return n;
  }

  /**
   * Draws full-period parameters for {@code m = 10^8}. See {@link #generate(int, SecureRandom)}.
   */
  public static Lcg generate(SecureRandom rnd) {
    return generate(CIN_DIGITS, rnd);
  }

  /**
   * Draws full-period parameters from {@code rnd}. {@code x0} is uniform on {@code [0, m)}; {@code
   * c} is uniform on the units of {@code [1, m)} coprime to 10; {@code a = 20t + 1} with {@code 1 <
   * a < m}, uniform over t. All draws use rejection sampling, so there is no modulo bias.
   *
   * <p>As a generator-only quality filter, {@code a = 1 (mod 100)} is also rejected; {@link
   * #requireHullDobell} does not apply that filter to supplied parameters.
   *
   * @throws IllegalArgumentException when {@code m = 10^cinDigits} admits no multiplier, which is
   *     the case for {@code cinDigits = 1}
   */
  public static Lcg generate(int cinDigits, SecureRandom rnd) {
    if (rnd == null) {
      throw new IllegalArgumentException("a SecureRandom is required");
    }
    long m = modulus(cinDigits);
    // a = 20t + 1 < m  <=>  t <= (m - 2) / 20; t = 0 gives a = 1 and is excluded.
    long maxT = (m - 2) / 20;
    if (maxT < 1) {
      throw new IllegalArgumentException(
          "no Hull-Dobell multiplier exists for " + cinDigits + " CIN digits");
    }
    // (a - 1) % 100 == 0  <=>  t % 5 == 0; t = 1 always remains, so the loop terminates.
    long t;
    do {
      t = 1 + uniform(rnd, maxT);
    } while (t % 5 == 0);
    long c;
    do {
      c = uniform(rnd, m);
    } while (c == 0 || c % 2 == 0 || c % 5 == 0);
    long x0 = uniform(rnd, m);
    return of(cinDigits, 20 * t + 1, c, x0);
  }

  /** Returns {@code f^n} as an affine pair, by repeated squaring. */
  private long[] power(long n) {
    long[] result = {1L, 0L};
    long[] base = {a, c};
    long remaining = n;
    while (remaining > 0) {
      if ((remaining & 1L) != 0) {
        result = compose(base, result);
      }
      remaining >>>= 1;
      if (remaining > 0) {
        base = compose(base, base);
      }
    }
    return result;
  }

  /** Returns {@code f o g}: {@code x -> f.A*(g.A*x + g.C) + f.C} mod m. */
  private long[] compose(long[] f, long[] g) {
    return new long[] {
      Math.multiplyExact(f[0], g[0]) % m, Math.addExact(Math.multiplyExact(f[0], g[1]), f[1]) % m
    };
  }

  private long apply(long[] map, long x) {
    return Math.addExact(Math.multiplyExact(map[0], x), map[1]) % m;
  }

  private void requireState(long x) {
    if (x < 0 || x >= m) {
      throw new IllegalArgumentException("LCG state must satisfy 0 <= x < m");
    }
  }

  /** Uniform draw on {@code [0, bound)} by rejection of the biased top of the 63-bit range. */
  private static long uniform(SecureRandom rnd, long bound) {
    long limit = Long.MAX_VALUE - (Long.MAX_VALUE % bound);
    long draw;
    do {
      draw = rnd.nextLong() >>> 1;
    } while (draw >= limit);
    return draw % bound;
  }

  private static long modulus(int cinDigits) {
    if (cinDigits < MIN_CIN_DIGITS || cinDigits > MAX_CIN_DIGITS) {
      throw new IllegalArgumentException("LCG CIN digits must be 1..8");
    }
    return Digits.pow10(cinDigits);
  }

  /** Returns only the CIN width; a, c and x0 predict the OPID sequence and are never printed. */
  @Override
  public String toString() {
    return "Lcg(k=" + cinDigits + ")";
  }
}
