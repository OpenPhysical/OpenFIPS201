/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.opid;

import org.bouncycastle.crypto.digests.SHA256Digest;

/**
 * OPID allocation sequence of one batch under one IIN.
 *
 * <p>Issuance number {@code n >= 1} has LCG state {@code x_n = lcg.at(n)} (m = 10^8) and receives
 * {@code OPID_n = IIII || E_n || L} with {@code E_n = FF1_K(batch(4) || x_n(8), ASCII(IIII))}
 * ({@link OpidCipher}) and L the Luhn digit over the 16 typed digits {@code IIII || E_n}; L is
 * never computed over the plaintext batch or state.
 *
 * <p>Uniqueness: batch numbers are unique per IIN and each batch LCG has full period, so every
 * {@code (batch, x)} pair under an IIN is unique; FF1 under one key and tweak permutes {@code [0,
 * 10^12)}, so every OPID under an IIN is unique.
 */
public final class OpidSequence {
  public static final int MAX_BATCH = 9999;
  public static final long MAX_QUOTA = 100000000L;

  private static final byte[] PARAMS_DOMAIN = {'O', 'P', 'S', 'A', 'M', 'P', 'R', 'M', '3'};
  private static final long STATE_MODULUS = 100000000L;

  public final int iin;
  public final int batch;
  public final Lcg lcg;

  private final OpidCipher cipher;

  private OpidSequence(int iin, int batch, Lcg lcg, OpidCipher cipher) {
    this.iin = iin;
    this.batch = batch;
    this.lcg = lcg;
    this.cipher = cipher;
  }

  /**
   * Builds the sequence. {@code fpeKey} (32 bytes, the IIN key) is copied.
   *
   * @throws IllegalArgumentException unless {@code 0 <= iin <= 9999}, {@code 0 <= batch <= 9999}
   *     and {@code lcg} has {@code m = 10^8}
   */
  public static OpidSequence of(int iin, int batch, Lcg lcg, byte[] fpeKey) {
    return of(iin, batch, lcg, OpidCipher.of(fpeKey));
  }

  /**
   * Builds the sequence over {@code cipher}, for example a token-backed {@link
   * OpidCipher#of(dev.mistial.tools.openfips201.crypto.AesBlock)}. {@link #destroy()} destroys it.
   *
   * @throws IllegalArgumentException as {@link #of(int, int, Lcg, byte[])}
   */
  public static OpidSequence of(int iin, int batch, Lcg lcg, OpidCipher cipher) {
    if (cipher == null) {
      throw new IllegalArgumentException("an FF1 cipher is required");
    }
    if (iin < 0 || iin > Opid.MAX_IIN) {
      throw new IllegalArgumentException("IIN must be 0..9999");
    }
    if (batch < 0 || batch > MAX_BATCH) {
      throw new IllegalArgumentException("batch number must be 0..9999");
    }
    if (lcg == null || lcg.cinDigits != Lcg.CIN_DIGITS) {
      throw new IllegalArgumentException("OPID batches require an LCG over 10^8");
    }
    return new OpidSequence(iin, batch, lcg, cipher);
  }

  /** Returns the FF1 tweak {@code ASCII(IIII)}. */
  public byte[] tweak() {
    return OpidCipher.tweak(iin);
  }

  /** Returns {@code E_n = FF1_K(batch || x_n, ASCII(IIII))} for {@code n >= 1}. */
  public long encipheredAt(long n) {
    if (n < 1) {
      throw new IllegalArgumentException("issuance numbers start at 1");
    }
    return cipher.encipher(iin, batch * STATE_MODULUS + lcg.at(n));
  }

  /** Returns the OPID of issuance number {@code n >= 1}. */
  public Opid opidAt(long n) {
    return Opid.of(iin, encipheredAt(n));
  }

  /**
   * Host mirror of the Issuer SAM DECIPHER command. Computes {@code (batch || x) = FF1^-1_K(E,
   * ASCII(IIII))}; when the batch is this sequence's batch, also recovers the count n with {@code
   * f^n(x0) = x} by {@link Lcg#indexOf} (digit-wise jump-map recovery, {@code 0 <= n < 10^8}; n = 0
   * means x = x0, which is never issued).
   *
   * @throws IllegalArgumentException when the OPID's IIN is not this sequence's IIN
   */
  public Deciphered decrypt(Opid opid) {
    if (opid == null) {
      throw new IllegalArgumentException("OPID is required");
    }
    if (opid.iin != iin) {
      throw new IllegalArgumentException("OPID IIN does not match this sequence");
    }
    long plain = cipher.decipher(iin, opid.e);
    int decodedBatch = (int) (plain / STATE_MODULUS);
    long x = plain % STATE_MODULUS;
    if (decodedBatch != batch) {
      return new Deciphered(decodedBatch, x, false, -1L);
    }
    return new Deciphered(decodedBatch, x, true, lcg.indexOf(x));
  }

  /** Returns the FF1 key check value ({@link OpidCipher#kcv()}). */
  public byte[] fpeKcv() {
    return cipher.kcv();
  }

  /**
   * Parameter digest v3, committed to by the SAM batch extension.
   *
   * <pre>
   * SHA-256("OPSAMPRM3" || IIN digits(4) || batch digits(4) || a digits(8) || c digits(8)
   *         || x0 digits(8) || initialQuota(u32 BE) || initialTs(u64 BE) || fpeKcv(16))
   * </pre>
   *
   * Each digit occupies one byte holding 0..9. IIN and batch digits are most-significant first; a,
   * c and x0 digits are least-significant first. The preimage is 69 bytes. The FF1 key itself is
   * never part of it.
   *
   * @throws IllegalArgumentException unless {@code 0 <= initialQuota <= 10^8}
   */
  public byte[] paramsDigest(long initialQuota, long initialTs) {
    byte[] preimage = paramsPreimage(initialQuota, initialTs);
    SHA256Digest sha = new SHA256Digest();
    sha.update(preimage, 0, preimage.length);
    byte[] out = new byte[sha.getDigestSize()];
    sha.doFinal(out, 0);
    return out;
  }

  /** Returns the exact byte string hashed by {@link #paramsDigest}. */
  public byte[] paramsPreimage(long initialQuota, long initialTs) {
    if (initialQuota < 0 || initialQuota > MAX_QUOTA) {
      throw new IllegalArgumentException("initial quota must be 0..10^8");
    }
    byte[] kcv = cipher.kcv();
    int k = Lcg.CIN_DIGITS;
    // shared wire contract: OPSAMPRM3 preimage layout, byte-identical with the SAM.
    byte[] out = new byte[PARAMS_DOMAIN.length + 4 + 4 + 3 * k + 4 + 8 + OpidCipher.KCV_LENGTH];
    int cursor = 0;
    System.arraycopy(PARAMS_DOMAIN, 0, out, cursor, PARAMS_DOMAIN.length);
    cursor += PARAMS_DOMAIN.length;
    cursor = digitsMsdFirst(iin, Opid.IIN_DIGITS, out, cursor);
    cursor = digitsMsdFirst(batch, 4, out, cursor);
    cursor = digitsLsdFirst(lcg.a, k, out, cursor);
    cursor = digitsLsdFirst(lcg.c, k, out, cursor);
    cursor = digitsLsdFirst(lcg.x0, k, out, cursor);
    for (int shift = 24; shift >= 0; shift -= 8) {
      out[cursor++] = (byte) (initialQuota >>> shift);
    }
    for (int shift = 56; shift >= 0; shift -= 8) {
      out[cursor++] = (byte) (initialTs >>> shift);
    }
    System.arraycopy(kcv, 0, out, cursor, OpidCipher.KCV_LENGTH);
    return out;
  }

  /** Overwrites the FF1 key; later enciphering, deciphering and digest operations fail. */
  public void destroy() {
    cipher.destroy();
  }

  /** Returns only the IIN; batch, LCG parameters and the key are never printed. */
  @Override
  public String toString() {
    return "OpidSequence(iin=" + Digits.pad(iin, Opid.IIN_DIGITS) + ")";
  }

  private static int digitsMsdFirst(long value, int count, byte[] out, int offset) {
    long remaining = value;
    for (int i = count - 1; i >= 0; i--) {
      out[offset + i] = (byte) (remaining % 10);
      remaining /= 10;
    }
    return offset + count;
  }

  private static int digitsLsdFirst(long value, int count, byte[] out, int offset) {
    long remaining = value;
    for (int i = 0; i < count; i++) {
      out[offset + i] = (byte) (remaining % 10);
      remaining /= 10;
    }
    return offset + count;
  }

  /** Result of {@link #decrypt}. */
  public static final class Deciphered {
    /** Deciphered batch number, 0..9999. */
    public final int batch;

    /** Deciphered LCG state x. The SAM never returns this value. */
    public final long x;

    /** True when {@link #batch} is the sequence's batch. */
    public final boolean sameBatch;

    /** Count n with {@code f^n(x0) = x} when {@link #sameBatch}; otherwise -1. */
    public final long count;

    Deciphered(int batch, long x, boolean sameBatch, long count) {
      this.batch = batch;
      this.x = x;
      this.sameBatch = sameBatch;
      this.count = count;
    }

    /** SAM flag {@code 84}: true when {@link #sameBatch} and {@code 1 <= count <= issued}. */
    public boolean issuedWithin(long issued) {
      return sameBatch && count >= 1 && count <= issued;
    }
  }
}
