package dev.mistial.tests.issuersam;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.fpe.FPEFF1Engine;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Independent host-side reference for OPID layout v2, built on BigInteger, the JCA AES provider and
 * the BouncyCastle FF1 engine. It shares no code with the applet.
 *
 * <p>OPID = IIII | E | L with E = FF1_K(batch(4) | x_n(8), ASCII(IIII)) over 12 digits and L the
 * Luhn digit over IIII | E; x_n = f^n(x0) for f(x) = (a x + c) mod 10^8.
 */
public final class OpidV2Reference {
  public static final BigInteger M = BigInteger.TEN.pow(8);

  public final int iin;
  public final int batch;
  public final long a;
  public final long c;
  public final long x0;
  private final byte[] key;

  public OpidV2Reference(int iin, int batch, long a, long c, long x0, byte[] key) {
    this.iin = iin;
    this.batch = batch;
    this.a = a;
    this.c = c;
    this.x0 = x0;
    this.key = key.clone();
  }

  /** x_n = f^n(x0) by square-and-multiply of the affine map. */
  public long x(long n) {
    BigInteger ra = BigInteger.ONE;
    BigInteger rc = BigInteger.ZERO;
    BigInteger pa = BigInteger.valueOf(a);
    BigInteger pc = BigInteger.valueOf(c);
    long e = n;
    while (e > 0) {
      if ((e & 1) == 1) {
        // r = p o r
        rc = pa.multiply(rc).add(pc).mod(M);
        ra = pa.multiply(ra).mod(M);
      }
      pc = pa.multiply(pc).add(pc).mod(M);
      pa = pa.multiply(pa).mod(M);
      e >>= 1;
    }
    return ra.multiply(BigInteger.valueOf(x0)).add(rc).mod(M).longValue();
  }

  public byte[] tweak() {
    return String.format("%04d", iin).getBytes(StandardCharsets.US_ASCII);
  }

  public String opidForX(long x) {
    return opidFor(batch, x);
  }

  public String opidFor(int batchNumber, long x) {
    byte[] digits = digits(String.format("%04d%08d", batchNumber, x));
    byte[] e = ff1(true, digits);
    String payload = String.format("%04d", iin) + numeral(e);
    return payload + luhn(payload);
  }

  public String opidAt(long n) {
    return opidForX(x(n));
  }

  /** FF1 decrypt of the 12 enciphered digits: returns {batch, x}. */
  public long[] decipher(String opid) {
    byte[] e = digits(opid.substring(4, 16));
    String plain = numeral(ff1(false, e));
    return new long[] {Long.parseLong(plain.substring(0, 4)), Long.parseLong(plain.substring(4))};
  }

  /** The index n in [0, 10^8) with f^n(x0) = x, by digit-wise search on the affine powers. */
  public long indexOf(long target) {
    long n = 0;
    long step = 1;
    for (int j = 1; j <= 8; j++) {
      long mod = BigInteger.TEN.pow(j).longValue();
      int t = 0;
      while (x(n) % mod != target % mod) {
        n += step;
        if (++t > 9) throw new IllegalStateException("not full period");
      }
      step *= 10;
    }
    return n;
  }

  private byte[] ff1(boolean encrypt, byte[] digits) {
    FPEFF1Engine engine = new FPEFF1Engine(AESEngine.newInstance());
    engine.init(encrypt, new FPEParameters(new KeyParameter(key), 10, tweak()));
    byte[] out = new byte[digits.length];
    engine.processBlock(digits, 0, digits.length, out, 0);
    return out;
  }

  public byte[] kcv() {
    try {
      Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
      aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
      byte[] block = aes.doFinal(new byte[16]);
      MessageDigest sha = MessageDigest.getInstance("SHA-256");
      sha.update("OPSAMFPEKCV1".getBytes(StandardCharsets.US_ASCII));
      return Arrays.copyOf(sha.digest(block), 16);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /** paramsDigest v3. */
  public byte[] paramsDigest(long initialQuota, long initialTs) {
    try {
      MessageDigest sha = MessageDigest.getInstance("SHA-256");
      sha.update("OPSAMPRM3".getBytes(StandardCharsets.US_ASCII));
      sha.update(digits(String.format("%04d", iin)));
      sha.update(digits(String.format("%04d", batch)));
      sha.update(reverse(digits(String.format("%08d", a))));
      sha.update(reverse(digits(String.format("%08d", c))));
      sha.update(reverse(digits(String.format("%08d", x0))));
      for (int shift = 24; shift >= 0; shift -= 8) sha.update((byte) (initialQuota >>> shift));
      for (int shift = 56; shift >= 0; shift -= 8) sha.update((byte) (initialTs >>> shift));
      sha.update(kcv());
      return sha.digest();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  public static int luhn(String payload) {
    int sum = 0;
    boolean doubled = true;
    for (int i = payload.length() - 1; i >= 0; i--) {
      int d = payload.charAt(i) - '0';
      if (doubled) {
        d *= 2;
        if (d > 9) d -= 9;
      }
      sum += d;
      doubled = !doubled;
    }
    return (10 - sum % 10) % 10;
  }

  public static byte[] digits(String numeral) {
    byte[] out = new byte[numeral.length()];
    for (int i = 0; i < out.length; i++) out[i] = (byte) (numeral.charAt(i) - '0');
    return out;
  }

  public static String numeral(byte[] digits) {
    StringBuilder out = new StringBuilder();
    for (byte d : digits) out.append((char) ('0' + d));
    return out.toString();
  }

  private static byte[] reverse(byte[] in) {
    byte[] out = new byte[in.length];
    for (int i = 0; i < in.length; i++) out[i] = in[in.length - 1 - i];
    return out;
  }
}
