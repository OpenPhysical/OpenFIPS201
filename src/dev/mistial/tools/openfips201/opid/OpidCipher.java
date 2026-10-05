/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.opid;

import dev.mistial.tools.openfips201.crypto.AesBlock;
import dev.mistial.tools.openfips201.crypto.BcAesBlock;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.fpe.FPEFF1Engine;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * OPID field cipher: NIST SP 800-38G Rev. 1 FF1 (Algorithms 7 and 8) with AES-256, radix 10, n = 12
 * digits (u = v = 6), tweak {@code T = ASCII(IIII)} (4 bytes). Since {@code 10^12 >= 10^6} no
 * cycle-walking is needed.
 *
 * <p>Contract: FF1 enciphers only the 12-digit {@code batch(4) || x_n(8)} field. The IIN is never
 * enciphered; it stays plaintext in the OPID and enters FF1 only as the tweak. One key serves every
 * batch and SAM of an IIN.
 *
 * <p>FF1 uses AES only in the forward direction (its PRF is AES-CBC-MAC), so the key is reached
 * through an {@link AesBlock}: {@link BcAesBlock} for a key in memory ({@link #of(byte[])}), or a
 * token key ({@code Pkcs11AesBlock}) so that FF1 runs without the key leaving the token ({@link
 * #of(AesBlock)}). Both give identical results. {@link #destroy()} destroys the block.
 */
public final class OpidCipher {
  public static final int KEY_LENGTH = 32;
  public static final int KCV_LENGTH = 16;

  private static final int RADIX = 10;
  private static final byte[] KCV_DOMAIN = {
    'O', 'P', 'S', 'A', 'M', 'F', 'P', 'E', 'K', 'C', 'V', '1'
  };

  private final AesBlock block;
  private boolean destroyed;

  private OpidCipher(AesBlock block) {
    this.block = block;
  }

  /** Wraps a copy of the 32-byte AES-256 key (Bouncy Castle AES). */
  public static OpidCipher of(byte[] key) {
    if (key == null || key.length != KEY_LENGTH) {
      throw new IllegalArgumentException("FF1 key must be " + KEY_LENGTH + " bytes (AES-256)");
    }
    return new OpidCipher(new BcAesBlock(key));
  }

  /**
   * Uses {@code block} as the AES-256 key. The caller guarantees the block's key is AES-256; the
   * KCV identifies it.
   */
  public static OpidCipher of(AesBlock block) {
    if (block == null) {
      throw new IllegalArgumentException("an AES block function is required");
    }
    return new OpidCipher(block);
  }

  /** Draws a fresh 32-byte AES-256 key; the caller wipes the returned array. */
  public static byte[] generateKey(SecureRandom rnd) {
    if (rnd == null) {
      throw new IllegalArgumentException("a SecureRandom is required");
    }
    byte[] out = new byte[KEY_LENGTH];
    rnd.nextBytes(out);
    return out;
  }

  /** Returns the tweak {@code ASCII(IIII)}, the IIN as 4 ASCII digits. */
  public static byte[] tweak(int iin) {
    if (iin < 0 || iin > Opid.MAX_IIN) {
      throw new IllegalArgumentException("IIN must be 0..9999");
    }
    String digits = Digits.pad(iin, Opid.IIN_DIGITS);
    byte[] ascii = new byte[digits.length()];
    for (int i = 0; i < ascii.length; i++) {
      ascii[i] = (byte) digits.charAt(i);
    }
    return ascii;
  }

  /**
   * Key check value: {@code SHA-256("OPSAMFPEKCV1" || AES-256-ECB_K(0^16))[0..16)}. It identifies
   * the key without revealing it and is committed to by the parameters digest.
   */
  public byte[] kcv() {
    requireLive();
    // shared wire contract: OPSAMFPEKCV1 key check value, byte-identical with the SAM.
    byte[] zero = new byte[16];
    byte[] encrypted = new byte[16];
    block.encryptBlock(zero, 0, encrypted, 0);
    SHA256Digest sha = new SHA256Digest();
    sha.update(KCV_DOMAIN, 0, KCV_DOMAIN.length);
    sha.update(encrypted, 0, encrypted.length);
    byte[] hash = new byte[sha.getDigestSize()];
    sha.doFinal(hash, 0);
    Arrays.fill(encrypted, (byte) 0);
    return Arrays.copyOf(hash, KCV_LENGTH);
  }

  /** Returns {@code E = FF1_K(plain, ASCII(IIII))} for {@code 0 <= plain < 10^12}. */
  public long encipher(int iin, long plain) {
    return apply(true, iin, plain);
  }

  /** Returns {@code FF1^-1_K(e, ASCII(IIII))} for {@code 0 <= e < 10^12}. */
  public long decipher(int iin, long e) {
    return apply(false, iin, e);
  }

  /**
   * Raw FF1 over {@code digits} (one value 0..9 per byte, at least 6) under {@code tweak}. Exposed
   * for the SP 800-38G sample vectors.
   */
  byte[] ff1(boolean encrypt, byte[] digits, byte[] tweak) {
    requireLive();
    FPEFF1Engine engine = new FPEFF1Engine(new BlockAdapter(block));
    // The AES key is held by the block; FPEParameters requires a key parameter, which the adapter
    // never reads.
    engine.init(
        encrypt, new FPEParameters(new KeyParameter(new byte[KEY_LENGTH]), RADIX, tweak.clone()));
    byte[] out = new byte[digits.length];
    engine.processBlock(digits, 0, digits.length, out, 0);
    return out;
  }

  /** Destroys the block (for a key in memory, overwrites it); later operations fail. */
  public void destroy() {
    block.destroy();
    destroyed = true;
  }

  private long apply(boolean encrypt, int iin, long value) {
    if (value < 0 || value >= Opid.E_MODULUS) {
      throw new IllegalArgumentException("FF1 input must have 12 digits");
    }
    byte[] input = new byte[Opid.E_DIGITS];
    Digits.toDigitValues(value, input);
    byte[] output = ff1(encrypt, input, tweak(iin));
    long result = Digits.fromDigitValues(output);
    Arrays.fill(input, (byte) 0);
    Arrays.fill(output, (byte) 0);
    return result;
  }

  private void requireLive() {
    if (destroyed) {
      throw new IllegalStateException("FF1 key has been destroyed");
    }
  }

  /**
   * Bouncy Castle {@link BlockCipher} view of an {@link AesBlock}: forward direction only. FF1 (SP
   * 800-38G section 5.1) initializes its cipher for encryption in both directions.
   */
  private static final class BlockAdapter implements BlockCipher {
    private final AesBlock block;

    BlockAdapter(AesBlock block) {
      this.block = block;
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params) {
      if (!forEncryption) {
        throw new IllegalArgumentException("FF1 uses AES in the forward direction only");
      }
    }

    @Override
    public String getAlgorithmName() {
      return "AES";
    }

    @Override
    public int getBlockSize() {
      return AesBlock.BLOCK_SIZE;
    }

    @Override
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) {
      block.encryptBlock(in, inOff, out, outOff);
      return AesBlock.BLOCK_SIZE;
    }

    @Override
    public void reset() {}
  }
}
