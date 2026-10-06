/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.crypto;

import java.util.Arrays;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * {@link AesBlock} over a key held in memory (Bouncy Castle AES). The instance owns a copy of the
 * key; {@link #destroy()} overwrites it.
 */
public final class BcAesBlock implements AesBlock {
  private final byte[] key;
  private final BlockCipher aes = AESEngine.newInstance();
  private boolean destroyed;

  /** Copies {@code key} (16, 24 or 32 bytes). */
  public BcAesBlock(byte[] key) {
    if (key == null || (key.length != 16 && key.length != 24 && key.length != 32)) {
      throw new IllegalArgumentException("AES key must be 16, 24 or 32 bytes");
    }
    this.key = key.clone();
    aes.init(true, new KeyParameter(this.key));
  }

  @Override
  public void encryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
    if (destroyed) {
      throw new IllegalStateException("AES key has been destroyed");
    }
    aes.processBlock(in, inOff, out, outOff);
  }

  @Override
  public void destroy() {
    Arrays.fill(key, (byte) 0);
    aes.reset();
    aes.init(true, new KeyParameter(new byte[key.length]));
    destroyed = true;
  }
}
