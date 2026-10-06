/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

import com.sun.jna.NativeLong;
import dev.mistial.tools.openfips201.crypto.AesBlock;
import java.util.Arrays;

/**
 * {@link AesBlock} over a token-resident AES key: each block is one {@code
 * C_EncryptInit(CKM_AES_ECB)} / {@code C_Encrypt} on the caller's {@link Pkcs11Session}. The key
 * never leaves the token.
 *
 * <p>Contract: usable while the session is open. {@link #destroy()} ends this view only; the token
 * object is unchanged.
 */
public final class Pkcs11AesBlock implements AesBlock {
  private final Pkcs11Session session;
  private final NativeLong key;
  private final String label;
  private boolean destroyed;

  Pkcs11AesBlock(Pkcs11Session session, NativeLong key, String label) {
    this.session = session;
    this.key = key;
    this.label = label;
  }

  @Override
  public void encryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
    if (destroyed) {
      throw new IllegalStateException("AES block view of " + label + " has been destroyed");
    }
    byte[] block = Arrays.copyOfRange(in, inOff, inOff + BLOCK_SIZE);
    byte[] result = session.token().encrypt(Pkcs11Constants.CKM_AES_ECB, key, block);
    try {
      if (result.length != BLOCK_SIZE) {
        throw new IllegalStateException("CKM_AES_ECB returned " + result.length + " bytes");
      }
      System.arraycopy(result, 0, out, outOff, BLOCK_SIZE);
    } finally {
      Arrays.fill(block, (byte) 0);
      Arrays.fill(result, (byte) 0);
    }
  }

  @Override
  public void destroy() {
    destroyed = true;
  }

  /** Label of the token key. */
  public String label() {
    return label;
  }
}
