/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.crypto;

/**
 * One AES key used only in the forward (encrypt) direction, one 16-byte block at a time: {@code out
 * = AES-ECB_K(in)}.
 *
 * <p>Contract: the key is held by the implementation (in memory, or as a token object) and is never
 * returned. {@link #destroy()} releases it; later calls fail.
 */
public interface AesBlock {
  int BLOCK_SIZE = 16;

  /** Writes {@code AES_K(in[inOff..inOff+16))} to {@code out[outOff..outOff+16)}. */
  void encryptBlock(byte[] in, int inOff, byte[] out, int outOff);

  /** Releases the key. */
  void destroy();
}
