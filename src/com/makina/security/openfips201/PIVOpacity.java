/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2017 Commonwealth of Australia
 ******************************************************************************/

package com.makina.security.openfips201;

import javacard.framework.Util;

/** No-allocation OPACITY KDF and key-confirmation input constructions. */
final class PIVOpacity {
  private static final short ZERO = (short) 0;
  private static final short KDF_INPUT_OFFSET = (short) 128;

  private final byte[] output;
  private final byte[] workspace;

  PIVOpacity(byte[] output, byte[] workspace) {
    this.output = output;
    this.workspace = workspace;
  }

  void deriveSessionKeys(
      short hashLength,
      short sessionKeyLength,
      byte algorithmId,
      short hashOffset,
      short zOffset,
      short nonceOffset,
      short nonceLength,
      short hostIdOffset,
      short hostPointOffset,
      short cardIdOffset) {
    short outputLength = (short) (sessionKeyLength * 4);
    short written = ZERO;
    for (byte counter = (byte) 1; written < outputLength; counter++) {
      short inputLength =
          buildKdfInput(
              KDF_INPUT_OFFSET,
              counter,
              algorithmId,
              zOffset,
              hashLength,
              nonceOffset,
              nonceLength,
              hostIdOffset,
              hostPointOffset,
              cardIdOffset);
      PIVCrypto.doSha(
          hashLength, output, KDF_INPUT_OFFSET, inputLength, workspace, hashOffset);
      short copyLength = hashLength;
      if ((short) (written + copyLength) > outputLength) {
        copyLength = (short) (outputLength - written);
      }
      Util.arrayCopyNonAtomic(workspace, hashOffset, output, written, copyLength);
      written += copyLength;
    }
  }

  short buildConfirmationInput(
      short hostIdOffset, short hostPointOffset, short cardIdOffset, short coordinateLength) {
    short offset = ZERO;
    output[offset++] = (byte) 0x4B;
    output[offset++] = (byte) 0x43;
    output[offset++] = (byte) 0x5F;
    output[offset++] = (byte) 0x31;
    output[offset++] = (byte) 0x5F;
    output[offset++] = (byte) 0x56;
    offset = Util.arrayCopyNonAtomic(workspace, cardIdOffset, output, offset, (short) 8);
    offset = Util.arrayCopyNonAtomic(workspace, hostIdOffset, output, offset, (short) 8);
    offset =
        Util.arrayCopyNonAtomic(
            workspace, (short) (hostPointOffset + 1), output, offset, coordinateLength);
    return offset;
  }

  private short buildKdfInput(
      short base,
      byte counter,
      byte algorithmId,
      short zOffset,
      short zLength,
      short nonceOffset,
      short nonceLength,
      short hostIdOffset,
      short hostPointOffset,
      short cardIdOffset) {
    short offset = base;
    output[offset++] = (byte) 0;
    output[offset++] = (byte) 0;
    output[offset++] = (byte) 0;
    output[offset++] = counter;
    offset = Util.arrayCopyNonAtomic(workspace, zOffset, output, offset, zLength);
    output[offset++] = (byte) 0x04;
    output[offset++] = algorithmId;
    output[offset++] = algorithmId;
    output[offset++] = algorithmId;
    output[offset++] = algorithmId;
    output[offset++] = (byte) 0x08;
    offset = Util.arrayCopyNonAtomic(workspace, hostIdOffset, output, offset, (short) 8);
    output[offset++] = (byte) 0x01;
    output[offset++] = (byte) 0x00;
    output[offset++] = (byte) 0x10;
    offset =
        Util.arrayCopyNonAtomic(
            workspace, (short) (hostPointOffset + 1), output, offset, (short) 16);
    output[offset++] = (byte) 0x08;
    offset = Util.arrayCopyNonAtomic(workspace, cardIdOffset, output, offset, (short) 8);
    output[offset++] = (byte) nonceLength;
    offset = Util.arrayCopyNonAtomic(workspace, nonceOffset, output, offset, nonceLength);
    output[offset++] = (byte) 0x01;
    output[offset++] = (byte) 0x00;
    return (short) (offset - base);
  }
}
