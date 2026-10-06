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

  // SP 800-73-5 Part 2 Table 18 fixes the compiled suite: CS2 uses "ECDH (Curve P-256)", "AES
  // 128" session keys and a "16 bytes" N_ICC; CS7 uses "ECDH (Curve P-384)", "AES 256" and "24
  // bytes". The OPACITY establishment and its KDA self-test both use these values.
  // #if VCI_CS2
  static final short FIELD_LENGTH = (short) 32;
  // #else
  static final short FIELD_LENGTH = (short) 48;
  // #endif
  static final short SESSION_KEY_LENGTH = (short) (FIELD_LENGTH - (short) 16);
  // Equal to ECPointValidator.encodedLength(FIELD_LENGTH), the single definition of the
  // uncompressed encoding. The Java Card converter accepts only constant initializers in a static
  // initializer, so the value is written as the compile-time constant that method returns.
  static final short POINT_LENGTH = (short) (FIELD_LENGTH * (short) 2 + (short) 1);
  static final short NONCE_LENGTH = (short) (FIELD_LENGTH / (short) 2);

  // Workspace layout shared by establishment and self-test: ID_sH(8) || Q_eH || Z || N_ICC ||
  // ID_sICC(8).
  static final short OFFSET_ID_H = ZERO;
  static final short OFFSET_Q_EH = (short) 8;
  static final short OFFSET_Z = (short) (OFFSET_Q_EH + POINT_LENGTH);
  static final short OFFSET_N = (short) (OFFSET_Z + FIELD_LENGTH);
  static final short OFFSET_ID_SICC = (short) (OFFSET_N + NONCE_LENGTH);

  // #if FIPS_MODE
  // #if VCI_CS2
  private static final byte[] KDA_EXPECTED = {
    (byte) 0xA4, (byte) 0x28, (byte) 0xFA, (byte) 0x53,
    (byte) 0x1C, (byte) 0x7C, (byte) 0xA5, (byte) 0x02,
    (byte) 0xFD, (byte) 0xD1, (byte) 0xCD, (byte) 0xE6,
    (byte) 0x9B, (byte) 0x23, (byte) 0x35, (byte) 0x1C,
    (byte) 0xCB, (byte) 0xF7, (byte) 0x2D, (byte) 0xF2,
    (byte) 0x15, (byte) 0x0F, (byte) 0xE8, (byte) 0xA7,
    (byte) 0x91, (byte) 0x8B, (byte) 0xF5, (byte) 0xCD,
    (byte) 0x39, (byte) 0x83, (byte) 0xB5, (byte) 0xA3,
    (byte) 0x57, (byte) 0xEB, (byte) 0x63, (byte) 0xF2,
    (byte) 0xFD, (byte) 0xF2, (byte) 0x92, (byte) 0x08,
    (byte) 0x7B, (byte) 0x4D, (byte) 0x55, (byte) 0x39,
    (byte) 0xEF, (byte) 0xA9, (byte) 0x1D, (byte) 0x9F,
    (byte) 0xFB, (byte) 0x10, (byte) 0x74, (byte) 0xB2,
    (byte) 0xA6, (byte) 0x64, (byte) 0xE0, (byte) 0x17,
    (byte) 0x7E, (byte) 0x3C, (byte) 0x93, (byte) 0x10,
    (byte) 0x48, (byte) 0xB3, (byte) 0xAB, (byte) 0x88
  };
  // #else
  private static final byte[] KDA_EXPECTED = {
    (byte) 0x99, (byte) 0xFA, (byte) 0x8E, (byte) 0x49,
    (byte) 0xA7, (byte) 0x01, (byte) 0x04, (byte) 0x86,
    (byte) 0x11, (byte) 0xBA, (byte) 0x54, (byte) 0x5C,
    (byte) 0x0B, (byte) 0x94, (byte) 0xA5, (byte) 0x92,
    (byte) 0xBB, (byte) 0x6A, (byte) 0xC7, (byte) 0xB8,
    (byte) 0x12, (byte) 0x65, (byte) 0x47, (byte) 0xD2,
    (byte) 0x63, (byte) 0xB4, (byte) 0x30, (byte) 0x47,
    (byte) 0xBD, (byte) 0x9B, (byte) 0x46, (byte) 0x17,
    (byte) 0x44, (byte) 0xE1, (byte) 0x36, (byte) 0x38,
    (byte) 0xC4, (byte) 0x19, (byte) 0x55, (byte) 0x5B,
    (byte) 0xCE, (byte) 0x5D, (byte) 0x9A, (byte) 0xD9,
    (byte) 0x4B, (byte) 0xA9, (byte) 0x44, (byte) 0xE2,
    (byte) 0x7C, (byte) 0xC0, (byte) 0x50, (byte) 0x13,
    (byte) 0xC8, (byte) 0x3C, (byte) 0xDA, (byte) 0xD9,
    (byte) 0xC5, (byte) 0x1D, (byte) 0xAF, (byte) 0x0F,
    (byte) 0x44, (byte) 0x0F, (byte) 0x74, (byte) 0x84,
    (byte) 0x15, (byte) 0x15, (byte) 0xFE, (byte) 0x6F,
    (byte) 0x7C, (byte) 0x2D, (byte) 0xCE, (byte) 0xFA,
    (byte) 0x79, (byte) 0x70, (byte) 0xCD, (byte) 0x26,
    (byte) 0x67, (byte) 0x81, (byte) 0x0C, (byte) 0xA8,
    (byte) 0x31, (byte) 0x53, (byte) 0x50, (byte) 0xDA,
    (byte) 0x1D, (byte) 0x9E, (byte) 0x67, (byte) 0x58,
    (byte) 0x11, (byte) 0x12, (byte) 0xD6, (byte) 0x56,
    (byte) 0xE0, (byte) 0xCA, (byte) 0xA0, (byte) 0x25,
    (byte) 0x1F, (byte) 0x7C, (byte) 0xAE, (byte) 0xE8,
    (byte) 0xC8, (byte) 0x7D, (byte) 0x34, (byte) 0x2B,
    (byte) 0x22, (byte) 0x2A, (byte) 0xD6, (byte) 0xD0,
    (byte) 0x69, (byte) 0xEF, (byte) 0x8A, (byte) 0xE0,
    (byte) 0x66, (byte) 0x01, (byte) 0x3D, (byte) 0x71,
    (byte) 0x29, (byte) 0x59, (byte) 0xAF, (byte) 0x7F,
    (byte) 0x7D, (byte) 0x63, (byte) 0x6E, (byte) 0xF2,
    (byte) 0x29, (byte) 0xFB, (byte) 0xAE, (byte) 0xD2
  };
  // #endif
  // #endif

  private final PIVCrypto crypto;
  private final byte[] output;
  private final byte[] workspace;

  PIVOpacity(PIVCrypto crypto, byte[] output, byte[] workspace) {
    this.crypto = crypto;
    this.output = output;
    this.workspace = workspace;
  }

  // #if FIPS_MODE
  /**
   * Runs the compiled suite's SP 800-56C one-step KDA known-answer test.
   *
   * <p>FIPS 140-3 IG 10.3.A Resolution 8 requires a CAST for an implemented KDA. This exercises the
   * complete OPACITY FixedInfo construction, counter processing, suite hash and truncation.
   */
  boolean runCryptographicAlgorithmSelfTest() {
    Util.arrayFillNonAtomic(output, ZERO, (short) output.length, (byte) 0);
    Util.arrayFillNonAtomic(workspace, ZERO, (short) workspace.length, (byte) 0);
    try {
      fillSequence(workspace, OFFSET_ID_H, (short) 8, (byte) 0x10);
      workspace[OFFSET_Q_EH] = (byte) 0x04;
      fillSequence(workspace, (short) (OFFSET_Q_EH + 1), (short) (POINT_LENGTH - 1), (byte) 0x21);
      fillSequence(workspace, OFFSET_Z, FIELD_LENGTH, (byte) 0x40);
      fillSequence(workspace, OFFSET_N, NONCE_LENGTH, (byte) 0x70);
      fillSequence(workspace, OFFSET_ID_SICC, (short) 8, (byte) 0x30);

      deriveSuiteSessionKeys((byte) 0x00);
      return PIVSecurityProvider.arrayEqualsConstantTime(
          output, ZERO, KDA_EXPECTED, ZERO, (short) KDA_EXPECTED.length);
    } finally {
      PIVSecurityProvider.zeroise(output, ZERO, (short) output.length);
      PIVSecurityProvider.zeroise(workspace, ZERO, (short) workspace.length);
    }
  }

  private static void fillSequence(byte[] buffer, short offset, short length, byte firstValue) {
    for (short index = ZERO; index < length; index++) {
      buffer[(short) (offset + index)] = (byte) (firstValue + (byte) index);
    }
  }
  // #endif

  /**
   * Derives the compiled suite's session keys from the shared workspace layout ({@link
   * #OFFSET_ID_H}, {@link #OFFSET_Q_EH}, {@link #OFFSET_Z}, {@link #OFFSET_N}, {@link
   * #OFFSET_ID_SICC}) with {@link PIV#OPACITY_KDF_ALG_ID} and {@link PIV#OPACITY_HASH_TMP}. This is
   * the only derivation entry point for OPACITY establishment and for its known-answer test.
   */
  void deriveSuiteSessionKeys(byte hostControlByte) {
    deriveSessionKeys(
        FIELD_LENGTH,
        SESSION_KEY_LENGTH,
        PIV.OPACITY_KDF_ALG_ID,
        PIV.OPACITY_HASH_TMP,
        OFFSET_Z,
        OFFSET_N,
        NONCE_LENGTH,
        OFFSET_ID_H,
        OFFSET_Q_EH,
        OFFSET_ID_SICC,
        hostControlByte);
  }

  /**
   * Derives SK_CFRM || SK_MAC || SK_ENC || SK_RMAC into {@code output} (SP 800-73-5 Part 2 Section
   * 4.1.6).
   *
   * @param hostControlByte CB_H as received from the client application; OtherInfo carries it
   *     verbatim ("0x01 || CB_H") while CB_ICC is always 0x00 (Table 16 steps C2 and C3)
   */
  private void deriveSessionKeys(
      short hashLength,
      short sessionKeyLength,
      byte algorithmId,
      short hashOffset,
      short zOffset,
      short nonceOffset,
      short nonceLength,
      short hostIdOffset,
      short hostPointOffset,
      short cardIdOffset,
      byte hostControlByte) {
    short outputLength = (short) (sessionKeyLength * 4);
    short written = ZERO;
    try {
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
                cardIdOffset,
                hostControlByte);
        crypto.doSha(hashLength, output, KDF_INPUT_OFFSET, inputLength, workspace, hashOffset);
        short copyLength = hashLength;
        if ((short) (written + copyLength) > outputLength) {
          copyLength = (short) (outputLength - written);
        }
        Util.arrayCopyNonAtomic(workspace, hashOffset, output, written, copyLength);
        written += copyLength;
      }
    } finally {
      // SP 800-73-5 Part 2 Section 4.1, Case 1A uses Z only as KDF input. buildKdfInput()
      // copies Z above the derived-key region, so clear that transient copy on success and error.
      PIVSecurityProvider.zeroise(
          output, KDF_INPUT_OFFSET, (short) (output.length - KDF_INPUT_OFFSET));
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
      short cardIdOffset,
      byte hostControlByte) {
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
    output[offset++] = hostControlByte;
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
