/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.common;

import java.math.BigInteger;
import java.util.Arrays;

/** Byte-array operations shared by host protocols and their tests. */
public final class ByteArrays {
  private ByteArrays() {}

  public static byte[] concat(byte[]... values) {
    int length = 0;
    for (byte[] value : values) {
      length = Math.addExact(length, value.length);
    }
    byte[] result = new byte[length];
    int offset = 0;
    for (byte[] value : values) {
      System.arraycopy(value, 0, result, offset, value.length);
      offset += value.length;
    }
    return result;
  }

  /** Returns an unsigned big-endian integer, padded or trimmed to exactly {@code length} bytes. */
  public static byte[] unsignedFixed(BigInteger value, int length) {
    if (length < 0) {
      throw new IllegalArgumentException("length must not be negative");
    }
    byte[] raw = value.toByteArray();
    byte[] result = new byte[length];
    int copied = Math.min(raw.length, length);
    System.arraycopy(raw, raw.length - copied, result, length - copied, copied);
    return result;
  }

  public static byte[] copyOfNullable(byte[] value) {
    return value == null ? null : Arrays.copyOf(value, value.length);
  }
}
