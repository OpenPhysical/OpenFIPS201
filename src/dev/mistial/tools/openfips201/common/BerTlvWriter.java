/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.common;

import java.io.ByteArrayOutputStream;

/** Encodes the definite-length BER-TLV subset used by PIV host commands. */
public final class BerTlvWriter {
  private BerTlvWriter() {}

  public static byte[] encode(int tag, byte[] value) {
    if (value == null) {
      throw new IllegalArgumentException("TLV value is required");
    }
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    append(output, tag, value);
    return output.toByteArray();
  }

  public static void append(ByteArrayOutputStream output, int tag, byte[] value) {
    if (output == null) {
      throw new IllegalArgumentException("TLV output is required");
    }
    if (value == null) {
      throw new IllegalArgumentException("TLV value is required");
    }
    writeTag(output, tag);
    writeLength(output, value.length);
    output.write(value, 0, value.length);
  }

  private static void writeTag(ByteArrayOutputStream output, int tag) {
    if (tag < 0 || tag > 0xFFFFFF) {
      throw new IllegalArgumentException("Unsupported TLV tag: " + Integer.toHexString(tag));
    }
    if (tag > 0xFFFF) {
      output.write((tag >>> 16) & 0xFF);
    }
    if (tag > 0xFF) {
      output.write((tag >>> 8) & 0xFF);
    }
    output.write(tag & 0xFF);
  }

  private static void writeLength(ByteArrayOutputStream output, int length) {
    if (length < 0x80) {
      output.write(length);
    } else if (length <= 0xFF) {
      output.write(0x81);
      output.write(length);
    } else if (length <= 0xFFFF) {
      output.write(0x82);
      output.write(length >>> 8);
      output.write(length);
    } else {
      throw new IllegalArgumentException("TLV value too large: " + length);
    }
  }
}
