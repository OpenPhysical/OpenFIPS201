/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.vci;

final class BerTlvReader {
  private BerTlvReader() {}

  static Tlv read(byte[] data, int offset) {
    return read(data, offset, data.length);
  }

  static Tlv read(byte[] data, int offset, int limit) {
    if (data == null) {
      throw new IllegalArgumentException("TLV data is null");
    }
    if (offset < 0 || offset >= limit || limit > data.length) {
      throw new IllegalArgumentException("TLV offset out of bounds");
    }

    int tagOffset = offset;
    int cursor = offset;
    int first = data[cursor++] & 0xFF;
    int tag = first;
    if ((first & 0x1F) == 0x1F) {
      tag = first;
      int tagBytes = 1;
      int next;
      do {
        if (cursor >= limit) {
          throw new IllegalArgumentException("truncated multi-byte TLV tag");
        }
        if (++tagBytes > 4) {
          throw new IllegalArgumentException("unsupported TLV tag form");
        }
        next = data[cursor++] & 0xFF;
        tag = (tag << 8) | next;
      } while ((next & 0x80) != 0);
    }

    if (cursor >= limit) {
      throw new IllegalArgumentException("missing TLV length");
    }
    int lengthByte = data[cursor++] & 0xFF;
    int length;
    if (lengthByte < 0x80) {
      length = lengthByte;
    } else if (lengthByte == 0x81) {
      if (cursor >= limit) {
        throw new IllegalArgumentException("truncated 0x81 TLV length");
      }
      length = data[cursor++] & 0xFF;
    } else if (lengthByte == 0x82) {
      if (cursor + 1 >= limit) {
        throw new IllegalArgumentException("truncated 0x82 TLV length");
      }
      length = ((data[cursor++] & 0xFF) << 8) | (data[cursor++] & 0xFF);
    } else {
      throw new IllegalArgumentException("unsupported TLV length form");
    }

    int valueOffset = cursor;
    int nextOffset = valueOffset + length;
    if (nextOffset < valueOffset || nextOffset > limit) {
      throw new IllegalArgumentException("TLV length exceeds enclosing object");
    }
    return new Tlv(tagOffset, tag, valueOffset, length, nextOffset);
  }

  static Tlv locate(byte[] data, int offset, int tag) {
    int cursor = offset;
    while (cursor < data.length) {
      Tlv tlv = read(data, cursor);
      if (tlv.tag == tag) {
        return tlv;
      }
      cursor = tlv.nextOffset;
    }
    return null;
  }

  static final class Tlv {
    final int tagOffset;
    final int tag;
    final int valueOffset;
    final int length;
    final int nextOffset;

    Tlv(int tagOffset, int tag, int valueOffset, int length, int nextOffset) {
      this.tagOffset = tagOffset;
      this.tag = tag;
      this.valueOffset = valueOffset;
      this.length = length;
      this.nextOffset = nextOffset;
    }
  }
}
