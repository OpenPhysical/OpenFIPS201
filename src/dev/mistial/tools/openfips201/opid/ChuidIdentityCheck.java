/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.opid;

import dev.mistial.tools.openfips201.common.BerTlvReader;
import java.util.Arrays;

/**
 * Checks that a CHUID carries the identifiers derived from an OPID.
 *
 * <p>SP 800-73-5 Part 1 Table 9: tag 0x30 is the 25-byte FASC-N and tag 0x34 the 16-byte GUID. Each
 * must appear exactly once and equal {@link OpidIdentifiers#fascNBytes} and {@link
 * OpidIdentifiers#guidBytes} respectively. Other CHUID elements are skipped.
 *
 * <p>The FASC-N comparison is byte-exact, so it also requires Person/Organization Association
 * Category 6 ({@link OpidIdentifiers#FASCN_PERSON_ASSOCIATION}).
 */
public final class ChuidIdentityCheck {
  private static final int TAG_DATA_OBJECT = 0x53;
  private static final int TAG_FASCN = 0x30;
  private static final int TAG_GUID = 0x34;
  private static final int GUID_LENGTH = 16;

  private ChuidIdentityCheck() {}

  /**
   * Verifies {@code chuidValue} against {@code opid}. {@code chuidValue} is the CHUID element list;
   * a value wrapped in a single 0x53 data object is unwrapped first.
   *
   * @throws IllegalArgumentException when the TLV structure is malformed, a required element is
   *     missing or duplicated, or the FASC-N or GUID differs from the value derived from the OPID
   */
  public static void verify(byte[] chuidValue, Opid opid) {
    if (chuidValue == null || chuidValue.length == 0) {
      throw new IllegalArgumentException("CHUID value is empty");
    }
    if (opid == null) {
      throw new IllegalArgumentException("OPID is required");
    }
    int offset = 0;
    int limit = chuidValue.length;
    if ((chuidValue[0] & 0xFF) == TAG_DATA_OBJECT) {
      BerTlvReader.Tlv wrapper = BerTlvReader.read(chuidValue, 0);
      if (wrapper.nextOffset != chuidValue.length) {
        throw new IllegalArgumentException("CHUID data object has trailing bytes");
      }
      offset = wrapper.valueOffset;
      limit = wrapper.valueOffset + wrapper.length;
    }
    byte[] fascN = null;
    byte[] guid = null;
    int cursor = offset;
    while (cursor < limit) {
      BerTlvReader.Tlv tlv = BerTlvReader.read(chuidValue, cursor, limit);
      if (tlv.tag == TAG_FASCN) {
        if (fascN != null) {
          throw new IllegalArgumentException("CHUID contains more than one FASC-N");
        }
        fascN = Arrays.copyOfRange(chuidValue, tlv.valueOffset, tlv.valueOffset + tlv.length);
      } else if (tlv.tag == TAG_GUID) {
        if (guid != null) {
          throw new IllegalArgumentException("CHUID contains more than one GUID");
        }
        guid = Arrays.copyOfRange(chuidValue, tlv.valueOffset, tlv.valueOffset + tlv.length);
      }
      cursor = tlv.nextOffset;
    }
    if (fascN == null) {
      throw new IllegalArgumentException("CHUID has no FASC-N (tag 30)");
    }
    if (guid == null) {
      throw new IllegalArgumentException("CHUID has no GUID (tag 34)");
    }
    if (fascN.length != FascNCodec.LENGTH) {
      throw new IllegalArgumentException("CHUID FASC-N must be " + FascNCodec.LENGTH + " bytes");
    }
    if (guid.length != GUID_LENGTH) {
      throw new IllegalArgumentException("CHUID GUID must be " + GUID_LENGTH + " bytes");
    }
    FascNCodec.decode(fascN);
    if (!Arrays.equals(fascN, OpidIdentifiers.fascNBytes(opid))) {
      throw new IllegalArgumentException("CHUID FASC-N does not match OPID " + opid);
    }
    if (!Arrays.equals(guid, OpidIdentifiers.guidBytes(opid))) {
      throw new IllegalArgumentException("CHUID GUID does not match OPID " + opid);
    }
  }
}
