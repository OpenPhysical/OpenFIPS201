/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import dev.mistial.tools.openfips201.common.BerTlvReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * The SAM DECIPHER response: {@code 81 04 batch (ASCII) | 82 01 sameBatch | [83 04 count (u32) | 84
 * 01 issued]}; count and issued are present only when the batch is the SAM's own. The LCG state X
 * is never returned.
 */
public final class DecipherResult {
  public final int batch;
  public final boolean sameBatch;

  /** Issuance index n with {@code f^n(x0) = X}, or -1 for another batch. */
  public final long count;

  /** Whether {@code 1 <= count <= issued} on the SAM. */
  public final boolean issued;

  DecipherResult(int batch, boolean sameBatch, long count, boolean issued) {
    this.batch = batch;
    this.sameBatch = sameBatch;
    this.count = count;
    this.issued = issued;
  }

  public static DecipherResult parse(byte[] data) {
    Integer batch = null;
    Boolean same = null;
    long count = -1;
    Boolean issued = null;
    int offset = 0;
    while (offset < data.length) {
      BerTlvReader.Tlv tlv = BerTlvReader.read(data, offset);
      byte[] value = Arrays.copyOfRange(data, tlv.valueOffset, tlv.nextOffset);
      switch (tlv.tag) {
        case 0x81:
          if (value.length != 4) {
            throw new IllegalArgumentException("DECIPHER batch must be four ASCII digits");
          }
          batch = Integer.parseInt(new String(value, StandardCharsets.US_ASCII));
          break;
        case 0x82:
          same = flag(value);
          break;
        case 0x83:
          if (value.length != 4) {
            throw new IllegalArgumentException("DECIPHER count must be four octets");
          }
          count = IssuanceCrypto.unsigned(value, 0, 4);
          break;
        case 0x84:
          issued = flag(value);
          break;
        default:
          throw new IllegalArgumentException(
              "unexpected DECIPHER tag " + Integer.toHexString(tlv.tag));
      }
      offset = tlv.nextOffset;
    }
    if (batch == null || same == null || same != (count >= 0) || same != (issued != null)) {
      throw new IllegalArgumentException("DECIPHER response is incomplete");
    }
    return new DecipherResult(batch, same, count, issued != null && issued);
  }

  private static boolean flag(byte[] value) {
    if (value.length != 1 || (value[0] != 0 && value[0] != 1)) {
      throw new IllegalArgumentException("DECIPHER flag must be 00 or 01");
    }
    return value[0] == 1;
  }

  /**
   * Requires the SAM to recognise the OPID as issuance {@code seq} of its own batch {@code
   * batchNumber}, already issued.
   */
  public void requireIssuance(int batchNumber, long seq) {
    if (!sameBatch || batch != batchNumber) {
      throw new IllegalStateException(
          "DECIPHER places the OPID in batch "
              + String.format("%04d", batch)
              + ", not in the SAM's batch "
              + String.format("%04d", batchNumber));
    }
    if (count != seq || !issued) {
      throw new IllegalStateException(
          "DECIPHER recovers issuance " + count + " (issued " + issued + "), not " + seq);
    }
  }
}
