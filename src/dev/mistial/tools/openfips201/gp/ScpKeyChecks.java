/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.gp;

import dev.mistial.tools.openfips201.common.HexUtil;
import java.util.Arrays;
import pro.javacard.gp.GPCrypto;

/** Key check values for SCP static keys. */
public final class ScpKeyChecks {
  /** Algorithm label recorded with a {@link #kcvAes(byte[])} value. */
  public static final String KCV_ALGORITHM_GP_B6_AES = "gp-b6-aes";

  private static final int KCV_LENGTH = 3;

  private ScpKeyChecks() {}

  /**
   * GP Card Specification v2.3.1 Section B.6: "For a AES key, the key check value is computed by
   * encrypting 16 bytes, each with value '01', with the key to be checked and retaining the 3
   * highest-order bytes of the encrypted result."
   *
   * @return the 3-byte KCV as upper-case hex
   */
  public static String kcvAes(byte[] key) {
    byte[] block = GPCrypto.kcv_aes(key);
    try {
      return HexUtil.format(Arrays.copyOf(block, KCV_LENGTH));
    } finally {
      Arrays.fill(block, (byte) 0);
    }
  }

  /**
   * The value recorded by batches created before {@link #KCV_ALGORITHM_GP_B6_AES}: the first 3
   * bytes of AES-ECB over 16 zero bytes. Used only to check a legacy {@code batch.json}.
   *
   * @return the 3-byte value as upper-case hex
   */
  public static String legacyZeroBlockKcv(byte[] key) {
    byte[] block = GPCrypto.kcv_aes0(key);
    try {
      return HexUtil.format(Arrays.copyOf(block, KCV_LENGTH));
    } finally {
      Arrays.fill(block, (byte) 0);
    }
  }
}
