/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.gp;

import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.ScpConfig;
import java.util.Arrays;
import pro.javacard.gp.GPCardKeys;

public final class DerivedScpKeys {
  public final ScpConfig config;
  public final String encKcv;
  public final String macKcv;
  public final String dekKcv;

  public static DerivedScpKeys fromConfig(ScpConfig config) {
    return new DerivedScpKeys(
        config,
        HexUtil.format(slice(config.toPlaintextKeys().kcv(GPCardKeys.KeyPurpose.ENC), 0, 3)),
        HexUtil.format(slice(config.toPlaintextKeys().kcv(GPCardKeys.KeyPurpose.MAC), 0, 3)),
        HexUtil.format(slice(config.toPlaintextKeys().kcv(GPCardKeys.KeyPurpose.DEK), 0, 3)));
  }

  DerivedScpKeys(ScpConfig config, String encKcv, String macKcv, String dekKcv) {
    this.config = config;
    this.encKcv = encKcv;
    this.macKcv = macKcv;
    this.dekKcv = dekKcv;
  }

  private static byte[] slice(byte[] value, int offset, int length) {
    return Arrays.copyOfRange(value, offset, offset + length);
  }
}
