/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.gp;

import dev.mistial.tools.openfips201.common.ScpConfig;

public final class DerivedScpKeys {
  public final ScpConfig config;
  public final String encKcv;
  public final String macKcv;
  public final String dekKcv;

  DerivedScpKeys(ScpConfig config, String encKcv, String macKcv, String dekKcv) {
    this.config = config;
    this.encKcv = encKcv;
    this.macKcv = macKcv;
    this.dekKcv = dekKcv;
  }
}
