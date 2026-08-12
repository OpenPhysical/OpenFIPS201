/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.gp;

import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.CardTransport;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.common.ScpConfig;

public final class CardKeyRotationService {
  public void rotate(CardTarget target, ScpConfig current, DerivedScpKeys derived)
      throws Exception {
    rotate(target, current, derived, false);
  }

  public void rotate(CardTarget target, ScpConfig current, DerivedScpKeys derived, boolean replace)
      throws Exception {
    try (CardTransport transport = target.openTransport()) {
      rotate(transport, current, derived, replace);
    }
  }

  public void rotate(
      CardTransport transport, ScpConfig current, DerivedScpKeys derived, boolean replace)
      throws Exception {
    if (current.keyVersion == derived.config.keyVersion) {
      throw new IllegalArgumentException(
          "Refusing same-version GP key rotation; choose a different target key version");
    }
    try (GlobalPlatformSession session =
        transport.openGlobalPlatformSession(GlobalPlatformSession.ISD_AID, current)) {
      session.putKeys(derived.config.toPlaintextKeys(), replace);
    }
    try (GlobalPlatformSession ignored =
        transport.openGlobalPlatformSession(GlobalPlatformSession.ISD_AID, derived.config)) {
      // Opening SCP with the new keys is the verification step.
    }
  }
}
