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
    int authenticatedCurrentVersion;
    try (GlobalPlatformSession session =
        transport.openGlobalPlatformSession(GlobalPlatformSession.ISD_AID, current)) {
      authenticatedCurrentVersion = session.authenticatedKeyVersion();
      if (authenticatedCurrentVersion == derived.config.keyVersion) {
        throw new IllegalArgumentException(
            "Refusing same-version GP key rotation; choose a different target key version");
      }
      session.putKeys(derived.config.toPlaintextKeys(), replace);
    }
    try (GlobalPlatformSession ignored =
        transport.openGlobalPlatformSession(GlobalPlatformSession.ISD_AID, derived.config)) {
      // Opening SCP with the new keys is the verification step.
    }
    try (GlobalPlatformSession session =
        transport.openGlobalPlatformSession(GlobalPlatformSession.ISD_AID, derived.config)) {
      // jCardEngine retires its synthetic factory key when the first issuer keyset is added. Real
      // cards may retain the old keyset, so remove it when it is still advertised.
      if (session.hasKeyVersion(authenticatedCurrentVersion)) {
        session.deleteKeyVersion(authenticatedCurrentVersion);
      }
      if (session.hasKeyVersion(authenticatedCurrentVersion)) {
        throw new IllegalStateException(
            "Old SCP key version "
                + authenticatedCurrentVersion
                + " remains present after rotation");
      }
      if (!session.hasKeyVersion(derived.config.keyVersion)) {
        throw new IllegalStateException(
            "New SCP key version " + derived.config.keyVersion + " is missing after rotation");
      }
    }
  }
}
