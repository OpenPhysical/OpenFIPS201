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

/**
 * Adds or replaces a destination keyset, verifies it, then retires the authenticated source.
 *
 * <p>These are separate card mutations, not one transaction. Inventory-based retirement must be
 * qualified for each card platform. A failure stops the workflow without trying other credentials
 * or rolling back automatically; {@link RotationFailure} identifies the last attempted stage.
 */
public final class CardKeyRotationService {
  /** The last attempted stage. Failure does not imply that a card mutation was rolled back. */
  public enum Stage {
    INSPECT_SOURCE,
    WRITE_TARGET,
    VERIFY_TARGET,
    INSPECT_SOURCE_RETIREMENT,
    RETIRE_SOURCE,
    VERIFY_RETIREMENT
  }

  /** Non-secret recovery context; never automatically retry an authentication or key mutation. */
  public static final class RotationFailure extends Exception {
    public final Stage stage;
    public final int sourceVersion;
    public final int targetVersion;

    private RotationFailure(Stage stage, int sourceVersion, int targetVersion, Exception cause) {
      super(
          "SCP rotation stopped at "
              + stage
              + " (source version "
              + sourceVersion
              + ", target version "
              + targetVersion
              + "). Card state may have changed; inspect key inventory before recovery."
              + " Do not repeat failed authentication attempts.",
          cause);
      this.stage = stage;
      this.sourceVersion = sourceVersion;
      this.targetVersion = targetVersion;
    }
  }

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
    requireDestinationVersion(derived.config.keyVersion);
    if (current.keyVersion == derived.config.keyVersion) {
      throw new IllegalArgumentException(
          "Refusing same-version GP key rotation; choose a different target key version");
    }
    int authenticatedCurrentVersion = -1;
    Stage stage = Stage.INSPECT_SOURCE;
    try {
      boolean targetExists;
      try (GlobalPlatformSession session =
          transport.openGlobalPlatformSession(GlobalPlatformSession.ISD_AID, current)) {
        authenticatedCurrentVersion = session.authenticatedKeyVersion();
        if (authenticatedCurrentVersion == derived.config.keyVersion) {
          throw new IllegalArgumentException(
              "Refusing same-version GP key rotation; choose a different target key version");
        }
        targetExists = session.hasKeyVersion(derived.config.keyVersion);
        if (targetExists && !replace) {
          throw new IllegalArgumentException(
              "Target SCP key version already exists; explicit replacement is required");
        }
      }
      // GET DATA key inventory and PUT KEY use separate channels. Besides isolating stages,
      // this accommodates platforms whose key-info path does not advance the SCP command MCV.
      stage = Stage.WRITE_TARGET;
      try (GlobalPlatformSession session =
          transport.openGlobalPlatformSession(GlobalPlatformSession.ISD_AID, current)) {
        // GlobalPlatform Card Specification v2.3.1 Sections 11.8.2.1 and 11.8.2.3:
        // P1 identifies the existing version (00 adds); the data identifies the new version.
        // GPPro replaces the target version, not the authenticated source version. An absent
        // target must be added even when the operator permits replacement of an existing target.
        session.putKeys(derived.config.toPlaintextKeys(), targetExists);
      }
      stage = Stage.VERIFY_TARGET;
      try (GlobalPlatformSession ignored =
          transport.openGlobalPlatformSession(GlobalPlatformSession.ISD_AID, derived.config)) {
        // Opening SCP with the new keys is the verification step.
      }
      boolean oldExists;
      stage = Stage.INSPECT_SOURCE_RETIREMENT;
      try (GlobalPlatformSession session =
          transport.openGlobalPlatformSession(GlobalPlatformSession.ISD_AID, derived.config)) {
        // jCardEngine retires its synthetic factory key when the first issuer keyset is added. Real
        // cards may retain the old keyset, so remove it when it is still advertised.
        oldExists = session.hasKeyVersion(authenticatedCurrentVersion);
      }
      if (oldExists) {
        stage = Stage.RETIRE_SOURCE;
        try (GlobalPlatformSession session =
            transport.openGlobalPlatformSession(GlobalPlatformSession.ISD_AID, derived.config)) {
          session.deleteKeyVersion(authenticatedCurrentVersion);
        }
      }
      stage = Stage.VERIFY_RETIREMENT;
      try (GlobalPlatformSession session =
          transport.openGlobalPlatformSession(GlobalPlatformSession.ISD_AID, derived.config)) {
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
    } catch (IllegalArgumentException validationFailure) {
      throw validationFailure;
    } catch (Exception failure) {
      throw new RotationFailure(
          stage, authenticatedCurrentVersion, derived.config.keyVersion, failure);
    }
  }

  /** GP v2.3.1 Section 11.8.2.3 permits destination versions 01..7F, not wildcard 00. */
  static void requireDestinationVersion(int version) {
    if (version < ScpConfig.KEY_VERSION_MIN || version > ScpConfig.KEY_VERSION_MAX) {
      throw new IllegalArgumentException(
          "Rotation requires an explicit destination key version (1..127); factory/reserved"
              + " versions need a platform-specific procedure");
    }
  }
}
