/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.gp;

import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.profiles.IssuerProfile;

public final class CardKeyPreflightService {
  private final CardDiversificationDataService kddService;
  private final IssuerCardKeyService issuerKeys;

  public CardKeyPreflightService() {
    this(new CardDiversificationDataService(), new IssuerCardKeyService());
  }

  CardKeyPreflightService(
      CardDiversificationDataService kddService, IssuerCardKeyService issuerKeys) {
    this.kddService = kddService;
    this.issuerKeys = issuerKeys;
  }

  public Result preflight(Request request) throws Exception {
    if (request.current == null) {
      throw new IllegalArgumentException("current SCP keys are required");
    }
    if (!request.allowSameVersion
        && request.targetKeys == null
        && request.profile != null
        && request.current.keyVersion == request.profile.cardKeys.newKeyVersion) {
      throw new IllegalArgumentException(
          "Refusing same-version GP key rotation; choose a different target key version");
    }
    byte[] kdd = request.kdd == null ? kddService.readKdd(request.target).kdd : request.kdd.clone();
    DerivedScpKeys target = request.targetKeys;
    if (target == null) {
      if (request.profile == null) {
        throw new IllegalArgumentException("profile or target keys are required");
      }
      target = issuerKeys.deriveCardKeys(request.profile, kdd);
    }
    if (!request.allowSameVersion && request.current.keyVersion == target.config.keyVersion) {
      throw new IllegalArgumentException(
          "Refusing same-version GP key rotation; choose a different target key version");
    }
    int authenticatedVersion;
    try (GlobalPlatformSession session =
        GlobalPlatformSession.open(
            request.target, GlobalPlatformSession.ISD_AID, request.current)) {
      // Opening SCP with the current keys is the non-mutating readiness check.
      authenticatedVersion = session.authenticatedKeyVersion();
      if (!request.allowSameVersion && authenticatedVersion == target.config.keyVersion) {
        throw new IllegalArgumentException(
            "Refusing same-version GP key rotation; choose a different target key version");
      }
    }
    ScpConfig authenticated =
        new ScpConfig(
            request.current.mode,
            authenticatedVersion,
            request.current.encKey,
            request.current.macKey,
            request.current.dekKey);
    return new Result(
        kdd,
        authenticated,
        target,
        rollbackCommand(request, kdd, authenticatedVersion),
        request.stockScpKey != null);
  }

  static String rollbackCommand(Request request, byte[] kdd, int authenticatedVersion) {
    // GP v2.3.1 Section 11.8.2.3 does not define PUT KEY to wildcard 00 or reserved
    // factory versions. Do not print a recovery command that cannot safely perform that roll.
    if (request.profilePath == null
        || authenticatedVersion < ScpConfig.KEY_VERSION_MIN
        || authenticatedVersion > ScpConfig.KEY_VERSION_MAX) {
      return null;
    }
    return "openfips201 gp keys keyroll backward --profile "
        + request.profilePath
        + " --target "
        + request.target.displayName()
        + " --kdd "
        + HexUtil.format(kdd)
        + " --stock-scp-key-version "
        + authenticatedVersion
        + " --yes";
  }

  public static final class Request {
    public CardTarget target;
    public ScpConfig current;
    public IssuerProfile profile;
    public String profilePath;
    public byte[] kdd;
    public DerivedScpKeys targetKeys;
    public String stockScpKey;
    public boolean allowSameVersion;
  }

  public static final class Result {
    public final byte[] kdd;
    public final String kddHex;
    public final int currentKeyVersion;
    public final int targetKeyVersion;
    public final String targetEncKcv;
    public final String targetMacKcv;
    public final String targetDekKcv;
    public final String rollbackCommand;
    public final boolean rollbackRequiresStockScpKey;
    public final String rollbackUnavailableReason;

    Result(
        byte[] kdd,
        ScpConfig current,
        DerivedScpKeys target,
        String rollbackCommand,
        boolean rollbackRequiresStockScpKey) {
      this.kdd = kdd.clone();
      this.kddHex = HexUtil.format(kdd);
      this.currentKeyVersion = current.keyVersion;
      this.targetKeyVersion = target.config.keyVersion;
      this.targetEncKcv = target.encKcv;
      this.targetMacKcv = target.macKcv;
      this.targetDekKcv = target.dekKcv;
      this.rollbackCommand = rollbackCommand;
      this.rollbackRequiresStockScpKey = rollbackRequiresStockScpKey;
      this.rollbackUnavailableReason =
          current.keyVersion < ScpConfig.KEY_VERSION_MIN
                  || current.keyVersion > ScpConfig.KEY_VERSION_MAX
              ? "Restoring the authenticated factory/reserved key version requires a"
                  + " platform-specific procedure"
              : null;
    }
  }
}
