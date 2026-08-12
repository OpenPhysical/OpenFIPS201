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

  CardKeyPreflightService(CardDiversificationDataService kddService, IssuerCardKeyService issuerKeys) {
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
    byte[] kdd =
        request.kdd == null ? kddService.readKdd(request.target).kdd : request.kdd.clone();
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
    try (GlobalPlatformSession ignored =
        GlobalPlatformSession.open(request.target, GlobalPlatformSession.ISD_AID, request.current)) {
      // Opening SCP with the current keys is the non-mutating readiness check.
    }
    return new Result(kdd, request.current, target, rollbackCommand(request, kdd));
  }

  private static String rollbackCommand(Request request, byte[] kdd) {
    if (request.profilePath == null || request.stockScpKey == null) {
      return null;
    }
    return "openfips201 gp keys keyroll backward --profile "
        + request.profilePath
        + " --target "
        + request.target.displayName()
        + " --kdd "
        + HexUtil.format(kdd)
        + " --stock-scp-key-version "
        + request.current.keyVersion
        + " --stock-scp-key "
        + request.stockScpKey
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

    Result(byte[] kdd, ScpConfig current, DerivedScpKeys target, String rollbackCommand) {
      this.kdd = kdd.clone();
      this.kddHex = HexUtil.format(kdd);
      this.currentKeyVersion = current.keyVersion;
      this.targetKeyVersion = target.config.keyVersion;
      this.targetEncKcv = target.encKcv;
      this.targetMacKcv = target.macKcv;
      this.targetDekKcv = target.dekKcv;
      this.rollbackCommand = rollbackCommand;
    }
  }
}
