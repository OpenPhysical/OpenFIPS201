/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.gp;

import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.profiles.IssuerProfile;

public final class CardKeyRollService {
  public enum Direction {
    FORWARD,
    BACKWARD
  }

  private final CardDiversificationDataService kddService;
  private final IssuerCardKeyService issuerKeys;
  private final CardKeyRotationService rotation;
  private final CardKeyPreflightService preflight;

  public CardKeyRollService() {
    this(
        new CardDiversificationDataService(),
        new IssuerCardKeyService(),
        new CardKeyRotationService(),
        new CardKeyPreflightService());
  }

  CardKeyRollService(
      CardDiversificationDataService kddService,
      IssuerCardKeyService issuerKeys,
      CardKeyRotationService rotation,
      CardKeyPreflightService preflight) {
    this.kddService = kddService;
    this.issuerKeys = issuerKeys;
    this.rotation = rotation;
    this.preflight = preflight;
  }

  public Result roll(Request request) throws Exception {
    if (!request.yes && !request.target.isZmq()) {
      throw new IllegalArgumentException("gp keys keyroll requires --yes for physical cards");
    }
    byte[] kdd =
        request.kdd == null ? kddService.readKdd(request.target).kdd : request.kdd.clone();
    ScpConfig stock = request.stockScpOverride == null
        ? issuerKeys.stockScp(request.profile)
        : request.stockScpOverride;
    DerivedScpKeys profileKeys = issuerKeys.deriveCardKeys(request.profile, kdd);

    ScpConfig current;
    DerivedScpKeys target;
    if (request.direction == Direction.FORWARD) {
      current = stock;
      target = profileKeys;
    } else {
      current = profileKeys.config;
      target = DerivedScpKeys.fromConfig(stock);
    }

    CardKeyPreflightService.Request preflightRequest = new CardKeyPreflightService.Request();
    preflightRequest.target = request.target;
    preflightRequest.current = current;
    preflightRequest.targetKeys = target;
    preflightRequest.kdd = kdd;
    preflight.preflight(preflightRequest);
    rotation.rotate(request.target, current, target, true);
    return new Result(request.direction, kdd, current.keyVersion, target.config.keyVersion, target);
  }

  public static final class Request {
    public CardTarget target;
    public IssuerProfile profile;
    public Direction direction;
    public byte[] kdd;
    public ScpConfig stockScpOverride;
    public boolean yes;
  }

  public static final class Result {
    public final Direction direction;
    public final byte[] kdd;
    public final int currentKeyVersion;
    public final int targetKeyVersion;
    public final DerivedScpKeys targetKeys;

    Result(
        Direction direction,
        byte[] kdd,
        int currentKeyVersion,
        int targetKeyVersion,
        DerivedScpKeys targetKeys) {
      this.direction = direction;
      this.kdd = kdd.clone();
      this.currentKeyVersion = currentKeyVersion;
      this.targetKeyVersion = targetKeyVersion;
      this.targetKeys = targetKeys;
    }
  }
}
