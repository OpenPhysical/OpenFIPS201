/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import java.io.IOException;
import java.security.cert.X509Certificate;

/**
 * The production station's key custody: the card-master key and the station handoff key, plus the
 * root station's public certificate. It holds no root key, no FF1 key and no LCG parameters.
 */
public interface Custody {
  /** The root station's certificate ({@code root.pem}), public only. */
  X509Certificate rootCertificate();

  /** Derives card and SAM issuer SCP keys from their KDD. */
  ScpKeyDeriver keyDeriver();

  /** The station handoff key's public point (created on first use). */
  byte[] stationPoint() throws Exception;

  /**
   * Unwraps a handoff secret wrapped to the station key under {@code ephemeralPub} with {@code
   * sharedInfo}; the caller wipes the result.
   */
  byte[] unwrapHandoff(byte[] ephemeralPub, byte[] wrapped, byte[] sharedInfo) throws Exception;

  /**
   * Refuses to continue when the custody can see the root key or an FF1 key, or a batch record
   * holds LCG parameters.
   */
  void requireProductionClean(String producer) throws IOException;

  /** {@code pkcs11} or {@code softhsm-dev}, as recorded in {@code producer.json}. */
  String custody();

  /** Whether the keys are in development custody, which never issues to a {@code pcsc:} card. */
  boolean isDevelopment();
}
