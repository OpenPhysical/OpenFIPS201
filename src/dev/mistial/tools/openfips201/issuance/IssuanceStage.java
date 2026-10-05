/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

/**
 * Stages of the per-card issuance sequence, in order. A failure is attributed to the stage being
 * attempted; the OPID is burned once {@link #ISSUE_REQUESTED} has reached the SAM.
 */
public enum IssuanceStage {
  PREFLIGHT,
  APPLET_INSTALLED,
  F9_GENERATED,
  SAM_NONCE,
  F9_PROVED,
  ISSUE_REQUESTED,
  ISSUED,
  F9_VERIFIED,
  F9_LOADED,
  PROOF_VERIFIED,
  APPLET_READBACK,
  KEYS_ROTATED,
  COMPLETED
}
