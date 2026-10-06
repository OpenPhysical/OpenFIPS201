/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import dev.mistial.tools.openfips201.gp.DerivedScpKeys;

/** Derives a card's issuer SCP keys from the KDD the card returned in INITIALIZE UPDATE. */
public interface ScpKeyDeriver {
  DerivedScpKeys derive(byte[] kdd) throws Exception;

  /** Non-secret description of the master key, for receipts. */
  String description();
}
