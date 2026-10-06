/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

public final class Pkcs11Exception extends RuntimeException {
  private final long rv;

  public Pkcs11Exception(String operation, long rv) {
    super(operation + " failed CKR=" + String.format("0x%08X", rv));
    this.rv = rv;
  }

  /** The CK_RV the operation returned. */
  public long rv() {
    return rv;
  }
}
