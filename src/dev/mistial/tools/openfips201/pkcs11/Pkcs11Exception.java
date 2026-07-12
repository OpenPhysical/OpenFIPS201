/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

public final class Pkcs11Exception extends RuntimeException {
  public Pkcs11Exception(String operation, long rv) {
    super(operation + " failed CKR=" + String.format("0x%08X", rv));
  }
}
