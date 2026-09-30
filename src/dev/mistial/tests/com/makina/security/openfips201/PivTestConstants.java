package com.makina.security.openfips201;

/**
 * Test-only access to package-private applet wire definitions. Aliases keep external-package tests
 * on the same definitions without exporting implementation details in the CAP's public API.
 * Independent known-answer byte vectors should not be constructed from these aliases.
 */
public final class PivTestConstants {
  public static final byte INS_GENERAL_AUTHENTICATE = OpenFIPS201.INS_PIV_GENERAL_AUTHENTICATE;
  public static final byte INS_CHANGE_REFERENCE_DATA = OpenFIPS201.INS_PIV_CHANGE_REFERENCE_DATA;
  public static final byte INS_UPDATE_KEY = OpenFIPS201.INS_ADMIN_UPDATE_KEY;
  public static final byte INS_RESET_RETRY_COUNTER = OpenFIPS201.INS_PIV_RESET_RETRY_COUNTER;
  public static final byte INS_ATTEST = OpenFIPS201.INS_PIV_ATTEST;
  public static final byte ATTESTATION_KEY_REFERENCE = PIV.ID_KEY_ATTESTATION;
  public static final byte ECC_PUBLIC_POINT_ELEMENT = PIVKeyObjectECC.ELEMENT_ECC_POINT;
  public static final byte ECC_PRIVATE_SCALAR_ELEMENT = PIVKeyObjectECC.ELEMENT_ECC_SECRET;

  private PivTestConstants() {}
}
