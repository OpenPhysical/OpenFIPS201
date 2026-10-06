/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

/** A card or SAM command that completed with a status word other than 9000. */
public final class SamApduException extends IllegalStateException {
  private static final long serialVersionUID = 1L;

  /** ISSUE failed after the SAM's issuance commit: the OPID is burned. */
  public static final int SW_FAILURE_AFTER_COMMIT = 0x6500;

  /** Quota or OPID period exhausted. */
  public static final int SW_EXHAUSTED = 0x6A84;

  /** Signature verification failed on the SAM; state unchanged. */
  public static final int SW_VERIFICATION_FAILED = 0x6300;

  public final int sw;

  public SamApduException(String label, int sw) {
    super(label + " failed SW=" + String.format("0x%04X", sw) + meaning(sw));
    this.sw = sw;
  }

  private static String meaning(int sw) {
    switch (sw) {
      case 0x6300:
        return " (signature verification failed)";
      case 0x6500:
        return " (failure after the issuance commit; the OPID is burned)";
      case 0x6982:
        return " (secure channel or operator PIN required)";
      case 0x6985:
        return " (conditions of use not satisfied, e.g. personalization after LOCK)";
      case 0x6A80:
        return " (malformed or rejected data)";
      case 0x6A84:
        return " (quota or OPID period exhausted)";
      default:
        return "";
    }
  }
}
