/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import dev.mistial.tools.openfips201.common.BerTlvReader;
import java.util.Arrays;

/** The ISSUE F9 response {@code 70 L cert | 71 L entry | 72 L sig}, each once, nothing trailing. */
public final class IssueResponse {
  private final byte[] raw;
  private final byte[] certificate;
  public final SamLedgerEntry.Signed signedEntry;

  private IssueResponse(byte[] raw, byte[] certificate, SamLedgerEntry.Signed signedEntry) {
    this.raw = raw.clone();
    this.certificate = certificate;
    this.signedEntry = signedEntry;
  }

  public static IssueResponse parse(byte[] raw) {
    if (raw == null || raw.length == 0) {
      throw new IllegalArgumentException("ISSUE response is empty");
    }
    BerTlvReader.Tlv cert = BerTlvReader.read(raw, 0);
    if (cert.tag != 0x70) {
      throw new IllegalArgumentException("ISSUE response does not begin with a 70 certificate");
    }
    SamLedgerEntry.Signed entry =
        SamLedgerEntry.Signed.parse(Arrays.copyOfRange(raw, cert.nextOffset, raw.length));
    if (entry.signature() == null) {
      throw new IllegalArgumentException("ISSUE response carries no entry signature");
    }
    return new IssueResponse(
        raw, Arrays.copyOfRange(raw, cert.valueOffset, cert.nextOffset), entry);
  }

  public byte[] raw() {
    return raw.clone();
  }

  public byte[] certificate() {
    return certificate.clone();
  }
}
