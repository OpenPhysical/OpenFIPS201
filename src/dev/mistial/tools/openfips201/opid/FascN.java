/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.opid;

/**
 * Federal Agency Smart Credential Number (TIG SCEPACS / SP 800-73-5 Part 1), immutable.
 *
 * <p>Fields and widths: Agency Code (4), System Code (4), Credential Number (6), Credential Series
 * (1), Individual Credential Issue (1), Person Identifier (10), Organizational Category (1),
 * Organizational Identifier (4), Person/Organization Association Category (1).
 */
public final class FascN {
  public final int agencyCode;
  public final int systemCode;
  public final int credentialNumber;
  public final int credentialSeries;
  public final int individualCredentialIssue;
  public final long personIdentifier;
  public final int organizationalCategory;
  public final int organizationalIdentifier;
  public final int personAssociation;

  public FascN(
      int agencyCode,
      int systemCode,
      int credentialNumber,
      int credentialSeries,
      int individualCredentialIssue,
      long personIdentifier,
      int organizationalCategory,
      int organizationalIdentifier,
      int personAssociation) {
    this.agencyCode = require(agencyCode, 9999L, "agency code");
    this.systemCode = require(systemCode, 9999L, "system code");
    this.credentialNumber = require(credentialNumber, 999999L, "credential number");
    this.credentialSeries = require(credentialSeries, 9L, "credential series");
    this.individualCredentialIssue =
        require(individualCredentialIssue, 9L, "individual credential issue");
    if (personIdentifier < 0 || personIdentifier > 9999999999L) {
      throw new IllegalArgumentException("FASC-N person identifier must have at most 10 digits");
    }
    this.personIdentifier = personIdentifier;
    this.organizationalCategory = require(organizationalCategory, 9L, "organizational category");
    this.organizationalIdentifier =
        require(organizationalIdentifier, 9999L, "organizational identifier");
    this.personAssociation = require(personAssociation, 9L, "person association");
  }

  /** Returns the 32 data digits in field order (sentinels, separators and LRC excluded). */
  public String digits() {
    return Digits.pad(agencyCode, 4)
        + Digits.pad(systemCode, 4)
        + Digits.pad(credentialNumber, 6)
        + credentialSeries
        + individualCredentialIssue
        + Digits.pad(personIdentifier, 10)
        + organizationalCategory
        + Digits.pad(organizationalIdentifier, 4)
        + personAssociation;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof FascN)) {
      return false;
    }
    return digits().equals(((FascN) other).digits());
  }

  @Override
  public int hashCode() {
    return digits().hashCode();
  }

  /**
   * Returns {@code S<agency>|<system>|<credential>|<CS>|<ICI>|<PI> <OC> <OI> <POA> E}, the
   * character layout of the encoded value with S, |, E standing for the SS, FS and ES sentinels.
   */
  @Override
  public String toString() {
    return "S"
        + Digits.pad(agencyCode, 4)
        + "|"
        + Digits.pad(systemCode, 4)
        + "|"
        + Digits.pad(credentialNumber, 6)
        + "|"
        + credentialSeries
        + "|"
        + individualCredentialIssue
        + "|"
        + Digits.pad(personIdentifier, 10)
        + " "
        + organizationalCategory
        + " "
        + Digits.pad(organizationalIdentifier, 4)
        + " "
        + personAssociation
        + " E";
  }

  private static int require(int value, long max, String name) {
    if (value < 0 || value > max) {
      throw new IllegalArgumentException("FASC-N " + name + " must be 0.." + max);
    }
    return value;
  }
}
