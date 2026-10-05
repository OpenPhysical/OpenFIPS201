/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.attestation;

import dev.mistial.tools.openfips201.opid.Opid;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;

/**
 * OPID codec for the F9 subject {@code serialNumber} attribute.
 *
 * <p>Wire contract: the F9 subject is the template RDNs followed by a final {@code serialNumber}
 * (2.5.4.5) RDN whose value is the canonical printed OPID as a PrintableString. Extraction mirrors
 * the card's certificate check: the attribute must occur exactly once in the whole name, alone in
 * its RelativeDistinguishedName, as a PrintableString, and its value must pass {@link
 * Opid#parseCanonical}.
 */
public final class F9SubjectNames {
  /** {@code id-at-serialNumber}, 2.5.4.5 (X.520). */
  public static final ASN1ObjectIdentifier SERIAL_NUMBER = new ASN1ObjectIdentifier("2.5.4.5");

  private F9SubjectNames() {}

  /**
   * Returns {@code template} with a final {@code serialNumber} RDN carrying {@code opid}.
   *
   * @throws IllegalArgumentException when the template already contains a serialNumber attribute
   */
  public static X500Name withOpid(X500Name template, Opid opid) {
    if (template == null || opid == null) {
      throw new IllegalArgumentException("F9 subject template and OPID are required");
    }
    RDN[] base = template.getRDNs();
    for (RDN rdn : base) {
      for (AttributeTypeAndValue attribute : rdn.getTypesAndValues()) {
        if (SERIAL_NUMBER.equals(attribute.getType())) {
          throw new IllegalArgumentException("F9 subject template must not contain serialNumber");
        }
      }
    }
    RDN[] rdns = Arrays.copyOf(base, base.length + 1);
    rdns[base.length] = new RDN(SERIAL_NUMBER, new DERPrintableString(opid.toPrinted(), true));
    return new X500Name(rdns);
  }

  /**
   * Extracts the OPID from an F9 subject.
   *
   * @throws IllegalArgumentException when the serialNumber attribute is absent, repeated, shares
   *     its RDN with another attribute, is not a PrintableString, or is not a canonical OPID
   */
  public static Opid extractOpid(X500Name subject) {
    if (subject == null) {
      throw new IllegalArgumentException("F9 subject is required");
    }
    ASN1Encodable found = null;
    for (RDN rdn : subject.getRDNs()) {
      AttributeTypeAndValue[] attributes = rdn.getTypesAndValues();
      for (AttributeTypeAndValue attribute : attributes) {
        if (!SERIAL_NUMBER.equals(attribute.getType())) {
          continue;
        }
        if (found != null) {
          throw new IllegalArgumentException("F9 subject has more than one serialNumber");
        }
        if (attributes.length != 1) {
          throw new IllegalArgumentException("F9 serialNumber must be alone in its RDN");
        }
        found = attribute.getValue();
      }
    }
    if (found == null) {
      throw new IllegalArgumentException("F9 subject has no serialNumber");
    }
    if (!(found instanceof ASN1PrintableString)) {
      throw new IllegalArgumentException("F9 serialNumber must be a PrintableString");
    }
    return Opid.parseCanonical(((ASN1PrintableString) found).getString());
  }
}
