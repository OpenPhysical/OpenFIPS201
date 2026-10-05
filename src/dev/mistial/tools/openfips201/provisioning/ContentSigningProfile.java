/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.provisioning;

import dev.mistial.tools.openfips201.common.BerTlvReader;
import dev.mistial.tools.openfips201.opid.FascN;
import dev.mistial.tools.openfips201.opid.FascNCodec;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * The extended key usage of the content signing certificate that signs a card's CHUID, Security
 * Object and secure messaging CVC, for PIV and PIV-I cards.
 *
 * <ul>
 *   <li>PIV: SP 800-73-5 Part 1 Section 3.1.2.1, "The content signing certificate SHALL also
 *       include an extended key usage (extKeyUsage) extension asserting id-PIV-content-signing".
 *   <li>PIV-I: FPKI PIV-I Certificate and CRL Profiles v1.3 Worksheet 8, "extKeyUsage ...
 *       KeyPurposeID 2.16.840.1.101.3.8.7 id-fpki-pivi-content-signing".
 * </ul>
 *
 * <p>Both policies make the extension critical and single-valued. FPKI Common Policy v2.13:
 * "Certificates that assert id-fpki-common-piv-contentSigning must include a critical Extended Key
 * Usage extension that asserts only id-PIV-content-signing" and "Certificates that assert
 * id-fpki-common-pivi-contentSigning must include a critical Extended Key Usage extension that
 * asserts only id-fpki-pivi-content-signing"; FBCA v3.7 states the same for
 * id-fpki-certpcy-pivi-contentSigning.
 *
 * <p>The card type comes from the CHUID FASC-N. SP 800-73-4 Part 1: "[PIV-I FAQ] requires the first
 * 14 digits of the FASC-Ns for PIV-I cards (the Agency Code, System Code, and Credential Number) to
 * be populated with all nines", so such a card is a non-federally issued PIV-I card. A federal
 * agency code does not settle the type: SP 800-116 Rev 1 footnote 18, "Federal agencies that are
 * assigned agency codes in [SP800 87] may use their agency codes to assign FASC-Ns for PIV-I
 * cards", and Common Policy defines id-fpki-common-pivi-contentSigning for "federally-issued PIV-I
 * data objects". For such a card the content signer's FPKI content signing policy decides, and
 * without one either purpose is accepted.
 */
public final class ContentSigningProfile {
  /** FIPS 201-3 Appendix B: "id-PIV-content-signing 2.16.840.1.101.3.6.7". */
  public static final KeyPurposeId ID_PIV_CONTENT_SIGNING =
      KeyPurposeId.getInstance(new ASN1ObjectIdentifier("2.16.840.1.101.3.6.7"));

  /** FPKI PIV-I Profiles v1.3: "2.16.840.1.101.3.8.7 id-fpki-pivi-content-signing". */
  public static final KeyPurposeId ID_FPKI_PIVI_CONTENT_SIGNING =
      KeyPurposeId.getInstance(new ASN1ObjectIdentifier("2.16.840.1.101.3.8.7"));

  // Common Policy v2.13: "id-fpki-common-piv-contentSigning ::= {2 16 840 1 101 3 2 1 3 39}".
  private static final ASN1ObjectIdentifier ID_FPKI_COMMON_PIV_CONTENT_SIGNING =
      new ASN1ObjectIdentifier("2.16.840.1.101.3.2.1.3.39");
  // Common Policy v2.13: "id-fpki-common-pivi-contentSigning ::= {2 16 840 1 101 3 2 1 3 47}".
  private static final ASN1ObjectIdentifier ID_FPKI_COMMON_PIVI_CONTENT_SIGNING =
      new ASN1ObjectIdentifier("2.16.840.1.101.3.2.1.3.47");
  // FBCA v3.7: "id-fpki-certpcy-pivi-contentSigning ::= {2 16 840 1 101 3 2 1 3 20}".
  private static final ASN1ObjectIdentifier ID_FPKI_CERTPCY_PIVI_CONTENT_SIGNING =
      new ASN1ObjectIdentifier("2.16.840.1.101.3.2.1.3.20");

  private static final int TAG_FASC_N = 0x30;

  private ContentSigningProfile() {}

  /**
   * Returns whether a FASC-N carries the PIV-I all-nines Agency Code, System Code and Credential
   * Number.
   *
   * @throws IllegalArgumentException if the FASC-N does not decode
   */
  public static boolean isNonFederalPivI(byte[] fascN) {
    FascN decoded = FascNCodec.decode(fascN);
    return decoded.agencyCode == 9999
        && decoded.systemCode == 9999
        && decoded.credentialNumber == 999999;
  }

  /**
   * Returns the CHUID FASC-N (tag 30).
   *
   * @param chuid the CHUID value, the concatenated CHUID elements without the 53 wrapper
   * @throws IllegalArgumentException if the CHUID has no 25-byte FASC-N
   */
  public static byte[] fascN(byte[] chuid) {
    BerTlvReader.Tlv element;
    try {
      element = BerTlvReader.locate(chuid, 0, TAG_FASC_N);
    } catch (RuntimeException malformed) {
      throw new IllegalArgumentException("CHUID is not BER-TLV", malformed);
    }
    if (element == null || element.length != FascNCodec.LENGTH) {
      throw new IllegalArgumentException("CHUID lacks a 25-byte FASC-N");
    }
    return Arrays.copyOfRange(chuid, element.valueOffset, element.nextOffset);
  }

  /**
   * Returns the purpose a generated content signer asserts for a card with this FASC-N: the PIV-I
   * purpose for the all-nines PIV-I FASC-N, otherwise id-PIV-content-signing.
   */
  public static KeyPurposeId purposeForFascN(byte[] fascN) {
    return isNonFederalPivI(fascN) ? ID_FPKI_PIVI_CONTENT_SIGNING : ID_PIV_CONTENT_SIGNING;
  }

  /**
   * Requires the content signing certificate of a card with this CHUID to carry a critical
   * extKeyUsage that asserts only the content signing purpose of the card type.
   *
   * @param chuid the CHUID value, the concatenated CHUID elements without the 53 wrapper
   * @param label names the object in the failure message
   * @throws IllegalArgumentException if the extension or the card type does not conform
   */
  public static void requireUsage(X509CertificateHolder certificate, byte[] chuid, String label) {
    Extension extension = certificate.getExtension(Extension.extendedKeyUsage);
    if (extension == null || !extension.isCritical()) {
      throw new IllegalArgumentException(
          label + " content signing certificate must carry a critical extKeyUsage");
    }
    KeyPurposeId[] usages = ExtendedKeyUsage.getInstance(extension.getParsedValue()).getUsages();
    Set<KeyPurposeId> allowed = allowedPurposes(certificate, fascN(chuid), label);
    if (usages.length != 1 || !allowed.contains(usages[0])) {
      throw new IllegalArgumentException(
          label
              + " content signing certificate extKeyUsage must assert only "
              + (allowed.size() == 1
                  ? name(allowed.iterator().next())
                  : name(ID_PIV_CONTENT_SIGNING) + " or " + name(ID_FPKI_PIVI_CONTENT_SIGNING))
              + " for this card");
    }
  }

  private static Set<KeyPurposeId> allowedPurposes(
      X509CertificateHolder certificate, byte[] fascN, String label) {
    boolean nonFederal = isNonFederalPivI(fascN);
    boolean pivPolicy = false;
    boolean pivIPolicy = false;
    CertificatePolicies policies = CertificatePolicies.fromExtensions(certificate.getExtensions());
    if (policies != null) {
      for (PolicyInformation information : policies.getPolicyInformation()) {
        ASN1ObjectIdentifier policy = information.getPolicyIdentifier();
        pivPolicy |= policy.equals(ID_FPKI_COMMON_PIV_CONTENT_SIGNING);
        pivIPolicy |=
            policy.equals(ID_FPKI_COMMON_PIVI_CONTENT_SIGNING)
                || policy.equals(ID_FPKI_CERTPCY_PIVI_CONTENT_SIGNING);
      }
    }
    if (pivPolicy && (pivIPolicy || nonFederal)) {
      throw new IllegalArgumentException(
          label + " content signing policy contradicts the card's PIV-I FASC-N or policies");
    }
    Set<KeyPurposeId> allowed = new HashSet<KeyPurposeId>();
    if (!pivIPolicy && !nonFederal) allowed.add(ID_PIV_CONTENT_SIGNING);
    if (!pivPolicy) allowed.add(ID_FPKI_PIVI_CONTENT_SIGNING);
    return allowed;
  }

  private static String name(KeyPurposeId purpose) {
    return purpose.equals(ID_PIV_CONTENT_SIGNING)
        ? "id-PIV-content-signing"
        : "id-fpki-pivi-content-signing";
  }
}
