/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import dev.mistial.tools.openfips201.attestation.AttestationVerifier;
import dev.mistial.tools.openfips201.attestation.OpenPhysicalExtensions;
import dev.mistial.tools.openfips201.attestation.VerificationReport;
import dev.mistial.tools.openfips201.attestation.VerificationRequest;
import dev.mistial.tools.openfips201.crypto.KeyIdentifiers;
import dev.mistial.tools.openfips201.crypto.SigningKey;
import dev.mistial.tools.openfips201.crypto.SigningKeyContentSigner;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;

/**
 * The root issues the SAM certificate:
 *
 * <ul>
 *   <li>issuer = the root subject as exact DER; random positive 128-bit serial; ecdsa-with-SHA256;
 *   <li>validity from now to min(now + validityDays, root notAfter);
 *   <li>BasicConstraints critical cA TRUE pathLen 1; KeyUsage critical keyCertSign |
 *       digitalSignature; SKI (RFC 7093 method 1) and AKI = root SKI;
 *   <li>the non-critical SAM batch extension {@code .20.10.10.3}.
 * </ul>
 *
 * <p>Every certificate is checked by {@link AttestationVerifier} (root to SAM) before it is
 * returned, so an invalid certificate is never loaded into a SAM.
 */
public final class SamCertificateFactory {
  private static final long DAY_MILLIS = 24L * 60L * 60L * 1000L;
  private static final SecureRandom RANDOM = new SecureRandom();

  private SamCertificateFactory() {}

  /**
   * @param root the root signer; its certificate is the trust anchor
   * @param batchExtension the SAM batch extension value ({@link
   *     SamParameters#encodeBatchExtension})
   */
  public static byte[] issue(
      SigningKey root,
      byte[] samPoint,
      X500Name subject,
      byte[] batchExtension,
      int validityDays,
      Date now)
      throws Exception {
    X509Certificate rootCertificate = root.certificate();
    if (rootCertificate == null) {
      throw new IllegalArgumentException("the root signer carries no certificate");
    }
    if (validityDays < 1) {
      throw new IllegalArgumentException("SAM validity must be at least one day");
    }
    Date notBefore = new Date(now.getTime() / 1000L * 1000L);
    Date notAfter = new Date(notBefore.getTime() + validityDays * DAY_MILLIS);
    if (notAfter.after(rootCertificate.getNotAfter())) {
      notAfter = rootCertificate.getNotAfter();
    }
    if (!notAfter.after(notBefore)) {
      throw new IllegalArgumentException("the root certificate expires before the SAM would");
    }
    SubjectPublicKeyInfo spki =
        SubjectPublicKeyInfo.getInstance(IssuanceCrypto.publicKey(samPoint).getEncoded());
    X509v3CertificateBuilder builder =
        new X509v3CertificateBuilder(
            X500Name.getInstance(rootCertificate.getSubjectX500Principal().getEncoded()),
            new BigInteger(128, RANDOM).setBit(126),
            notBefore,
            notAfter,
            subject,
            spki);
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(1));
    builder.addExtension(
        Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature));
    builder.addExtension(
        Extension.subjectKeyIdentifier, false, new DEROctetString(KeyIdentifiers.ski(spki)));
    builder.addExtension(
        Extension.authorityKeyIdentifier,
        false,
        new DERSequence(
            new DERTaggedObject(
                false, 0, new DEROctetString(KeyIdentifiers.ski(rootCertificate.getPublicKey())))));
    builder.addExtension(
        OpenPhysicalExtensions.SAM_BATCH, false, ASN1Primitive.fromByteArray(batchExtension));
    byte[] encoded = builder.build(SigningKeyContentSigner.sha256(root)).getEncoded();
    requireValid(rootCertificate, encoded, now);
    return encoded;
  }

  /** Runs {@link AttestationVerifier} over root to SAM and fails on any failed check. */
  public static VerificationReport requireValid(
      X509Certificate rootCertificate, byte[] samCertificate, Date at) {
    VerificationReport report =
        AttestationVerifier.verify(
            VerificationRequest.builder()
                .anchor(rootCertificate)
                .samCertificate(samCertificate)
                .at(at)
                .build());
    if (!report.valid()) {
      throw new IllegalStateException("SAM certificate failed verification:\n" + report.toTable());
    }
    return report;
  }
}
