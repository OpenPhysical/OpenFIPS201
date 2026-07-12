/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.attestation;

import dev.mistial.tools.openfips201.common.CardSession;
import dev.mistial.tools.openfips201.crypto.PemFiles;
import dev.mistial.tools.openfips201.crypto.SigningKey;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;

public final class AttestationAuthorityService {
  public Result importGeneratedAuthority(
      CardSession session,
      SigningKey issuerSigner,
      String issuerSubject,
      int validityDays,
      byte[] issuerObjectId)
      throws Exception {
    return importGeneratedAuthority(
        session, issuerSigner, issuerSubject, issuerSubject, validityDays, issuerObjectId);
  }

  public Result importGeneratedAuthority(
      CardSession session,
      SigningKey issuerSigner,
      String rootSubject,
      String f9Subject,
      int validityDays,
      byte[] issuerObjectId)
      throws Exception {
    KeyPair f9 = AttestationSupport.generateF9KeyPair();
    X509Certificate certificate =
        createIssuerCertificate(issuerSigner, f9, rootSubject, f9Subject, validityDays);
    F9Profile profile = AttestationSupport.profileFromIssuer(f9.getPrivate(), certificate);
    provisionAuthority(session, profile, AttestationSupport.der(certificate), issuerObjectId);
    return new Result(certificate, f9.getPrivate());
  }

  public static final class Result {
    public final X509Certificate issuerCertificate;
    public final PrivateKey f9PrivateKey;

    Result(X509Certificate issuerCertificate, PrivateKey f9PrivateKey) {
      this.issuerCertificate = issuerCertificate;
      this.f9PrivateKey = f9PrivateKey;
    }
  }

  private static X509Certificate createIssuerCertificate(
      final SigningKey signer, KeyPair f9, String subjectName, int validityDays) throws Exception {
    return createIssuerCertificate(signer, f9, subjectName, subjectName, validityDays);
  }

  private static X509Certificate createIssuerCertificate(
      final SigningKey signer,
      KeyPair f9,
      String issuerName,
      String subjectName,
      int validityDays)
      throws Exception {
    PemFiles.ensureProvider();
    X500Name issuer = new X500Name(issuerName);
    X500Name subject = new X500Name(subjectName);
    Date notBefore = new Date();
    Date notAfter = new Date(notBefore.getTime() + validityDays * 24L * 60L * 60L * 1000L);
    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            issuer, new BigInteger(160, new java.security.SecureRandom()).abs(), notBefore,
            notAfter, subject, f9.getPublic());
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    builder.addExtension(
        Extension.keyUsage,
        true,
        new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));
    ContentSigner contentSigner =
        new ContentSigner() {
          private final java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();

          @Override
          public org.bouncycastle.asn1.x509.AlgorithmIdentifier getAlgorithmIdentifier() {
            return new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                org.bouncycastle.asn1.x9.X9ObjectIdentifiers.ecdsa_with_SHA256);
          }

          @Override
          public java.io.OutputStream getOutputStream() {
            return out;
          }

          @Override
          public byte[] getSignature() {
            try {
              return signer.sign("SHA256withECDSA", out.toByteArray());
            } catch (Exception e) {
              throw new IllegalStateException("HSM signing failed", e);
            }
          }
        };
    X509CertificateHolder holder = builder.build(contentSigner);
    return new JcaX509CertificateConverter()
        .setProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME)
        .getCertificate(holder);
  }

  private static void provisionAuthority(
      CardSession session, F9Profile profile, byte[] issuerCertificateDer, byte[] issuerObjectId) {
    try {
      transmitExpect(
          session,
          new apdu4j.core.CommandAPDU(
              0x84, 0xDB, 0x3F, 0x00, AttestationSupport.createF9KeyDefinition()),
          true);
      transmitExpect(
          session,
          new apdu4j.core.CommandAPDU(
              0x84,
              0x24,
              AttestationSupport.ALG_ECC_P256 & 0xFF,
              AttestationSupport.F9_AUTHORITY & 0xFF,
              AttestationSupport.clearReferenceDataElement()),
          false);
      importElement(session, (byte) 0x86, profile.publicPoint);
      importElement(session, (byte) 0x87, profile.privateScalar);
      importElement(session, (byte) 0x92, profile.subjectDer);
      importElement(session, (byte) 0x93, profile.validityDer);
      transmitExpect(
          session,
          new apdu4j.core.CommandAPDU(
              0x84, 0xDB, 0x3F, 0x00, AttestationSupport.createDataObjectDefinition(issuerObjectId)),
          true);
      sendChainedPutData(
          session,
          AttestationSupport.putDataPayload(
              issuerObjectId, AttestationSupport.certificateObject(issuerCertificateDer)));
    } finally {
      profile.clearPrivateScalarCopy();
    }
  }

  private static void importElement(CardSession session, byte tag, byte[] value) {
    transmitExpect(
        session,
        new apdu4j.core.CommandAPDU(
            0x84,
            0x24,
            AttestationSupport.ALG_ECC_P256 & 0xFF,
            AttestationSupport.F9_AUTHORITY & 0xFF,
            AttestationSupport.changeReferenceDataElement(tag, value)),
        false);
  }

  private static void sendChainedPutData(CardSession session, byte[] payload) {
    int offset = 0;
    while (offset < payload.length) {
      int chunkLength = Math.min(0xEF, payload.length - offset);
      byte[] chunk = new byte[chunkLength];
      System.arraycopy(payload, offset, chunk, 0, chunkLength);
      offset += chunkLength;
      int cla = offset < payload.length ? 0x10 : 0x00;
      transmitExpect(session, new apdu4j.core.CommandAPDU(cla, 0xDB, 0x3F, 0xFF, chunk), false);
    }
  }

  static void transmitExpect(CardSession session, apdu4j.core.CommandAPDU command, boolean existsOk) {
    apdu4j.core.ResponseAPDU response = session.transmit(command);
    if (response.getSW() == 0x9000 || (existsOk && response.getSW() == 0x6E27)) {
      return;
    }
    throw new IllegalStateException(
        "APDU failed SW=" + String.format("0x%04X", response.getSW())
            + " command=" + command.toLogString());
  }
}
