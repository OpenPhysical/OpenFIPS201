/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.attestation;

import dev.mistial.tools.openfips201.common.CardSession;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.crypto.PemFiles;
import dev.mistial.tools.openfips201.crypto.SigningKey;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;

public final class AttestationAuthorityService {
  private static final int SW_NO_ERROR = 0x9000;
  private static final int SW_PUT_DATA_OBJECT_EXISTS = 0x6E27;

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

  /**
   * Mints a per-card F9 authority with a durable {@link F9InstanceId}, imports it over SCP, and
   * stores the F9 certificate in the issuer object.
   *
   * @param f9SubjectTemplate operator-configured subject template without serialNumber; the
   *     instance id is appended as a serialNumber RDN
   */
  public Result importGeneratedAuthority(
      CardSession session,
      SigningKey issuerSigner,
      String rootSubject,
      String f9SubjectTemplate,
      int validityDays,
      byte[] issuerObjectId)
      throws Exception {
    F9InstanceId instanceId = F9InstanceId.generate();
    X500Name subject = instanceId.composeSubject(f9SubjectTemplate);
    KeyPair f9 = AttestationSupport.generateF9KeyPair();
    X509Certificate certificate =
        createIssuerCertificate(
            issuerSigner, f9, rootSubject, subject, instanceId.toSerialNumber(), validityDays);
    F9Profile profile = AttestationSupport.profileFromIssuer(f9.getPrivate(), certificate);
    provisionAuthority(session, profile, AttestationSupport.der(certificate), issuerObjectId);
    return new Result(
        certificate, f9.getPrivate(), instanceId.toHex(), spkiSha256(certificate));
  }

  public static final class Result {
    public final X509Certificate issuerCertificate;
    public final PrivateKey f9PrivateKey;
    /** 32-character uppercase hex durable instance id. */
    public final String instanceId;
    /** SHA-256 over the SubjectPublicKeyInfo DER of the F9 certificate. */
    public final String f9SpkiSha256;

    Result(
        X509Certificate issuerCertificate,
        PrivateKey f9PrivateKey,
        String instanceId,
        String f9SpkiSha256) {
      this.issuerCertificate = issuerCertificate;
      this.f9PrivateKey = f9PrivateKey;
      this.instanceId = instanceId;
      this.f9SpkiSha256 = f9SpkiSha256;
    }
  }

  public static String spkiSha256(X509Certificate certificate) throws Exception {
    SubjectPublicKeyInfo spki =
        SubjectPublicKeyInfo.getInstance(certificate.getPublicKey().getEncoded());
    return HexUtil.format(MessageDigest.getInstance("SHA-256").digest(spki.getEncoded()));
  }

  public static String certificateSha256(X509Certificate certificate) throws Exception {
    return HexUtil.format(
        MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
  }

  /** Hex of the F9 cert serial, zero-padded to the 16-byte durable instance id form. */
  public static String serialHex(X509Certificate certificate) {
    return F9InstanceId.fromSerialNumber(certificate.getSerialNumber()).toHex();
  }

  private static X509Certificate createIssuerCertificate(
      final SigningKey signer,
      KeyPair f9,
      String issuerName,
      X500Name subject,
      BigInteger serial,
      int validityDays)
      throws Exception {
    PemFiles.ensureProvider();
    X500Name issuer = new X500Name(issuerName);
    Date notBefore = new Date();
    Date notAfter = new Date(notBefore.getTime() + validityDays * 24L * 60L * 60L * 1000L);
    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, subject, f9.getPublic());
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

  static void provisionAuthority(
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
    if (response.getSW() == SW_NO_ERROR
        || (existsOk && response.getSW() == SW_PUT_DATA_OBJECT_EXISTS)) {
      return;
    }
    throw new IllegalStateException(
        "APDU failed SW=" + String.format("0x%04X", response.getSW())
            + " (" + statusMeaning(response.getSW()) + ")"
            + " command=" + command.toLogString());
  }

  private static String statusMeaning(int sw) {
    switch (sw) {
      case 0x6982:
        return "security status not satisfied; check SCP and target access policy";
      case 0x6985:
        return "authority or target state is incomplete, or target key was not generated on-card";
      case 0x6A80:
        return "malformed authority data, malformed DER, unsupported authority field, or key-pair"
            + " mismatch";
      case 0x6A84:
        return "configured subject, validity, or generated object exceeds applet limits";
      case 0x6A86:
        return "invalid command parameters";
      case 0x6A88:
        return "target slot or key reference not found";
      case SW_PUT_DATA_OBJECT_EXISTS:
        return "object already exists";
      default:
        return "see docs/ATTESTATION.md status words";
    }
  }
}
