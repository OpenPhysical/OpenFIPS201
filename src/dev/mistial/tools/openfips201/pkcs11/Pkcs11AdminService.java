/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

import dev.mistial.tools.openfips201.crypto.PemFiles;
import dev.mistial.tools.openfips201.crypto.SigningKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;

public final class Pkcs11AdminService {
  public Result ensureRootSigner(Pkcs11Config config, String label, byte[] id, String subjectName)
      throws Exception {
    Pkcs11Config selected = config.copy();
    selected.keyAlias = label;
    selected.keyId = null;
    PemFiles.ensureProvider();
    try (Pkcs11Token token = Pkcs11Token.open(config)) {
      token.generateEcP256KeyPair(label, id);
      PublicKey publicKey = token.publicKey(label, id);
      X509Certificate certificate =
          createCaCertificate(new TokenSigningKey(config, label, id, publicKey), subjectName, publicKey);
      X500Name subject = new X500Name(subjectName);
      BigInteger serial = certificate.getSerialNumber();
      token.createCertificate(
          label,
          id,
          subject.getEncoded(),
          subject.getEncoded(),
          new ASN1Integer(serial).getEncoded(),
          certificate.getEncoded());
      return new Result(certificate);
    }
  }

  public void generateAes256Key(Pkcs11Config config, String label, byte[] id) {
    try (Pkcs11Token token = Pkcs11Token.open(config)) {
      token.generateAesKey(label, id, 32);
    }
  }

  private static X509Certificate createCaCertificate(
      SigningKey signer, String subjectName, PublicKey publicKey) throws Exception {
    X500Name subject = new X500Name(subjectName);
    Date notBefore = new Date();
    Date notAfter = new Date(notBefore.getTime() + 3650L * 24L * 60L * 60L * 1000L);
    BigInteger serial = new BigInteger(160, new java.security.SecureRandom()).abs();
    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(subject, serial, notBefore, notAfter, subject, publicKey);
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    builder.addExtension(
        Extension.keyUsage,
        true,
        new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));
    X509CertificateHolder holder = builder.build(contentSigner(signer));
    return new JcaX509CertificateConverter()
        .setProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME)
        .getCertificate(holder);
  }

  private static ContentSigner contentSigner(final SigningKey signer) {
    return new ContentSigner() {
      private final ByteArrayOutputStream out = new ByteArrayOutputStream();

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
          throw new IllegalStateException("PKCS#11 signing failed", e);
        }
      }
    };
  }

  public static final class Result {
    public final X509Certificate certificate;

    Result(X509Certificate certificate) {
      this.certificate = certificate;
    }
  }

  private static final class TokenSigningKey implements SigningKey {
    private final Pkcs11Config config;
    private final String label;
    private final byte[] id;
    private final PublicKey publicKey;

    TokenSigningKey(Pkcs11Config config, String label, byte[] id, PublicKey publicKey) {
      this.config = config.copy();
      this.label = label;
      this.id = id.clone();
      this.publicKey = publicKey;
    }

    @Override
    public PublicKey publicKey() {
      return publicKey;
    }

    @Override
    public byte[] sign(String jcaAlgorithm, byte[] message) throws Exception {
      Pkcs11Config selected = config.copy();
      selected.keyAlias = label;
      selected.keyId = null;
      byte[] raw;
      try (Pkcs11Token token = Pkcs11Token.open(selected)) {
        raw = token.sign(Pkcs11Constants.CKM_ECDSA, token.findPrivateKey(selected), java.security.MessageDigest.getInstance("SHA-256").digest(message));
      }
      return Pkcs11SigningKey.derEncodeEcdsa(raw, 32);
    }

    @Override
    public String description() {
      return "pkcs11:" + label;
    }
  }

  public static X509Certificate parseCertificate(byte[] der) throws Exception {
    return (X509Certificate)
        CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
  }
}
