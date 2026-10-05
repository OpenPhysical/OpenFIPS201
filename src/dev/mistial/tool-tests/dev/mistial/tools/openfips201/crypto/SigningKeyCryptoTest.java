/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.junit.jupiter.api.Test;

/** {@link KeyIdentifiers}, {@link SigningKeyContentSigner} and {@link CertifiedSigningKey}. */
class SigningKeyCryptoTest {
  @Test
  void skiIsLeftmost160BitsOfSha256OverTheUncompressedPoint() throws Exception {
    ECPublicKey publicKey = (ECPublicKey) ecKeyPair("secp256r1").getPublic();
    byte[] point = new byte[65];
    point[0] = 0x04;
    copyCoordinate(publicKey.getW().getAffineX(), point, 1);
    copyCoordinate(publicKey.getW().getAffineY(), point, 33);
    byte[] expected = Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(point), 20);

    assertArrayEquals(expected, KeyIdentifiers.ski(publicKey));
    assertArrayEquals(expected, KeyIdentifiers.subjectKeyIdentifier(publicKey).getKeyIdentifier());
  }

  @Test
  void contentSignerProducesVerifiableCertificatesForSha256AndSha384() throws Exception {
    KeyPair p256 = ecKeyPair("secp256r1");
    X509Certificate sha256 =
        selfSigned(SigningKeyContentSigner.sha256(software(p256)), p256.getPublic());
    sha256.verify(p256.getPublic());
    assertEquals(X9ObjectIdentifiers.ecdsa_with_SHA256.getId(), sha256.getSigAlgOID());
    assertNull(
        new X509CertificateHolder(sha256.getEncoded()).getSignatureAlgorithm().getParameters());

    KeyPair p384 = ecKeyPair("secp384r1");
    X509Certificate sha384 =
        selfSigned(
            new SigningKeyContentSigner(software(p384), "SHA384withECDSA"), p384.getPublic());
    sha384.verify(p384.getPublic());
    assertEquals(X9ObjectIdentifiers.ecdsa_with_SHA384.getId(), sha384.getSigAlgOID());

    assertThrows(
        IllegalArgumentException.class,
        () -> new SigningKeyContentSigner(software(p256), "SHA1withECDSA"));
  }

  @Test
  void certifiedSigningKeyAcceptsTheMatchingCertificate() throws Exception {
    KeyPair pair = ecKeyPair("secp256r1");
    X509Certificate certificate =
        selfSigned(SigningKeyContentSigner.sha256(software(pair)), pair.getPublic());

    CertifiedSigningKey certified = new CertifiedSigningKey(software(pair), certificate);

    assertSame(certificate, certified.certificate());
    assertArrayEquals(pair.getPublic().getEncoded(), certified.publicKey().getEncoded());
  }

  @Test
  void certifiedSigningKeyRefusesAnotherKeysCertificate() throws Exception {
    KeyPair pair = ecKeyPair("secp256r1");
    KeyPair other = ecKeyPair("secp256r1");
    X509Certificate otherCertificate =
        selfSigned(SigningKeyContentSigner.sha256(software(other)), other.getPublic());

    assertThrows(
        IllegalArgumentException.class,
        () -> new CertifiedSigningKey(software(pair), otherCertificate));
    assertThrows(IllegalArgumentException.class, () -> CertifiedSigningKey.of(software(pair)));
  }

  @Test
  void certifiedSigningKeyRefusesASignerWhosePrivateKeyDoesNotMatch() throws Exception {
    KeyPair pair = ecKeyPair("secp256r1");
    KeyPair other = ecKeyPair("secp256r1");
    X509Certificate certificate =
        selfSigned(SigningKeyContentSigner.sha256(software(pair)), pair.getPublic());
    // Claims pair's public key but signs with other's private key.
    SigningKey impostor = new PemSigningKey(other.getPrivate(), pair.getPublic(), "impostor");

    assertThrows(
        IllegalArgumentException.class, () -> new CertifiedSigningKey(impostor, certificate));
  }

  private static SigningKey software(KeyPair pair) {
    return new PemSigningKey(pair.getPrivate(), pair.getPublic(), "software");
  }

  private static X509Certificate selfSigned(
      SigningKeyContentSigner contentSigner, PublicKey publicKey) throws Exception {
    CryptoProviders.ensureBouncyCastle();
    X500Name subject = new X500Name("CN=Signing Key Test");
    Date now = new Date();
    return new JcaX509CertificateConverter()
        .getCertificate(
            new JcaX509v3CertificateBuilder(
                    subject,
                    BigInteger.TEN,
                    now,
                    new Date(now.getTime() + 60_000L),
                    subject,
                    publicKey)
                .build(contentSigner));
  }

  private static KeyPair ecKeyPair(String curve) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec(curve));
    return generator.generateKeyPair();
  }

  private static void copyCoordinate(BigInteger value, byte[] out, int offset) {
    byte[] bytes = value.toByteArray();
    int length = Math.min(bytes.length, 32);
    System.arraycopy(bytes, bytes.length - length, out, offset + 32 - length, length);
  }
}
