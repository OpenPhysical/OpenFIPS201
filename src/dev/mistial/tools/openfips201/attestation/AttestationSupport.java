/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ******************************************************************************/

package dev.mistial.tools.openfips201.attestation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;
import java.util.Date;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Hex;
import pro.javacard.gp.GPUtils;

final class AttestationSupport {
  static final byte F9_AUTHORITY = (byte) 0xF9;
  // Applet-side limits for the issuer profile (PIVAttestation.LENGTH_SUBJECT_MAX and
  // LENGTH_VALIDITY_MAX). Checked here so an oversize issuer fails with a clear message before
  // any card communication.
  static final int LENGTH_SUBJECT_MAX = 0x80;
  static final int LENGTH_VALIDITY_MAX = 0x40;
  static final byte ALG_ECC_P256 = (byte) 0x11;
  static final byte ROLE_SIGN = (byte) 0x04;
  static final byte ADMIN_ALWAYS = (byte) 0x00;
  static final byte ACCESS_NEVER = (byte) 0x00;
  static final byte ACCESS_ALWAYS = (byte) 0x7F;
  static final byte ATTR_IMPORTABLE = (byte) 0x10;
  static final String DEFAULT_ISSUER_OBJECT_ID_HEX = "5FFF01";
  static final byte[] PIV_AID = hex("A000000308000010000100");
  static final byte[] DEFAULT_ISSUER_OBJECT_ID = hex(DEFAULT_ISSUER_OBJECT_ID_HEX);

  private AttestationSupport() {}

  static void ensureProvider() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  static byte[] createF9KeyDefinition() {
    return tlv(
        0x66,
        concat(
            tlv(0x8B, new byte[] {F9_AUTHORITY}),
            tlv(0x8C, new byte[] {ADMIN_ALWAYS}),
            tlv(0x8D, new byte[] {ACCESS_NEVER}),
            tlv(0x8E, new byte[] {ALG_ECC_P256}),
            tlv(0x8F, new byte[] {ROLE_SIGN}),
            tlv(0x90, new byte[] {ATTR_IMPORTABLE})));
  }

  static byte[] changeReferenceDataElement(byte tag, byte[] value) {
    return tlv(0x30, tlv(tag & 0xFF, value));
  }

  static byte[] clearReferenceDataElement() {
    // E0 is the applet's ELEMENT_CLEAR wire tag. FF is not usable here: BER treats a tag byte
    // with bits B5-B1 all set as the start of a multi-byte tag, so the applet cannot parse it.
    return changeReferenceDataElement((byte) 0xE0, new byte[0]);
  }

  static byte[] createDataObjectDefinition(byte[] objectId) {
    requireObjectId(objectId);
    return tlv(
        0x64,
        concat(
            tlv(0x8B, objectId),
            tlv(0x8C, new byte[] {ACCESS_ALWAYS}),
            tlv(0x8D, new byte[] {ACCESS_ALWAYS}),
            tlv(0x91, new byte[] {(byte) 0x9B})));
  }

  static byte[] certificateObject(byte[] certificateDer) {
    return tlv(
        0x53,
        concat(
            tlv(0x70, certificateDer),
            tlv(0x71, new byte[] {(byte) 0x00}),
            new byte[] {(byte) 0xFE, (byte) 0x00}));
  }

  static byte[] putDataPayload(byte[] objectId, byte[] objectBody) {
    requireObjectId(objectId);
    return concat(tlv(0x5C, objectId), objectBody);
  }

  static KeyPair generateF9KeyPair() throws GeneralSecurityException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
    return generator.generateKeyPair();
  }

  static byte[] publicPoint(PublicKey publicKey) {
    if (!(publicKey instanceof ECPublicKey)) {
      throw new IllegalArgumentException("F9 public key must be an EC public key");
    }
    ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
    int size = coordinateSize(ecPublicKey);
    ECPoint point = ecPublicKey.getW();
    return concat(
        new byte[] {(byte) 0x04}, fixed(point.getAffineX(), size), fixed(point.getAffineY(), size));
  }

  static byte[] privateScalar(PrivateKey privateKey) {
    if (!(privateKey instanceof ECPrivateKey)) {
      throw new IllegalArgumentException("F9 private key must be an EC private key");
    }
    ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
    int size = (ecPrivateKey.getParams().getOrder().bitLength() + 7) / 8;
    return fixed(ecPrivateKey.getS(), size);
  }

  static byte[] subjectDer(X509Certificate certificate) throws IOException {
    return X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded()).getEncoded();
  }

  static byte[] validityDer(X509Certificate certificate) throws IOException {
    ASN1EncodableVector vector = new ASN1EncodableVector();
    vector.add(new Time(certificate.getNotBefore()));
    vector.add(new Time(certificate.getNotAfter()));
    return new DERSequence(vector).getEncoded();
  }

  static F9Profile profileFromIssuer(PrivateKey privateKey, X509Certificate issuerCertificate)
      throws GeneralSecurityException, IOException {
    validateF9Issuer(privateKey, issuerCertificate);
    byte[] subject = subjectDer(issuerCertificate);
    if (subject.length > LENGTH_SUBJECT_MAX) {
      throw new GeneralSecurityException(
          "Issuer subject DER is "
              + subject.length
              + " bytes; the applet accepts at most "
              + LENGTH_SUBJECT_MAX
              + ". Attestation issuer names are intentionally small.");
    }
    byte[] validity = validityDer(issuerCertificate);
    if (validity.length > LENGTH_VALIDITY_MAX) {
      throw new GeneralSecurityException(
          "Issuer validity DER is "
              + validity.length
              + " bytes; the applet accepts at most "
              + LENGTH_VALIDITY_MAX);
    }
    return new F9Profile(
        publicPoint(issuerCertificate.getPublicKey()),
        privateScalar(privateKey),
        subject,
        validity);
  }

  static void validateF9Issuer(PrivateKey privateKey, X509Certificate certificate)
      throws GeneralSecurityException {
    if (!(privateKey instanceof ECPrivateKey)
        || !(certificate.getPublicKey() instanceof ECPublicKey)) {
      throw new GeneralSecurityException("F9 authority must use an EC P-256 key pair");
    }
    ECPublicKey publicKey = (ECPublicKey) certificate.getPublicKey();
    if (coordinateSize(publicKey) != 32) {
      throw new GeneralSecurityException("F9 authority public key must be P-256");
    }
    try {
      certificate.checkValidity();
    } catch (CertificateNotYetValidException e) {
      throw new GeneralSecurityException("F9 issuer certificate is not valid yet", e);
    } catch (CertificateExpiredException e) {
      throw new GeneralSecurityException("F9 issuer certificate has expired", e);
    }
    if (certificate.getBasicConstraints() < 0) {
      throw new GeneralSecurityException("F9 issuer certificate must be a CA certificate");
    }
    byte[] challenge = hex("4639206174746573746174696F6E2070726F6F66");
    Signature signer = Signature.getInstance("SHA256withECDSA");
    signer.initSign(privateKey);
    signer.update(challenge);
    byte[] signature = signer.sign();
    Signature verifier = Signature.getInstance("SHA256withECDSA");
    verifier.initVerify(publicKey);
    verifier.update(challenge);
    if (!verifier.verify(signature)) {
      throw new GeneralSecurityException(
          "F9 private key does not match issuer certificate public key");
    }
  }

  static PKCS10CertificationRequest createCsr(KeyPair keyPair, X500Name subject) throws Exception {
    ensureProvider();
    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(keyPair.getPrivate());
    return new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic()).build(signer);
  }

  static X509Certificate createIssuerCertificate(
      KeyPair f9KeyPair, X500Name subject, Date notBefore, Date notAfter) throws Exception {
    ensureProvider();
    BigInteger serial = new BigInteger(160, new SecureRandom()).abs();
    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            subject, serial, notBefore, notAfter, subject, f9KeyPair.getPublic());
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    builder.addExtension(
        Extension.keyUsage,
        true,
        new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));
    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(f9KeyPair.getPrivate());
    X509CertificateHolder holder = builder.build(signer);
    return new JcaX509CertificateConverter()
        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .getCertificate(holder);
  }

  static byte[] der(X509Certificate certificate) throws CertificateEncodingException {
    return certificate.getEncoded();
  }

  static byte[] tlv(int tag, byte[] value) {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    output.write(tag & 0xFF);
    writeLength(output, value.length);
    output.write(value, 0, value.length);
    return output.toByteArray();
  }

  static byte[] concat(byte[]... arrays) {
    return GPUtils.concatenate(arrays);
  }

  static byte[] hex(String value) {
    try {
      return Hex.decode(value.replace(" ", "").replace("\n", "").replace("\t", ""));
    } catch (RuntimeException e) {
      throw new IllegalArgumentException("Invalid hex: " + value, e);
    }
  }

  static String toHex(byte[] bytes) {
    return Hex.toHexString(bytes).toUpperCase();
  }

  static void clear(byte[] bytes) {
    if (bytes != null) {
      Arrays.fill(bytes, (byte) 0x00);
    }
  }

  private static void writeLength(ByteArrayOutputStream output, int length) {
    if (length < 0x80) {
      output.write(length);
    } else if (length <= 0xFF) {
      output.write(0x81);
      output.write(length);
    } else if (length <= 0xFFFF) {
      output.write(0x82);
      output.write((length >>> 8) & 0xFF);
      output.write(length & 0xFF);
    } else {
      throw new IllegalArgumentException("TLV value too large");
    }
  }

  private static byte[] fixed(BigInteger value, int size) {
    byte[] source = value.toByteArray();
    if (source.length > size + 1 || (source.length == size + 1 && source[0] != (byte) 0x00)) {
      throw new IllegalArgumentException("Integer does not fit in " + size + " bytes");
    }
    byte[] output = new byte[size];
    int copyLength = Math.min(source.length, size);
    System.arraycopy(source, source.length - copyLength, output, size - copyLength, copyLength);
    return output;
  }

  private static int coordinateSize(ECPublicKey publicKey) {
    return (publicKey.getParams().getCurve().getField().getFieldSize() + 7) / 8;
  }

  private static void requireObjectId(byte[] objectId) {
    if (objectId == null || objectId.length < 1 || objectId.length > 3) {
      throw new IllegalArgumentException("PIV object identifier must be 1 to 3 bytes");
    }
  }
}
