package dev.mistial.tools.openfips201.provisioning;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.crypto.CryptoProviders;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.icao.DataGroupHash;
import org.bouncycastle.asn1.icao.LDSSecurityObject;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.Test;

/**
 * Issuer CMS preflight: SP 800-73-5 Part 1 Section 3.1.2.1 (CHUID eContentType and pivSigner-DN),
 * SP 800-85B AS06.04.06 (Security Object eContentType 1.3.27.1.1.1), SP 800-78-5 Table 2 (hash per
 * signer key) and Section 3.2.3 (LDS hashes use the signature hash).
 */
class CertificationProfileValidatorCmsTest {
  private static final ASN1ObjectIdentifier ID_DATA =
      new ASN1ObjectIdentifier("1.2.840.113549.1.7.1");
  private static final ASN1ObjectIdentifier ID_PIV_CHUID_SECURITY_OBJECT =
      new ASN1ObjectIdentifier("2.16.840.1.101.3.6.1");
  private static final ASN1ObjectIdentifier ID_PIV_SIGNER_DN =
      new ASN1ObjectIdentifier("2.16.840.1.101.3.6.5");
  private static final ASN1ObjectIdentifier ID_ICAO_LDS_SECURITY_OBJECT =
      new ASN1ObjectIdentifier("1.3.27.1.1.1");
  private static final byte[] CCC =
      HexUtil.parse("F000F100F200F300F400F50110F600F700FA00FB00FC00FD00FE00");
  private static final byte[] PRINTED_INFORMATION =
      HexUtil.parse(
          "0101410201420409323032364A414E3031050143060F414141414141414141414141414141FE00");
  private static final byte[] CHUID_FIELDS =
      HexUtil.parse(
          "3019"
              + "D4E739DA739CED39CE739D836858210842108421C84210C3EB"
              + "3410"
              + "00112233445566778899AABBCCDDEEFF"
              + "3508"
              + "3230333031323331");

  /** One knob per conformance property; defaults produce a conforming profile. */
  private static final class Profile {
    String curve = "secp256r1";
    String chuidSignature = "SHA256withECDSA";
    String securityObjectSignature = "SHA256withECDSA";
    ASN1ObjectIdentifier chuidType = ID_PIV_CHUID_SECURITY_OBJECT;
    ASN1ObjectIdentifier securityObjectType = ID_ICAO_LDS_SECURITY_OBJECT;
    boolean pivSignerDn = true;
    X500Name pivSignerDnValue;
    ASN1ObjectIdentifier ldsDigest = NISTObjectIdentifiers.id_sha256;

    Profile p384() {
      curve = "secp384r1";
      chuidSignature = "SHA384withECDSA";
      securityObjectSignature = "SHA384withECDSA";
      ldsDigest = NISTObjectIdentifiers.id_sha384;
      return this;
    }

    Map<String, ConformancePackage.DataObject> build() throws Exception {
      CryptoProviders.ensureBouncyCastle();
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
      generator.initialize(new ECGenParameterSpec(curve));
      KeyPair keyPair = generator.generateKeyPair();
      X500Name subject = new X500Name("CN=Test PIV Content Signer");
      X509Certificate certificate =
          new JcaX509CertificateConverter()
              .setProvider("BC")
              .getCertificate(
                  new JcaX509v3CertificateBuilder(
                          subject,
                          BigInteger.ONE,
                          new Date(),
                          new Date(System.currentTimeMillis() + 86_400_000L),
                          subject,
                          keyPair.getPublic())
                      .build(
                          new JcaContentSignerBuilder(chuidSignature)
                              .setProvider("BC")
                              .build(keyPair.getPrivate())));

      byte[] signedChuid = concat(CHUID_FIELDS, HexUtil.parse("FE00"));
      AttributeTable chuidAttributes = null;
      if (pivSignerDn) {
        ASN1EncodableVector attributes = new ASN1EncodableVector();
        attributes.add(
            new Attribute(
                ID_PIV_SIGNER_DN,
                new DERSet(pivSignerDnValue == null ? subject : pivSignerDnValue)));
        chuidAttributes = new AttributeTable(attributes);
      }
      byte[] chuidCms =
          sign(
              signedChuid,
              chuidType,
              chuidSignature,
              keyPair,
              certificate,
              chuidAttributes,
              true,
              false);
      byte[] chuid = concat(CHUID_FIELDS, concat(tlv(0x3E, chuidCms), HexUtil.parse("FE00")));

      MessageDigest digest = MessageDigest.getInstance(ldsDigest.getId(), "BC");
      LDSSecurityObject lds =
          new LDSSecurityObject(
              new AlgorithmIdentifier(ldsDigest),
              new DataGroupHash[] {
                new DataGroupHash(1, new DEROctetString(digest.digest(CCC))),
                new DataGroupHash(2, new DEROctetString(digest.digest(PRINTED_INFORMATION)))
              });
      byte[] soCms =
          sign(
              lds.getEncoded("DER"),
              securityObjectType,
              securityObjectSignature,
              keyPair,
              certificate,
              null,
              false,
              true);
      byte[] securityObject =
          concat(
              tlv(0xBA, HexUtil.parse("01DB00023001")),
              concat(tlv(0xBB, soCms), HexUtil.parse("FE00")));

      Map<String, ConformancePackage.DataObject> objects =
          new HashMap<String, ConformancePackage.DataObject>();
      objects.put("5FC107", object("5FC107", CCC));
      objects.put("5FC109", object("5FC109", PRINTED_INFORMATION));
      objects.put("5FC102", object("5FC102", chuid));
      objects.put("5FC106", object("5FC106", securityObject));
      return objects;
    }
  }

  @Test
  void acceptsConformingP256AndP384IssuerSignatures() {
    assertDoesNotThrow(
        () -> CertificationProfileValidator.validateSecurityObject(new Profile().build()));
    assertDoesNotThrow(
        () -> CertificationProfileValidator.validateSecurityObject(new Profile().p384().build()));
  }

  @Test
  void rejectsChuidWithoutPivChuidContentType() throws Exception {
    Profile profile = new Profile();
    profile.chuidType = ID_DATA;
    assertRejected(profile, "eContentType");
  }

  @Test
  void rejectsChuidWithoutPivSignerDn() throws Exception {
    Profile profile = new Profile();
    profile.pivSignerDn = false;
    assertRejected(profile, "pivSigner-DN");
  }

  @Test
  void rejectsChuidPivSignerDnOtherThanSignerSubject() throws Exception {
    Profile profile = new Profile();
    profile.pivSignerDnValue = new X500Name("CN=Someone Else");
    assertRejected(profile, "pivSigner-DN");
  }

  @Test
  void rejectsP384ChuidSignedWithSha256() throws Exception {
    Profile profile = new Profile().p384();
    profile.chuidSignature = "SHA256withECDSA";
    assertRejected(profile, "Table 2");
  }

  @Test
  void rejectsP384SecurityObjectSignedWithSha256() throws Exception {
    Profile profile = new Profile().p384();
    profile.securityObjectSignature = "SHA256withECDSA";
    profile.ldsDigest = NISTObjectIdentifiers.id_sha256;
    assertRejected(profile, "Table 2");
  }

  @Test
  void rejectsSecurityObjectWithoutLdsContentType() throws Exception {
    Profile profile = new Profile();
    profile.securityObjectType = ID_DATA;
    assertRejected(profile, "eContentType");
  }

  @Test
  void rejectsLdsHashesOtherThanTheSignatureHash() throws Exception {
    Profile profile = new Profile();
    profile.ldsDigest = NISTObjectIdentifiers.id_sha384;
    assertRejected(profile, "hash algorithm");
  }

  private static void assertRejected(Profile profile, String reason) throws Exception {
    Map<String, ConformancePackage.DataObject> objects = profile.build();
    IllegalArgumentException failure =
        assertThrows(
            IllegalArgumentException.class,
            () -> CertificationProfileValidator.validateSecurityObject(objects));
    assertTrue(
        failure.getMessage().contains(reason),
        "expected '" + reason + "' in: " + failure.getMessage());
  }

  private static byte[] sign(
      byte[] content,
      ASN1ObjectIdentifier contentType,
      String algorithm,
      KeyPair keyPair,
      X509Certificate certificate,
      AttributeTable signedAttributes,
      boolean includeCertificate,
      boolean encapsulate)
      throws Exception {
    ContentSigner signer =
        new JcaContentSignerBuilder(algorithm).setProvider("BC").build(keyPair.getPrivate());
    JcaSignerInfoGeneratorBuilder signerInfo =
        new JcaSignerInfoGeneratorBuilder(
            new JcaDigestCalculatorProviderBuilder().setProvider("BC").build());
    if (signedAttributes != null) {
      signerInfo.setSignedAttributeGenerator(
          new DefaultSignedAttributeTableGenerator(signedAttributes));
    }
    CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
    generator.addSignerInfoGenerator(signerInfo.build(signer, certificate));
    if (includeCertificate) {
      generator.addCertificates(new JcaCertStore(Collections.singletonList(certificate)));
    }
    return generator
        .generate(new CMSProcessableByteArray(contentType, content), encapsulate)
        .getEncoded();
  }

  private static ConformancePackage.DataObject object(String id, byte[] payload) {
    return new ConformancePackage.DataObject(
        HexUtil.parse(id),
        id,
        (byte) 0x7F,
        (byte) 0x7F,
        ConformancePackage.PutForm.TAG_LIST,
        payload);
  }

  private static byte[] tlv(int tag, byte[] value) {
    byte[] header;
    if (value.length < 0x80) header = new byte[] {(byte) tag, (byte) value.length};
    else if (value.length <= 0xFF)
      header = new byte[] {(byte) tag, (byte) 0x81, (byte) value.length};
    else
      header =
          new byte[] {(byte) tag, (byte) 0x82, (byte) (value.length >> 8), (byte) value.length};
    return concat(header, value);
  }

  private static byte[] concat(byte[] a, byte[] b) {
    byte[] out = Arrays.copyOf(a, a.length + b.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }
}
