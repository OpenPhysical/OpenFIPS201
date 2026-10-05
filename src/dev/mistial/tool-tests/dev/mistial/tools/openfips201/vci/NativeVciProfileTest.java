package dev.mistial.tools.openfips201.vci;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.common.BerTlvReader;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.provisioning.ConformancePackage;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.icao.LDSSecurityObject;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NativeVciProfileTest {
  private static final Path GSA_CARD_46 =
      Paths.get(
          "test-vectors/gsa-icam-card-builder/cards/ICAM_Card_Objects/"
              + "46_Golden_FIPS_201-2_PIV");
  private static final ASN1ObjectIdentifier ID_PIV_CHUID_SECURITY_OBJECT =
      new ASN1ObjectIdentifier("2.16.840.1.101.3.6.1");
  private static final ASN1ObjectIdentifier ID_PIV_SIGNER_DN =
      new ASN1ObjectIdentifier("2.16.840.1.101.3.6.5");
  private static final ASN1ObjectIdentifier ID_ICAO_LDS_SECURITY_OBJECT =
      new ASN1ObjectIdentifier("1.3.27.1.1.1");

  @Test
  void buildsStrictCs2AndCs7ProfilesWithFreshIssuerIntegrity(@TempDir Path tempDir)
      throws Exception {
    for (byte suite : new byte[] {VciSupport.ALG_CS2, VciSupport.ALG_CS7}) {
      String prefix = tempDir.resolve(String.format("native-%02x", suite & 0xFF)).toString();
      NativeVciProfile.Material material =
          NativeVciProfile.build(GSA_CARD_46, prefix, "12345678", suite);

      assertEquals(13, material.profile.dataObjects.size());
      assertEquals(4, material.profile.keys.size());
      assertEquals(suite, material.suite);
      assertTrue(Files.isRegularFile(Paths.get(material.signerCertificatePath)));
      assertTrue(Files.isRegularFile(Paths.get(material.signerKeyPath)));
    }
  }

  /**
   * SP 800-78-5 Table 2 pairs P-384 with SHA-384; SP 800-73-5 Part 1 Section 3.1.2.1 requires the
   * CHUID eContentType id-PIV-CHUIDSecurityObject and a pivSigner-DN signed attribute; SP 800-85B
   * AS06.04.06 requires the Security Object eContentType id-icao-ldsSecurityObject (1.3.27.1.1.1);
   * SP 800-78-5 Section 3.2.3 requires the LDS hashes to use the signature's hash.
   */
  @Test
  void signsChuidAndSecurityObjectWithSuiteHashAndPivContentTypes(@TempDir Path tempDir)
      throws Exception {
    for (byte suite : new byte[] {VciSupport.ALG_CS2, VciSupport.ALG_CS7}) {
      boolean cs7 = suite == VciSupport.ALG_CS7;
      String digest =
          (cs7 ? NISTObjectIdentifiers.id_sha384 : NISTObjectIdentifiers.id_sha256).getId();
      String signature =
          (cs7 ? X9ObjectIdentifiers.ecdsa_with_SHA384 : X9ObjectIdentifiers.ecdsa_with_SHA256)
              .getId();
      String prefix = tempDir.resolve(String.format("cms-%02x", suite & 0xFF)).toString();
      NativeVciProfile.Material material =
          NativeVciProfile.build(GSA_CARD_46, prefix, "12345678", suite);

      CMSSignedData chuid = chuidSignature(payload(material.profile, "5FC102"));
      assertEquals(ID_PIV_CHUID_SECURITY_OBJECT.getId(), chuid.getSignedContentTypeOID());
      SignerInformation chuidSigner = chuid.getSignerInfos().getSigners().iterator().next();
      assertEquals(digest, chuidSigner.getDigestAlgOID(), "CHUID digest for suite " + suite);
      assertEquals(signature, chuidSigner.getEncryptionAlgOID(), "CHUID signature algorithm");
      Attribute signerDn = chuidSigner.getSignedAttributes().get(ID_PIV_SIGNER_DN);
      assertNotNull(signerDn, "CHUID must carry the pivSigner-DN signed attribute");
      assertEquals(
          X500Name.getInstance(material.signerCertificate.getSubjectX500Principal().getEncoded()),
          X500Name.getInstance(signerDn.getAttrValues().getObjectAt(0)));

      byte[] securityObject = payload(material.profile, "5FC106");
      BerTlvReader.Tlv mapping = BerTlvReader.read(securityObject, 0);
      BerTlvReader.Tlv cms = BerTlvReader.read(securityObject, mapping.nextOffset);
      CMSSignedData so =
          new CMSSignedData(Arrays.copyOfRange(securityObject, cms.valueOffset, cms.nextOffset));
      assertEquals(ID_ICAO_LDS_SECURITY_OBJECT.getId(), so.getSignedContentTypeOID());
      SignerInformation soSigner = so.getSignerInfos().getSigners().iterator().next();
      assertEquals(digest, soSigner.getDigestAlgOID(), "Security Object digest");
      assertEquals(signature, soSigner.getEncryptionAlgOID(), "Security Object signature");
      LDSSecurityObject lds =
          LDSSecurityObject.getInstance(
              ASN1Primitive.fromByteArray((byte[]) so.getSignedContent().getContent()));
      assertEquals(digest, lds.getDigestAlgorithmIdentifier().getAlgorithm().getId());
    }
  }

  private static byte[] payload(ConformancePackage profile, String id) {
    for (ConformancePackage.DataObject object : profile.dataObjects) {
      if (HexUtil.format(object.id).equals(id)) return object.payload;
    }
    throw new AssertionError("profile lacks " + id);
  }

  private static CMSSignedData chuidSignature(byte[] chuid) throws Exception {
    int offset = 0;
    while (offset < chuid.length) {
      BerTlvReader.Tlv element = BerTlvReader.read(chuid, offset);
      if (element.tag == 0x3E) {
        byte[] signedContent =
            concat(
                Arrays.copyOf(chuid, offset),
                Arrays.copyOfRange(chuid, element.nextOffset, chuid.length));
        return new CMSSignedData(
            new CMSProcessableByteArray(signedContent),
            Arrays.copyOfRange(chuid, element.valueOffset, element.nextOffset));
      }
      offset = element.nextOffset;
    }
    throw new AssertionError("CHUID lacks 3E");
  }

  private static byte[] concat(byte[] a, byte[] b) {
    byte[] out = Arrays.copyOf(a, a.length + b.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }
}
