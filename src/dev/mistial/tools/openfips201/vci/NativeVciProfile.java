/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.vci;

import static dev.mistial.tools.openfips201.common.ByteArrays.concat;

import apdu4j.core.BIBO;
import dev.mistial.tools.openfips201.common.BerTlvReader;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.provisioning.CertificationProfileValidator;
import dev.mistial.tools.openfips201.provisioning.ConformancePackage;
import dev.mistial.tools.openfips201.provisioning.IcamCardFolder;
import java.io.ByteArrayOutputStream;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.icao.DataGroupHash;
import org.bouncycastle.asn1.icao.LDSSecurityObject;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/** Builds a signed SP 800-73-5 VCI profile from the public GSA identity fixtures. */
public final class NativeVciProfile {
  public static final byte SUITE_CS2 = (byte) 0x27;
  public static final byte SUITE_CS7 = (byte) 0x2E;
  private static final byte ACCESS_PIN = (byte) 0x01;
  private static final byte ACCESS_VCI = (byte) 0x08;
  private static final byte ACCESS_ALWAYS = (byte) 0x7F;
  private static final byte[] ID_CHUID = HexUtil.parse("5FC102");
  private static final byte[] ID_SECURITY_OBJECT = HexUtil.parse("5FC106");
  private static final byte[] ID_DISCOVERY = HexUtil.parse("7E");
  private static final byte[] ID_SM_SIGNER = HexUtil.parse("5FC122");
  private static final byte[] ID_PAIRING = HexUtil.parse("5FC123");

  private NativeVciProfile() {}

  public static Material build(
      Path icamDirectory, String caOutPrefix, String pairingCode, byte suite) throws Exception {
    VciProvisioning.ensureProvider();
    ConformancePackage base = IcamCardFolder.load(icamDirectory);
    VciProvisioning.CaMaterial signer =
        VciProvisioning.makeCa(caOutPrefix, "CN=OpenFIPS201 VCI Content Signer", suite);
    ConformancePackage profile = augment(base, signer.privateKey, signer.certificate, pairingCode);
    CertificationProfileValidator.validate(
        profile, new CertificationProfileValidator.Claims(true, true, true));
    return new Material(
        profile, caOutPrefix + ".crt", caOutPrefix + ".key", signer.certificate, suite);
  }

  public static final class Material {
    public final ConformancePackage profile;
    public final String signerCertificatePath;
    public final String signerKeyPath;
    public final X509Certificate signerCertificate;
    public final byte suite;

    Material(
        ConformancePackage profile,
        String signerCertificatePath,
        String signerKeyPath,
        X509Certificate signerCertificate,
        byte suite) {
      this.profile = profile;
      this.signerCertificatePath = signerCertificatePath;
      this.signerKeyPath = signerKeyPath;
      this.signerCertificate = signerCertificate;
      this.suite = suite;
    }
  }

  /** Issues the on-card SM key and CVC after the material's profile has been provisioned. */
  public static void provisionSmCredential(BIBO bibo, Material material) throws Exception {
    if (bibo == null || material == null) {
      throw new IllegalArgumentException("transport and native profile material are required");
    }
    VciProvisioning.provisionSmCredentialOnly(
        bibo, material.signerCertificatePath, material.signerKeyPath, null, material.suite);
  }

  private static ConformancePackage augment(
      ConformancePackage base,
      PrivateKey signerKey,
      X509Certificate signerCertificate,
      String pairingCode)
      throws Exception {
    if (pairingCode == null || !pairingCode.matches("[0-9]{8}")) {
      throw new IllegalArgumentException("pairing code must be exactly eight decimal digits");
    }
    List<ConformancePackage.DataObject> objects = new ArrayList<ConformancePackage.DataObject>();
    ConformancePackage.DataObject oldChuid = null;
    for (ConformancePackage.DataObject object : base.dataObjects) {
      String id = HexUtil.format(object.id);
      if (id.equals("5FC102")) oldChuid = object;
      if (!id.equals("5FC102") && !id.equals("5FC106") && !id.equals("7E")) {
        objects.add(object);
      }
    }
    if (oldChuid == null) throw new IllegalArgumentException("base profile has no CHUID");

    objects.add(
        data(
            ID_DISCOVERY,
            "SP 800-73-5 VCI Discovery Object",
            ACCESS_ALWAYS,
            ACCESS_ALWAYS,
            ConformancePackage.PutForm.DISCOVERY,
            HexUtil.parse("7E124F0BA0000003080000100001005F2F024800")));
    objects.add(
        data(
            ID_SM_SIGNER,
            "Secure Messaging Certificate Signer",
            ACCESS_ALWAYS,
            ACCESS_ALWAYS,
            ConformancePackage.PutForm.TAG_LIST,
            concat(
                VciSupport.tlv(0x70, signerCertificate.getEncoded()),
                VciSupport.tlv(0x71, new byte[] {0x00}),
                VciSupport.tlv(0xFE, new byte[0]))));
    objects.add(
        data(
            ID_PAIRING,
            "Pairing Code Reference Data",
            ACCESS_PIN,
            (byte) (ACCESS_VCI | ACCESS_PIN),
            ConformancePackage.PutForm.TAG_LIST,
            concat(
                VciSupport.tlv(0x99, pairingCode.getBytes("US-ASCII")),
                VciSupport.tlv(0xFE, new byte[0]))));

    byte[] chuid = resignChuid(oldChuid.payload, signerKey, signerCertificate);
    objects.add(
        data(
            ID_CHUID,
            "SP 800-73-5 Cardholder Unique Identifier",
            ACCESS_ALWAYS,
            ACCESS_ALWAYS,
            ConformancePackage.PutForm.TAG_LIST,
            chuid));
    byte[] securityObject = buildSecurityObject(objects, signerKey, signerCertificate);
    objects.add(
        data(
            ID_SECURITY_OBJECT,
            "SP 800-73-5 Security Object",
            ACCESS_ALWAYS,
            ACCESS_VCI,
            ConformancePackage.PutForm.TAG_LIST,
            securityObject));

    return new ConformancePackage(
        base.credentialId + "-SP800-73-5-VCI",
        base.sourceDirectory,
        base.pin,
        base.puk,
        base.managementKey,
        objects,
        base.keys);
  }

  private static byte[] resignChuid(byte[] oldPayload, PrivateKey key, X509Certificate certificate)
      throws Exception {
    ByteArrayOutputStream content = new ByteArrayOutputStream();
    int offset = 0;
    while (offset < oldPayload.length) {
      BerTlvReader.Tlv item = BerTlvReader.read(oldPayload, offset);
      if (item.tag != 0x32 && item.tag != 0x3E && item.tag != 0xFE) {
        content.write(oldPayload, offset, item.nextOffset - offset);
      }
      offset = item.nextOffset;
    }
    content.write(VciSupport.tlv(0xFE, new byte[0]));
    byte[] signedContent = content.toByteArray();
    byte[] signature = signCms(signedContent, key, certificate, true, false);
    return concat(
        Arrays.copyOf(signedContent, signedContent.length - 2),
        VciSupport.tlv(0x3E, signature),
        VciSupport.tlv(0xFE, new byte[0]));
  }

  private static byte[] buildSecurityObject(
      List<ConformancePackage.DataObject> objects, PrivateKey key, X509Certificate certificate)
      throws Exception {
    String[][] required = {
      {"5FC107", "DB00"}, {"5FC109", "3001"}, {"7E", "6050"}, {"5FC123", "1018"}
    };
    ByteArrayOutputStream mapping = new ByteArrayOutputStream();
    List<DataGroupHash> hashes = new ArrayList<DataGroupHash>();
    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    int dg = 1;
    for (String[] entry : required) {
      ConformancePackage.DataObject object = find(objects, entry[0]);
      if (object == null) continue;
      int container = Integer.parseInt(entry[1], 16);
      mapping.write(dg);
      mapping.write(container >>> 8);
      mapping.write(container);
      byte[] hashInput = object.payload;
      if (entry[0].equals("7E")) {
        BerTlvReader.Tlv discovery = BerTlvReader.read(object.payload, 0);
        hashInput = Arrays.copyOfRange(object.payload, discovery.valueOffset, discovery.nextOffset);
      }
      hashes.add(new DataGroupHash(dg, new DEROctetString(sha256.digest(hashInput))));
      dg++;
    }
    LDSSecurityObject lds =
        new LDSSecurityObject(
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256),
            hashes.toArray(new DataGroupHash[hashes.size()]));
    byte[] cms = signCms(lds.getEncoded("DER"), key, certificate, false, true);
    return concat(
        VciSupport.tlv(0xBA, mapping.toByteArray()),
        VciSupport.tlv(0xBB, cms),
        VciSupport.tlv(0xFE, new byte[0]));
  }

  private static byte[] signCms(
      byte[] content,
      PrivateKey key,
      X509Certificate certificate,
      boolean includeCertificate,
      boolean encapsulate)
      throws Exception {
    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(key);
    CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
    generator.addSignerInfoGenerator(
        new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
            .build(signer, certificate));
    if (includeCertificate) {
      generator.addCertificates(new JcaCertStore(Arrays.asList(certificate)));
    }
    CMSSignedData signed = generator.generate(new CMSProcessableByteArray(content), encapsulate);
    return signed.getEncoded();
  }

  private static ConformancePackage.DataObject find(
      List<ConformancePackage.DataObject> objects, String id) {
    for (ConformancePackage.DataObject object : objects) {
      if (HexUtil.format(object.id).equals(id)) return object;
    }
    return null;
  }

  private static ConformancePackage.DataObject data(
      byte[] id,
      String label,
      byte contact,
      byte contactless,
      ConformancePackage.PutForm form,
      byte[] payload) {
    return new ConformancePackage.DataObject(id, label, contact, contactless, form, payload);
  }
}
