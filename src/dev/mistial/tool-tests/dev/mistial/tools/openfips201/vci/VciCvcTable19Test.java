package dev.mistial.tools.openfips201.vci;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.common.HexUtil;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

/**
 * SP 800-73-5 Part 2 Table 19 CVC fields (42 = signer SKI[0:8], 5F20 = Card UUID) and the Table 15
 * H4/H5 host checks on the card's OPACITY response.
 */
class VciCvcTable19Test {
  private static final byte[] GUID = HexUtil.parse("0123456789ABCDEF0123456789ABCDEF");

  @Test
  void generatedSignerCarriesSkiWhoseLeftmostEightBytesAreTheIin() throws Exception {
    for (byte suite : new byte[] {VciSupport.ALG_CS2, VciSupport.ALG_CS7}) {
      X509Certificate signer =
          VciProvisioning.makeCa(null, "CN=Table 19 Signer", suite).certificate;
      byte[] extension = signer.getExtensionValue(Extension.subjectKeyIdentifier.getId());
      assertNotNull(extension, "generated VCI signer must carry a subjectKeyIdentifier");
      byte[] ski =
          SubjectKeyIdentifier.getInstance(ASN1OctetString.getInstance(extension).getOctets())
              .getKeyIdentifier();
      byte[] iin = VciSupport.issuerIdFromCertificate(signer);
      assertArrayEquals(Arrays.copyOf(ski, 8), iin);
      // The .NET CVC issuer derives the IIN as SHA-256(SPKI)[0:8]; generated signers agree.
      byte[] spkiHash =
          MessageDigest.getInstance("SHA-256").digest(signer.getPublicKey().getEncoded());
      assertArrayEquals(Arrays.copyOf(spkiHash, 8), iin);
    }
  }

  @Test
  void rejectsSignerCertificateWithoutSubjectKeyIdentifier() throws Exception {
    VciProvisioning.ensureProvider();
    KeyPair keyPair = keyPair("secp256r1");
    X500Name name = new X500Name("CN=No SKI");
    X509Certificate certificate =
        new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(
                new JcaX509v3CertificateBuilder(
                        name,
                        BigInteger.ONE,
                        new Date(),
                        new Date(System.currentTimeMillis() + 86_400_000L),
                        name,
                        keyPair.getPublic())
                    .build(
                        new JcaContentSignerBuilder("SHA256withECDSA")
                            .setProvider("BC")
                            .build(keyPair.getPrivate())));
    assertThrows(
        IllegalArgumentException.class, () -> VciSupport.issuerIdFromCertificate(certificate));
  }

  @Test
  void cvcSubjectIsTheChuidGuid() {
    byte[] chuid =
        HexUtil.parse(
            "53"
                + "3B"
                + "3019D4E739DA739CED39CE739D836858210842108421C84210C3EB"
                + "3410"
                + HexUtil.format(GUID)
                + "35083230333031323331"
                + "3E00"
                + "FE00");
    assertArrayEquals(GUID, VciProvisioning.cardUuidFromChuid(chuid));
    assertThrows(
        IllegalArgumentException.class,
        () -> VciProvisioning.cardUuidFromChuid(HexUtil.parse("530A35083230333031323331")));
  }

  @Test
  void rejectsNonZeroCbIccAndCvcCurveOtherThanTheSuite() throws Exception {
    VciProvisioning.ensureProvider();
    byte[] p256 = cvc(keyPair("secp256r1"));
    byte[] p384 = cvc(keyPair("secp384r1"));

    assertDoesNotThrow(() -> VciSupport.checkCardResponse((byte) 0x00, p256, VciSupport.ALG_CS2));
    assertDoesNotThrow(() -> VciSupport.checkCardResponse((byte) 0x00, p384, VciSupport.ALG_CS7));

    IllegalArgumentException cbIcc =
        assertThrows(
            IllegalArgumentException.class,
            () -> VciSupport.checkCardResponse((byte) 0x01, p256, VciSupport.ALG_CS2));
    assertTrue(cbIcc.getMessage().contains("H4"));
    IllegalArgumentException domain =
        assertThrows(
            IllegalArgumentException.class,
            () -> VciSupport.checkCardResponse((byte) 0x00, p256, VciSupport.ALG_CS7));
    assertTrue(domain.getMessage().contains("H5"));
    assertThrows(
        IllegalArgumentException.class,
        () -> VciSupport.checkCardResponse((byte) 0x00, p384, VciSupport.ALG_CS2));
  }

  private static byte[] cvc(KeyPair cardKey) {
    byte[] point = ((ECPublicKey) cardKey.getPublic()).getQ().getEncoded(false);
    byte[] body = VciSupport.buildCvcBody(point, new byte[8], GUID);
    return VciSupport.assembleCvc(body, HexUtil.parse("3006020101020101"));
  }

  private static KeyPair keyPair(String curve) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
    generator.initialize(new ECGenParameterSpec(curve));
    return generator.generateKeyPair();
  }
}
