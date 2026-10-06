package dev.mistial.tests.issuersam;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** End-to-end issuance: OPID sequence, F9 profile, PKIX chains, ledger chain and recovery. */
class IssuerSamIssuanceTest extends IssuerSamTestSupport {

  @ParameterizedTest(name = "parameter set {0}")
  @ValueSource(ints = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
  void issuesReferenceOpidSequenceAndProfile(int variant) throws Exception {
    Params params = Params.variant(root, variant);
    params.quota = 3;
    byte[] genesis = personalize(params);
    X509CertificateHolder samCert = samCertificate();
    byte[] samPoint = samCert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
    byte[] samSki = ski(samPoint);

    byte[][] genesisParts = entryAndSignature(genesis);
    assertTrue(verify(publicKey(samPoint), genesisParts[0], genesisParts[1]), "genesis sig");
    byte[] prevHead = sha256(genesisParts[0]);

    for (long n = 1; n <= 3; n++) {
      Issued issued = issueOne();
      X509CertificateHolder f9 = new X509CertificateHolder(issued.certificate);
      String opid = referenceOpid(params, n);
      assertEquals(opid, serialNumberOf(f9), "OPID for issuance " + n);
      assertProfile(f9, samCert, issued.f9, samSki, n, prevHead);
      assertTrue(f9.isSignatureValid(new JcaContentVerifierProviderBuilder().build(samCert)));

      // ISSUE entry
      byte[] entry = issued.entry;
      assertArrayEquals("OPSAMLE1".getBytes(), Arrays.copyOf(entry, 8));
      assertEquals(0x02, entry[8]);
      assertArrayEquals(samSki, Arrays.copyOfRange(entry, 9, 29));
      assertEquals(n + 1, new BigInteger(1, Arrays.copyOfRange(entry, 29, 33)).longValue());
      assertArrayEquals(prevHead, Arrays.copyOfRange(entry, 33, 65));
      assertEquals(n, new BigInteger(1, Arrays.copyOfRange(entry, 65, 69)).longValue());
      int opidLength = entry[69];
      assertEquals(opid, new String(entry, 70, opidLength, "US-ASCII"));
      int cursor = 70 + opidLength;
      assertArrayEquals(
          ski(point(issued.f9.getPublic())), Arrays.copyOfRange(entry, cursor, cursor + 20));
      assertArrayEquals(CAP_SHA256, Arrays.copyOfRange(entry, cursor + 20, cursor + 52));
      assertArrayEquals(CPLC_SHA256, Arrays.copyOfRange(entry, cursor + 52, cursor + 84));
      assertArrayEquals(
          sha256(f9.toASN1Structure().getTBSCertificate().getEncoded("DER")),
          Arrays.copyOfRange(entry, cursor + 84, cursor + 116));
      assertEquals(entry.length, cursor + 116);
      assertEquals(203, entry.length);
      assertTrue(verify(publicKey(samPoint), entry, issued.signature), "entry signature");
      prevHead = sha256(entry);
    }
    assertArrayEquals(prevHead, chainHead());
    assertEquals(3, issued());
  }

  @Test
  void pkixRootSamF9LeafValidatesAndPathLenZeroBlocksSubordinateCa() throws Exception {
    Params params = Params.variant(root, 0);
    personalize(params);
    X509CertificateHolder samCert = samCertificate();
    Issued issued = issueOne();
    X509CertificateHolder f9 = new X509CertificateHolder(issued.certificate);

    KeyPair leafKey = newP256();
    X509CertificateHolder leaf =
        childCertificate(f9, issued.f9, leafKey, new X500Name("CN=PIV Attestation 9A"), null);
    validatePath(leaf, f9, samCert);

    KeyPair subKey = newP256();
    X509CertificateHolder subCa =
        childCertificate(f9, issued.f9, subKey, new X500Name("CN=Rogue Sub CA"), 0);
    X509CertificateHolder subLeaf =
        childCertificate(subCa, subKey, newP256(), new X500Name("CN=Rogue Leaf"), null);
    assertThrows(
        CertPathValidatorException.class, () -> validatePathWithSub(subLeaf, subCa, f9, samCert));
  }

  @Test
  void signedStatusMatchesRecomputedChainFromGenesis() throws Exception {
    Params params = Params.variant(root, 5);
    byte[] genesis = personalize(params);
    byte[] head = sha256(entryAndSignature(genesis)[0]);
    for (int i = 0; i < 2; i++) head = sha256(issueOne().entry);

    byte[] samPoint = samCertificate().getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
    byte[] nonce = new byte[20];
    new java.security.SecureRandom().nextBytes(nonce);
    byte[] signed = collect(transmit(0x80, 0xCA, 0x01, 0x01, nonce), "signed STATUS");
    int sigTag = signed.length;
    // The status TLV is followed by 9E L sig.
    int offset = 0;
    while ((signed[offset] & 0xFF) != 0x9E) {
      offset += 1 + derLengthSize(signed, offset + 1) + derLength(signed, offset + 1);
    }
    sigTag = offset;
    byte[] statusTlv = Arrays.copyOf(signed, sigTag);
    byte[] sig = Arrays.copyOfRange(signed, sigTag + 2, signed.length);
    assertTrue(
        verify(publicKey(samPoint), concat("OPSAMSTAT1".getBytes(), nonce, statusTlv), sig),
        "STATUS signature");
    assertArrayEquals(head, tlvValue(statusTlv, 0x8A));
    assertEquals(2, new BigInteger(1, tlvValue(statusTlv, 0x85)).longValue());
    assertEquals(3, new BigInteger(1, tlvValue(statusTlv, 0x89)).longValue());
    assertEquals(LC_OPERATIONAL, tlvValue(statusTlv, 0x80)[0]);
  }

  @Test
  void paramsDigestInSamCertificateMatchesHostReference() throws Exception {
    Params params = Params.variant(root, 7);
    personalize(params);
    // LOAD SAM CERTIFICATE accepted the root-signed batch extension built from the host Lcg
    // digest, so the SAM's own paramsDigest equals the host value.
    X509CertificateHolder samCert = samCertificate();
    byte[] value =
        ASN1OctetString.getInstance(
                samCert
                    .getExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.57923.20.10.10.3"))
                    .getExtnValue())
            .getOctets();
    ASN1Sequence batch = ASN1Sequence.getInstance(value);
    assertArrayEquals(
        referenceParamsDigest(params),
        ASN1OctetString.getInstance(batch.getObjectAt(5)).getOctets());
    assertEquals(8, batch.size(), "batch extension v3 has eight fields");
    assertEquals(BigInteger.valueOf(3), ASN1Integer.getInstance(batch.getObjectAt(0)).getValue());
  }

  //
  // Helpers.
  //

  static String serialNumberOf(X509CertificateHolder cert) {
    RDN[] rdns = cert.getSubject().getRDNs();
    RDN last = rdns[rdns.length - 1];
    assertEquals(BCStyle.SERIALNUMBER, last.getFirst().getType());
    assertEquals(1, cert.getSubject().getRDNs(BCStyle.SERIALNUMBER).length);
    return last.getFirst().getValue().toString();
  }

  static void assertProfile(
      X509CertificateHolder f9,
      X509CertificateHolder samCert,
      KeyPair f9Key,
      byte[] samSki,
      long seq,
      byte[] prevHead)
      throws Exception {
    assertEquals(3, f9.getVersionNumber());
    assertTrue(f9.getSerialNumber().signum() > 0);
    assertTrue(f9.getSerialNumber().bitLength() <= 127);
    assertEquals(samCert.getSubject(), f9.getIssuer());
    assertArrayEquals(samCert.getSubject().getEncoded("DER"), f9.getIssuer().getEncoded("DER"));
    assertArrayEquals(
        point(f9Key.getPublic()), f9.getSubjectPublicKeyInfo().getPublicKeyData().getBytes());
    Extension bc = f9.getExtension(Extension.basicConstraints);
    assertTrue(bc.isCritical());
    assertArrayEquals(hex("3006 0101FF 020100"), bc.getExtnValue().getOctets());
    Extension ku = f9.getExtension(Extension.keyUsage);
    assertTrue(ku.isCritical());
    assertArrayEquals(hex("03020204"), ku.getExtnValue().getOctets());
    assertArrayEquals(
        concat(hex("0414"), ski(point(f9Key.getPublic()))),
        f9.getExtension(Extension.subjectKeyIdentifier).getExtnValue().getOctets());
    assertArrayEquals(
        concat(hex("30168014"), samSki),
        f9.getExtension(Extension.authorityKeyIdentifier).getExtnValue().getOctets());
    Extension issuance = f9.getExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.57923.20.10.10.2"));
    assertFalse(issuance.isCritical());
    ASN1Sequence value = ASN1Sequence.getInstance(issuance.getExtnValue().getOctets());
    assertEquals(6, value.size());
    assertEquals(BigInteger.valueOf(2), ASN1Integer.getInstance(value.getObjectAt(0)).getValue());
    assertEquals(BigInteger.valueOf(seq), ASN1Integer.getInstance(value.getObjectAt(1)).getValue());
    assertEquals(
        BigInteger.valueOf(seq + 1), ASN1Integer.getInstance(value.getObjectAt(2)).getValue());
    assertArrayEquals(prevHead, DEROctetString.getInstance(value.getObjectAt(3)).getOctets());
    assertArrayEquals(CAP_SHA256, DEROctetString.getInstance(value.getObjectAt(4)).getOctets());
    assertArrayEquals(CPLC_SHA256, DEROctetString.getInstance(value.getObjectAt(5)).getOctets());
    assertArrayEquals(
        issuanceExtensionDer(seq, seq + 1, prevHead, CAP_SHA256, CPLC_SHA256),
        issuance.getExtnValue().getOctets(),
        "issuance extension v2 DER");
    assertTrue(f9.getEncoded().length <= 0x2F8);
  }

  /**
   * Golden DER of the F9 issuance extension v2 value, written out field by field: {@code 30 L {02
   * 01 02, 02 L issuanceSeq, 02 L eventSeq, 04 20 prevChainHead, 04 20 capSha256, 04 20
   * cplcSha256}} with minimal positive INTEGER encodings.
   */
  static byte[] issuanceExtensionDer(
      long issuanceSeq, long eventSeq, byte[] prevHead, byte[] capSha256, byte[] cplcSha256) {
    byte[] body =
        concat(
            hex("020102"),
            tlv(0x02, BigInteger.valueOf(issuanceSeq).toByteArray()),
            tlv(0x02, BigInteger.valueOf(eventSeq).toByteArray()),
            tlv(0x04, prevHead),
            tlv(0x04, capSha256),
            tlv(0x04, cplcSha256));
    return tlv(0x30, body);
  }

  @Test
  void issuanceExtensionGoldenEncoding() throws Exception {
    // issuanceSeq 1 and eventSeq 2 (the first ISSUE after GENESIS).
    byte[] head = new byte[32];
    Arrays.fill(head, (byte) 0x11);
    byte[] cap = new byte[32];
    Arrays.fill(cap, (byte) 0x22);
    byte[] cplc = new byte[32];
    Arrays.fill(cplc, (byte) 0x33);
    byte[] expected =
        hex(
            "306F"
                + "020102"
                + "020101"
                + "020102"
                + "0420"
                + "1111111111111111111111111111111111111111111111111111111111111111"
                + "0420"
                + "2222222222222222222222222222222222222222222222222222222222222222"
                + "0420"
                + "3333333333333333333333333333333333333333333333333333333333333333");
    assertArrayEquals(expected, issuanceExtensionDer(1, 2, head, cap, cplc));

    Params params = Params.variant(root, 0);
    byte[] genesis = personalize(params);
    Issued issued = issueOne();
    X509CertificateHolder f9 = new X509CertificateHolder(issued.certificate);
    byte[] actual =
        f9.getExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.57923.20.10.10.2"))
            .getExtnValue()
            .getOctets();
    assertArrayEquals(
        issuanceExtensionDer(1, 2, sha256(entryAndSignature(genesis)[0]), CAP_SHA256, CPLC_SHA256),
        actual);
    assertEquals(0x30, actual[0] & 0xFF);
    assertEquals(0x6F, actual[1] & 0xFF);
  }

  static X509CertificateHolder childCertificate(
      X509CertificateHolder issuer,
      KeyPair issuerKey,
      KeyPair subjectKey,
      X500Name subject,
      Integer caPathLen)
      throws Exception {
    long now = System.currentTimeMillis();
    X509v3CertificateBuilder builder =
        new X509v3CertificateBuilder(
            issuer.getSubject(),
            BigInteger.valueOf(now),
            new Date(now - 60_000L),
            new Date(now + 365L * 86_400_000L),
            subject,
            spki(point(subjectKey.getPublic())));
    if (caPathLen != null) {
      builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(caPathLen));
      builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
    } else {
      builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
      builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
    }
    return builder.build(TestRoot.signer(issuerKey));
  }

  void validatePath(X509CertificateHolder... chain) throws Exception {
    validate(chain);
  }

  void validatePathWithSub(X509CertificateHolder... chain) throws Exception {
    validate(chain);
  }

  private void validate(X509CertificateHolder[] chain) throws Exception {
    JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    java.util.List<X509Certificate> certificates = new java.util.ArrayList<>();
    for (X509CertificateHolder holder : chain) {
      certificates.add(
          (X509Certificate)
              factory.generateCertificate(new ByteArrayInputStream(holder.getEncoded())));
    }
    X509Certificate anchor = converter.getCertificate(root.certificate);
    CertPath path = factory.generateCertPath(certificates);
    PKIXParameters parameters =
        new PKIXParameters(Collections.singleton(new TrustAnchor(anchor, null)));
    parameters.setRevocationEnabled(false);
    assertNotNull(CertPathValidator.getInstance("PKIX").validate(path, parameters));
  }
}
