/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.attestation;

import dev.mistial.tools.openfips201.opid.Opid;
import dev.mistial.tools.openfips201.opid.OpidIdentifiers;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Builds root -> SAM -> F9 -> leaf chains with configurable defects. */
final class AttestationTestChains {
  /** A 17-digit OPID under IIN 1234 (E = 123412345678; the batch is enciphered within E). */
  static final Opid SAMPLE_OPID = Opid.of(1234, 123412345678L);

  static final Date AT = date("2026-06-01T00:00:00Z");

  private static final SecureRandom RANDOM = new SecureRandom();

  private AttestationTestChains() {}

  /** Chain knobs; defaults produce a fully valid chain. */
  static final class Options {
    Opid opid = SAMPLE_OPID;
    /** serialNumber value; null means {@code opid.toPrinted()}. */
    String f9SerialNumber;

    Integer samPathLen = 1;
    Integer f9PathLen = 0;
    /** SAM batch extension issuerId; null means the OPID's IIN. */
    Integer samIssuerId;

    /** SAM batch extension batch number; the OPID enciphers its batch, so it is never compared. */
    int samBatch = 4711;

    long issuanceSeq = 1;
    int issuanceVersion = OpenPhysicalExtensions.F9_ISSUANCE_VERSION;
    byte[] capSha256 = CAP_SHA256;
    byte[] cplcSha256 = CPLC_SHA256;
    byte[] f9AuthorityKeyId;
    boolean f9IssuerUtf8;
    boolean samExpiresBeforeAt;

    int leafRole = AttestationVerifier.ROLE_SIGN;
    int leafKeyUsage = KeyUsage.digitalSignature;
    int leafKeyReference = 0x9A;
    String leafCommonName;
    int leafOrigin = 2;
    int leafVersion = OpenPhysicalExtensions.PIV_LEAF_VERSION;
    byte[] buildSha256 = BUILD_SHA256;
  }

  /** Default measurements the test chains record. */
  static final byte[] CAP_SHA256 = filled(0xCA);

  static final byte[] CPLC_SHA256 = filled(0xC1);
  static final byte[] BUILD_SHA256 = filled(0xB5);

  private static byte[] filled(int value) {
    byte[] out = new byte[32];
    Arrays.fill(out, (byte) value);
    return out;
  }

  /** A built chain: keys and exact DER encodings. */
  static final class Chain {
    KeyPair rootKey;
    KeyPair samKey;
    KeyPair f9Key;
    KeyPair leafKey;
    byte[] root;
    byte[] sam;
    byte[] f9;
    byte[] leaf;

    VerificationRequest.Builder request() {
      return VerificationRequest.builder()
          .anchor(root)
          .samCertificate(sam)
          .f9Certificate(f9)
          .leaf(leaf)
          .at(AT);
    }
  }

  static Chain build() throws Exception {
    return build(new Options());
  }

  static Chain build(Options o) throws Exception {
    Chain chain = new Chain();
    chain.rootKey = ecKey("secp256r1");
    chain.samKey = ecKey("secp256r1");
    chain.f9Key = ecKey("secp256r1");
    chain.leafKey = ecKey("secp256r1");

    X500Name rootName =
        new X500Name(
            new RDN[] {
              new RDN(AttestationVerifier.COMMON_NAME, new DERPrintableString("Test Root CA"))
            });
    X500Name samName = samName(false);
    X500Name f9Template =
        new X500Name(
            new RDN[] {
              new RDN(AttestationVerifier.COMMON_NAME, new DERPrintableString("F9 Authority"))
            });
    String serial = o.f9SerialNumber == null ? o.opid.toPrinted() : o.f9SerialNumber;
    RDN[] f9Rdns = Arrays.copyOf(f9Template.getRDNs(), 2);
    f9Rdns[1] = new RDN(F9SubjectNames.SERIAL_NUMBER, new DERPrintableString(serial));
    X500Name f9Name = new X500Name(f9Rdns);
    String cn =
        o.leafCommonName == null
            ? String.format("PIV Attestation %02X", o.leafKeyReference)
            : o.leafCommonName;
    X500Name leafName =
        new X500Name(new RDN[] {new RDN(AttestationVerifier.COMMON_NAME, new DERUTF8String(cn))});

    byte[] rootSki = ski(chain.rootKey);
    byte[] samSki = ski(chain.samKey);
    byte[] f9Ski = ski(chain.f9Key);

    X509v3CertificateBuilder root =
        builder(
            rootName,
            date("2026-01-01T00:00:00Z"),
            date("2036-01-01T00:00:00Z"),
            rootName,
            chain.rootKey);
    root.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    root.addExtension(
        Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
    root.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(rootSki));
    chain.root = sign(root, chain.rootKey.getPrivate());

    Date samEnd =
        o.samExpiresBeforeAt ? date("2026-05-01T00:00:00Z") : date("2035-01-01T00:00:00Z");
    X509v3CertificateBuilder sam =
        builder(rootName, date("2026-01-02T00:00:00Z"), samEnd, samName, chain.samKey);
    sam.addExtension(Extension.basicConstraints, true, basicConstraints(o.samPathLen));
    sam.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
    sam.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(samSki));
    sam.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(rootSki));
    int issuerId = o.samIssuerId == null ? o.opid.iin : o.samIssuerId;
    sam.addExtension(
        OpenPhysicalExtensions.SAM_BATCH,
        false,
        seq(
            new ASN1Integer(OpenPhysicalExtensions.SAM_BATCH_VERSION),
            new ASN1Integer(issuerId),
            new ASN1Integer(o.samBatch),
            new ASN1Integer(1000),
            new DEROctetString(new byte[8]),
            new DEROctetString(new byte[32]),
            new ASN1Integer(1),
            new DEROctetString(new byte[32])));
    chain.sam = sign(sam, chain.rootKey.getPrivate());

    Date f9End = o.samExpiresBeforeAt ? date("2026-04-30T00:00:00Z") : date("2034-01-01T00:00:00Z");
    X509v3CertificateBuilder f9 =
        builder(samName(o.f9IssuerUtf8), date("2026-02-01T00:00:00Z"), f9End, f9Name, chain.f9Key);
    f9.addExtension(Extension.basicConstraints, true, basicConstraints(o.f9PathLen));
    f9.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
    f9.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(f9Ski));
    f9.addExtension(
        Extension.authorityKeyIdentifier,
        false,
        new AuthorityKeyIdentifier(o.f9AuthorityKeyId == null ? samSki : o.f9AuthorityKeyId));
    f9.addExtension(
        OpenPhysicalExtensions.F9_ISSUANCE,
        false,
        seq(
            new ASN1Integer(o.issuanceVersion),
            new ASN1Integer(o.issuanceSeq),
            new ASN1Integer(o.issuanceSeq + 1),
            new DEROctetString(new byte[32]),
            new DEROctetString(o.capSha256),
            new DEROctetString(o.cplcSha256)));
    chain.f9 = sign(f9, chain.samKey.getPrivate());

    Date leafEnd =
        o.samExpiresBeforeAt ? date("2026-04-29T00:00:00Z") : date("2033-01-01T00:00:00Z");
    X509v3CertificateBuilder leaf =
        builder(f9Name, date("2026-03-01T00:00:00Z"), leafEnd, leafName, chain.leafKey);
    leaf.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
    leaf.addExtension(Extension.keyUsage, true, new KeyUsage(o.leafKeyUsage));
    leaf.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(f9Ski));
    leaf.addExtension(
        OpenPhysicalExtensions.PIV_LEAF,
        false,
        seq(
            new ASN1Integer(o.leafVersion),
            new DEROctetString(new byte[] {1, 4, 0, 0}),
            octet(OpenPhysicalExtensions.BUILD_FLAG_ATTESTATION),
            octet(0x27),
            new DEROctetString("TEST".getBytes(StandardCharsets.US_ASCII)),
            octet(o.leafKeyReference),
            octet(0x11),
            octet(o.leafRole),
            octet(0x00),
            new ASN1Enumerated(o.leafOrigin),
            octet(0x7F),
            octet(0x7F),
            new DEROctetString(o.buildSha256)));
    chain.leaf = sign(leaf, chain.f9Key.getPrivate());
    return chain;
  }

  /** Self-contained certificate over a fresh key, used as an unrelated slot certificate. */
  static byte[] selfSigned(KeyPair key) throws Exception {
    X500Name name =
        new X500Name(
            new RDN[] {new RDN(AttestationVerifier.COMMON_NAME, new DERUTF8String("Slot"))});
    X509v3CertificateBuilder builder =
        builder(name, date("2026-01-01T00:00:00Z"), date("2030-01-01T00:00:00Z"), name, key);
    return sign(builder, key.getPrivate());
  }

  /**
   * CHUID element list carrying the FASC-N (tag 30) and GUID (tag 34) derived from {@code opid}.
   */
  static byte[] chuid(Opid opid) {
    byte[] fascN = OpidIdentifiers.fascNBytes(opid);
    byte[] guid = OpidIdentifiers.guidBytes(opid);
    byte[] out = new byte[2 + fascN.length + 2 + guid.length];
    out[0] = 0x30;
    out[1] = (byte) fascN.length;
    System.arraycopy(fascN, 0, out, 2, fascN.length);
    out[2 + fascN.length] = 0x34;
    out[3 + fascN.length] = (byte) guid.length;
    System.arraycopy(guid, 0, out, 4 + fascN.length, guid.length);
    return out;
  }

  /** Copy of {@code der} with its final octet (the last signature octet) inverted. */
  static byte[] tamperLastByte(byte[] der) {
    byte[] out = der.clone();
    out[out.length - 1] ^= (byte) 0xFF;
    return out;
  }

  /** Copy of {@code der} with one trailing 0x00 octet. */
  static byte[] withTrailingByte(byte[] der) {
    return Arrays.copyOf(der, der.length + 1);
  }

  /**
   * Re-encodes the outer {@code 30 82 HH LL} header with the non-minimal {@code 30 83 00 HH LL}.
   */
  static byte[] withNonMinimalLength(byte[] der) {
    if ((der[0] & 0xFF) != 0x30 || (der[1] & 0xFF) != 0x82) {
      throw new IllegalStateException("expected a 30 82 header");
    }
    byte[] out = new byte[der.length + 1];
    out[0] = 0x30;
    out[1] = (byte) 0x83;
    out[2] = 0x00;
    System.arraycopy(der, 2, out, 3, der.length - 2);
    return out;
  }

  static String pem(byte[] der) {
    return "-----BEGIN CERTIFICATE-----\n"
        + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der)
        + "\n-----END CERTIFICATE-----\n";
  }

  static KeyPair ecKey(String curve) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec(curve), RANDOM);
    return generator.generateKeyPair();
  }

  static Date date(String instant) {
    return Date.from(Instant.parse(instant));
  }

  private static X500Name samName(boolean utf8) {
    ASN1Encodable value = utf8 ? new DERUTF8String("Test SAM") : new DERPrintableString("Test SAM");
    return new X500Name(new RDN[] {new RDN(AttestationVerifier.COMMON_NAME, value)});
  }

  private static BasicConstraints basicConstraints(Integer pathLen) {
    return pathLen == null ? new BasicConstraints(true) : new BasicConstraints(pathLen);
  }

  private static byte[] ski(KeyPair key) {
    return AttestationVerifier.keyIdentifierMethod1(
        SubjectPublicKeyInfo.getInstance(key.getPublic().getEncoded()));
  }

  private static X509v3CertificateBuilder builder(
      X500Name issuer, Date notBefore, Date notAfter, X500Name subject, KeyPair key) {
    byte[] serial = new byte[16];
    RANDOM.nextBytes(serial);
    serial[0] &= 0x7F;
    serial[0] |= 0x01;
    return new X509v3CertificateBuilder(
        issuer,
        new BigInteger(serial),
        notBefore,
        notAfter,
        subject,
        SubjectPublicKeyInfo.getInstance(key.getPublic().getEncoded()));
  }

  private static byte[] sign(X509v3CertificateBuilder builder, PrivateKey key) throws Exception {
    return builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(key)).getEncoded();
  }

  private static DERSequence seq(ASN1Encodable... elements) {
    return new DERSequence(elements);
  }

  private static DEROctetString octet(int value) {
    return new DEROctetString(new byte[] {(byte) value});
  }
}
