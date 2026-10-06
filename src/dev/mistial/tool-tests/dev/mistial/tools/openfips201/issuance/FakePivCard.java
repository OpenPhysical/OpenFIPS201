/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import dev.mistial.tools.openfips201.attestation.F9SubjectNames;
import dev.mistial.tools.openfips201.attestation.OpenPhysicalExtensions;
import dev.mistial.tools.openfips201.common.BerTlvWriter;
import dev.mistial.tools.openfips201.common.ByteArrays;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.crypto.KeyIdentifiers;
import dev.mistial.tools.openfips201.gp.DerivedScpKeys;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** A PIV card in software: on-card F9, proof of possession, F9 load and attestation leaves. */
final class FakePivCard implements PivIssuanceClient {
  /** The CPLC data the card serves, as hex. */
  static final String CPLC =
      "4790503347905033000000000000000000000000000000000000000000000000000000000000000000000000";

  /** The build identity the card's attestation leaves carry ({@code build.sha256}). */
  static final byte[] BUILD_SHA256 =
      IssuanceCrypto.sha256("fake PIV applet build".getBytes(StandardCharsets.US_ASCII));

  final List<String> calls = new ArrayList<String>();
  String cplc = CPLC;
  byte[] buildSha256 = BUILD_SHA256;
  byte[] kdd = {0, 0, 0x42, 0x42, 0x4A, 0x43, 0x45, 0x4E, 0x42, 0x42};
  byte[] finalKdd;
  KeyPair f9;
  byte[] loaded;
  DerivedScpKeys rotated;

  @Override
  public CardIdentity readIdentity() {
    calls.add("identity");
    byte[] value = finalKdd != null && calls.contains("install") ? finalKdd : kdd;
    return new CardIdentity(cplc, Collections.<String, String>emptyMap(), value);
  }

  @Override
  public void installApplet() {
    calls.add("install");
    instancePresent = true;
  }

  /** Whether GP status lists the PIV instance. */
  boolean instancePresent;

  @Override
  public boolean pivInstancePresent() {
    calls.add("present");
    return instancePresent;
  }

  @Override
  public void deleteInstance(ScpConfig keys) {
    calls.add("delete");
    instancePresent = false;
  }

  @Override
  public void restoreStockKeys(ScpConfig current, int version) {
    calls.add("restore");
    rotated = null;
  }

  @Override
  public byte[] generateF9() {
    calls.add("generate");
    f9 = IssuanceTestKeys.p256();
    return IssuanceCrypto.point(f9.getPublic());
  }

  @Override
  public byte[] proveF9(byte[] nonce) throws Exception {
    calls.add("prove");
    Signature signature = Signature.getInstance("SHA256withECDSA");
    signature.initSign(f9.getPrivate());
    signature.update(
        ByteArrays.concat(
            CardIssuanceOrchestrator.PREFIX_POP, nonce, IssuanceCrypto.point(f9.getPublic())));
    return signature.sign();
  }

  @Override
  public void loadF9Certificate(byte[] certificate) {
    calls.add("load");
    loaded = certificate.clone();
  }

  @Override
  public byte[] readF9Certificate() {
    calls.add("read");
    return loaded.clone();
  }

  @Override
  public ProofResult attestProofKey() throws Exception {
    calls.add("proof");
    Certificate f9Certificate = Certificate.getInstance(loaded);
    KeyPair leafKey = IssuanceTestKeys.p256();
    X509v3CertificateBuilder leaf =
        new X509v3CertificateBuilder(
            f9Certificate.getSubject(),
            BigInteger.valueOf(System.nanoTime()).abs().add(BigInteger.ONE),
            f9Certificate.getStartDate().getDate(),
            f9Certificate.getEndDate().getDate(),
            new X500Name(
                new RDN[] {
                  new RDN(
                      org.bouncycastle.asn1.x500.style.BCStyle.CN,
                      new DERUTF8String("PIV Attestation 9A"))
                }),
            SubjectPublicKeyInfo.getInstance(leafKey.getPublic().getEncoded()));
    leaf.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
    leaf.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
    leaf.addExtension(
        Extension.authorityKeyIdentifier,
        false,
        new AuthorityKeyIdentifier(KeyIdentifiers.ski(f9.getPublic())));
    leaf.addExtension(
        OpenPhysicalExtensions.PIV_LEAF,
        false,
        new DERSequence(
            new ASN1Encodable[] {
              new ASN1Integer(OpenPhysicalExtensions.PIV_LEAF_VERSION),
              new DEROctetString(new byte[] {1, 11, 0, 0}),
              octet(OpenPhysicalExtensions.BUILD_FLAG_ATTESTATION),
              octet(0x27),
              new DEROctetString("standard".getBytes(StandardCharsets.US_ASCII)),
              octet(0x9A),
              octet(0x11),
              octet(0x04),
              octet(0x00),
              new ASN1Enumerated(OpenPhysicalExtensions.ORIGIN_GENERATED),
              octet(0x01),
              octet(0x09),
              new DEROctetString(buildSha256)
            }));
    byte[] encoded =
        leaf.build(new JcaContentSignerBuilder("SHA256withECDSA").build(f9.getPrivate()))
            .getEncoded();
    return new ProofResult(encoded, IssuanceCrypto.point(leafKey.getPublic()), true);
  }

  @Override
  public byte[] getVersion() {
    calls.add("version");
    return BerTlvWriter.encode(0x53, BerTlvWriter.encode(0x81, new byte[] {1}));
  }

  @Override
  public byte[] getStatus() {
    calls.add("status");
    Certificate certificate = Certificate.getInstance(loaded);
    String opid = F9SubjectNames.extractOpid(certificate.getSubject()).toPrinted();
    return BerTlvWriter.encode(
        0x53,
        ByteArrays.concat(
            BerTlvWriter.encode(0x89, new byte[] {0x03}),
            BerTlvWriter.encode(0x8A, opid.getBytes(StandardCharsets.US_ASCII)),
            BerTlvWriter.encode(0x8B, KeyIdentifiers.ski(f9.getPublic()))));
  }

  @Override
  public void rotateKeys(DerivedScpKeys keys) {
    calls.add("rotate");
    rotated = keys;
  }

  private static DEROctetString octet(int value) {
    return new DEROctetString(new byte[] {(byte) value});
  }
}
