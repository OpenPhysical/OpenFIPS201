/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.attestation;

import static dev.mistial.tools.openfips201.attestation.AttestationTestChains.AT;
import static dev.mistial.tools.openfips201.attestation.AttestationTestChains.SAMPLE_OPID;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import dev.mistial.tools.openfips201.attestation.AttestationTestChains.Chain;
import dev.mistial.tools.openfips201.attestation.AttestationTestChains.Options;
import dev.mistial.tools.openfips201.attestation.VerificationReport.Entry;
import dev.mistial.tools.openfips201.attestation.VerificationReport.Status;
import dev.mistial.tools.openfips201.opid.Lcg;
import dev.mistial.tools.openfips201.opid.Opid;
import dev.mistial.tools.openfips201.opid.OpidSequence;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.Test;

class AttestationVerifierTest {
  private static final OpidSequence SEQUENCE =
      OpidSequence.of(1234, 4711, Lcg.of(21, 7, 0), new byte[32]);
  private static final long SEQ = 5;

  // ---- positive ----

  @Test
  void fullChainIsValid() throws Exception {
    Chain chain = AttestationTestChains.build();
    VerificationReport report =
        AttestationVerifier.verify(
            chain
                .request()
                .expectOpid(SAMPLE_OPID)
                .slotCertificate(AttestationTestChains.selfSigned(chain.leafKey))
                .chuidValue(AttestationTestChains.chuid(SAMPLE_OPID))
                .build());
    assertValid(report);
    for (String id :
        new String[] {
          AttestationVerifier.DER_ROOT,
          AttestationVerifier.DER_SAM,
          AttestationVerifier.DER_F9,
          AttestationVerifier.DER_LEAF,
          AttestationVerifier.PKIX_PATH,
          AttestationVerifier.F9_OPID,
          AttestationVerifier.F9_SKI,
          AttestationVerifier.F9_EXPECT_OPID,
          AttestationVerifier.LEAF_KEY_USAGE,
          AttestationVerifier.LEAF_KEY_REFERENCE,
          AttestationVerifier.LEAF_SLOT_SPKI,
          AttestationVerifier.CHUID_IDENTITY
        }) {
      assertEquals(Status.PASS, status(report, id), id);
    }
    assertEquals(Status.SKIP, status(report, AttestationVerifier.F9_LCG_AUDIT));
  }

  @Test
  void chainWithoutLeafIsValid() throws Exception {
    Chain chain = AttestationTestChains.build();
    VerificationReport report =
        AttestationVerifier.verify(
            VerificationRequest.builder()
                .anchor(chain.root)
                .samCertificate(chain.sam)
                .f9Certificate(chain.f9)
                .at(AT)
                .build());
    assertValid(report);
    assertEquals(Status.SKIP, status(report, AttestationVerifier.LEAF));
    assertEquals(Status.PASS, status(report, AttestationVerifier.PKIX_PATH));
  }

  @Test
  void lcgAuditMatches() throws Exception {
    Options options = new Options();
    options.opid = SEQUENCE.opidAt(SEQ);
    options.issuanceSeq = SEQ;
    Chain chain = AttestationTestChains.build(options);
    VerificationReport report =
        AttestationVerifier.verify(chain.request().sequence(SEQUENCE).issuanceSeq(SEQ).build());
    assertValid(report);
    assertEquals(Status.PASS, status(report, AttestationVerifier.F9_LCG_AUDIT));
  }

  @Test
  void keyEstablishmentLeafWithKeyAgreementIsValid() throws Exception {
    Options options = new Options();
    options.leafRole = AttestationVerifier.ROLE_KEY_ESTABLISH;
    options.leafKeyUsage = KeyUsage.keyAgreement;
    options.leafKeyReference = 0x9D;
    assertValid(AttestationVerifier.verify(AttestationTestChains.build(options).request().build()));
  }

  @Test
  void reportSerializesAsJson() throws Exception {
    VerificationReport report =
        AttestationVerifier.verify(AttestationTestChains.build().request().build());
    JsonObject json = JsonParser.parseString(report.toJson()).getAsJsonObject();
    assertTrue(json.get("valid").getAsBoolean());
    JsonObject first = json.getAsJsonArray("checks").get(0).getAsJsonObject();
    assertEquals(AttestationVerifier.DER_ROOT, first.get("checkId").getAsString());
    assertEquals("PASS", first.get("status").getAsString());
    assertTrue(report.toTable().contains("RESULT: VALID"));
  }

  // ---- negative ----

  @Test
  void wrongAnchorFailsPath() throws Exception {
    Chain chain = AttestationTestChains.build();
    Chain other = AttestationTestChains.build();
    VerificationReport report =
        AttestationVerifier.verify(chain.request().anchor(other.root).build());
    assertFails(report, AttestationVerifier.PKIX_PATH);
    assertFails(report, AttestationVerifier.SAM_SIGNATURE);
    assertFails(report, AttestationVerifier.SAM_AKI);
  }

  @Test
  void tamperedRootSignatureFails() throws Exception {
    Chain chain = AttestationTestChains.build();
    VerificationReport report =
        AttestationVerifier.verify(
            chain.request().anchor(AttestationTestChains.tamperLastByte(chain.root)).build());
    assertFails(report, AttestationVerifier.ROOT_SELF_SIGNED);
  }

  @Test
  void tamperedSamSignatureFails() throws Exception {
    Chain chain = AttestationTestChains.build();
    VerificationReport report =
        AttestationVerifier.verify(
            chain
                .request()
                .samCertificate(AttestationTestChains.tamperLastByte(chain.sam))
                .build());
    assertFails(report, AttestationVerifier.PKIX_PATH);
    assertFails(report, AttestationVerifier.SAM_SIGNATURE);
  }

  @Test
  void tamperedF9SignatureFails() throws Exception {
    Chain chain = AttestationTestChains.build();
    VerificationReport report =
        AttestationVerifier.verify(
            chain.request().f9Certificate(AttestationTestChains.tamperLastByte(chain.f9)).build());
    assertFails(report, AttestationVerifier.PKIX_PATH);
    assertFails(report, AttestationVerifier.F9_SIGNATURE);
  }

  @Test
  void tamperedLeafSignatureFails() throws Exception {
    Chain chain = AttestationTestChains.build();
    VerificationReport report =
        AttestationVerifier.verify(
            chain.request().leaf(AttestationTestChains.tamperLastByte(chain.leaf)).build());
    assertFails(report, AttestationVerifier.PKIX_PATH);
    assertFails(report, AttestationVerifier.LEAF_SIGNATURE);
  }

  @Test
  void samPathLenZeroFails() throws Exception {
    Options options = new Options();
    options.samPathLen = 0;
    assertFails(build(options), AttestationVerifier.SAM_BASIC_CONSTRAINTS);
  }

  @Test
  void f9WithoutPathLenFails() throws Exception {
    Options options = new Options();
    options.f9PathLen = null;
    assertFails(build(options), AttestationVerifier.F9_BASIC_CONSTRAINTS);
  }

  @Test
  void f9SerialNumberThatIsNotAnOpidFails() throws Exception {
    Options options = new Options();
    options.f9SerialNumber = "NOTANOPID";
    VerificationReport report = build(options);
    assertFails(report, AttestationVerifier.F9_OPID);
  }

  @Test
  void f9SerialNumberWithBadLuhnFails() throws Exception {
    Options options = new Options();
    String printed = SAMPLE_OPID.toPrinted();
    char last = printed.charAt(printed.length() - 1);
    options.f9SerialNumber =
        printed.substring(0, printed.length() - 1) + (char) ('0' + (last - '0' + 1) % 10);
    VerificationReport report = build(options);
    assertFails(report, AttestationVerifier.F9_OPID);
    assertTrue(report.entry(AttestationVerifier.F9_OPID).get().detail().contains("check digit"));
  }

  @Test
  void f9AuthorityKeyIdentifierMismatchFails() throws Exception {
    Options options = new Options();
    options.f9AuthorityKeyId = new byte[20];
    assertFails(build(options), AttestationVerifier.F9_AKI);
  }

  @Test
  void issuerDifferingOnlyInStringEncodingFails() throws Exception {
    Options options = new Options();
    options.f9IssuerUtf8 = true;
    assertFails(build(options), AttestationVerifier.F9_ISSUER);
  }

  @Test
  void trailingByteFailsStrictDer() throws Exception {
    Chain chain = AttestationTestChains.build();
    VerificationReport report =
        AttestationVerifier.verify(
            chain
                .request()
                .f9Certificate(AttestationTestChains.withTrailingByte(chain.f9))
                .build());
    assertFails(report, AttestationVerifier.DER_F9);
    assertEquals(Status.SKIP, status(report, AttestationVerifier.F9_OPID));
  }

  @Test
  void nonMinimalLengthFailsStrictDer() throws Exception {
    Chain chain = AttestationTestChains.build();
    VerificationReport report =
        AttestationVerifier.verify(
            chain.request().leaf(AttestationTestChains.withNonMinimalLength(chain.leaf)).build());
    assertFails(report, AttestationVerifier.DER_LEAF);
  }

  @Test
  void strictDerRejectsBerForms() throws Exception {
    byte[] der = AttestationTestChains.build().root;
    StrictDer.parseCertificate(der);
    assertThrows(
        IllegalArgumentException.class,
        () -> StrictDer.parseCertificate(AttestationTestChains.withTrailingByte(der)));
    assertThrows(
        IllegalArgumentException.class,
        () -> StrictDer.parseCertificate(AttestationTestChains.withNonMinimalLength(der)));
    // BOOLEAN TRUE must be encoded as FF (X.690 Section 11.1).
    assertThrows(
        IllegalArgumentException.class, () -> StrictDer.parse(new byte[] {0x30, 3, 1, 1, 1}));
    // Indefinite length.
    assertThrows(
        IllegalArgumentException.class,
        () -> StrictDer.parse(new byte[] {0x30, (byte) 0x80, 2, 1, 1, 0, 0}));
  }

  @Test
  void expiredSamAtEvaluationTimeFails() throws Exception {
    Options options = new Options();
    options.samExpiresBeforeAt = true;
    assertFails(build(options), AttestationVerifier.PKIX_PATH);
  }

  @Test
  void leafSpkiDifferentFromSlotCertificateFails() throws Exception {
    Chain chain = AttestationTestChains.build();
    byte[] slot = AttestationTestChains.selfSigned(AttestationTestChains.ecKey("secp256r1"));
    VerificationReport report =
        AttestationVerifier.verify(chain.request().slotCertificate(slot).build());
    assertFails(report, AttestationVerifier.LEAF_SLOT_SPKI);
  }

  @Test
  void opidIinDifferentFromSamIssuerIdFails() throws Exception {
    Options options = new Options();
    options.samIssuerId = 4321;
    assertFails(build(options), AttestationVerifier.F9_OPID_BATCH);
  }

  @Test
  void samBatchNumberIsNotComparedWithTheEncipheredOpid() throws Exception {
    Options options = new Options();
    options.samBatch = 9999;
    VerificationReport report = build(options);
    assertValid(report);
    assertEquals(Status.PASS, status(report, AttestationVerifier.F9_OPID_BATCH));
  }

  @Test
  void eighteenDigitFormatOpidIsRejected() throws Exception {
    Options options = new Options();
    options.f9SerialNumber = "123401234123456782";
    assertFails(build(options), AttestationVerifier.F9_OPID);
  }

  @Test
  void sequenceAuditMismatchFails() throws Exception {
    Options options = new Options();
    options.opid = SEQUENCE.opidAt(SEQ + 1);
    options.issuanceSeq = SEQ;
    Chain chain = AttestationTestChains.build(options);
    VerificationReport report =
        AttestationVerifier.verify(chain.request().sequence(SEQUENCE).build());
    assertFails(report, AttestationVerifier.F9_LCG_AUDIT);
  }

  @Test
  void sequenceAuditUnderAnotherIinKeyFails() throws Exception {
    Options options = new Options();
    options.opid = SEQUENCE.opidAt(SEQ);
    options.issuanceSeq = SEQ;
    Chain chain = AttestationTestChains.build(options);
    byte[] otherKey = new byte[32];
    otherKey[0] = 1;
    OpidSequence other = OpidSequence.of(1234, 4711, Lcg.of(21, 7, 0), otherKey);
    assertFails(
        AttestationVerifier.verify(chain.request().sequence(other).build()),
        AttestationVerifier.F9_LCG_AUDIT);
  }

  @Test
  void expectedIssuanceSeqMismatchFails() throws Exception {
    Options options = new Options();
    options.opid = SEQUENCE.opidAt(SEQ);
    options.issuanceSeq = SEQ;
    Chain chain = AttestationTestChains.build(options);
    VerificationReport report =
        AttestationVerifier.verify(chain.request().sequence(SEQUENCE).issuanceSeq(SEQ + 1).build());
    assertFails(report, AttestationVerifier.F9_LCG_AUDIT);
  }

  @Test
  void expectOpidMismatchFails() throws Exception {
    Chain chain = AttestationTestChains.build();
    VerificationReport report =
        AttestationVerifier.verify(chain.request().expectOpid(Opid.of(1234, 1)).build());
    assertFails(report, AttestationVerifier.F9_EXPECT_OPID);
  }

  @Test
  void signRoleWithKeyAgreementUsageFails() throws Exception {
    Options options = new Options();
    options.leafKeyUsage = KeyUsage.keyAgreement;
    assertFails(build(options), AttestationVerifier.LEAF_KEY_USAGE);
  }

  @Test
  void signRoleWithExtraUsageBitFails() throws Exception {
    Options options = new Options();
    options.leafKeyUsage = KeyUsage.digitalSignature | KeyUsage.nonRepudiation;
    assertFails(build(options), AttestationVerifier.LEAF_KEY_USAGE);
  }

  @Test
  void leafCommonNameNotNamingTheSlotFails() throws Exception {
    Options options = new Options();
    options.leafCommonName = "PIV Attestation 9C";
    assertFails(build(options), AttestationVerifier.LEAF_KEY_REFERENCE);
  }

  @Test
  void importedLeafOriginFails() throws Exception {
    Options options = new Options();
    options.leafOrigin = 1;
    assertFails(build(options), AttestationVerifier.LEAF_ORIGIN);
  }

  @Test
  void chuidMismatchFails() throws Exception {
    Chain chain = AttestationTestChains.build();
    VerificationReport report =
        AttestationVerifier.verify(
            chain.request().chuidValue(AttestationTestChains.chuid(Opid.of(1234, 1))).build());
    assertFails(report, AttestationVerifier.CHUID_IDENTITY);
  }

  @Test
  void leafWithoutF9FailsStructure() throws Exception {
    Chain chain = AttestationTestChains.build();
    VerificationReport report =
        AttestationVerifier.verify(
            VerificationRequest.builder()
                .anchor(chain.root)
                .samCertificate(chain.sam)
                .leaf(chain.leaf)
                .at(AT)
                .build());
    assertFails(report, AttestationVerifier.CHAIN_STRUCTURE);
  }

  @Test
  void garbageInputNeverThrows() {
    VerificationReport report =
        AttestationVerifier.verify(
            VerificationRequest.builder()
                .anchor(new byte[] {0x30, 0x00})
                .samCertificate(new byte[] {0x01})
                .f9Certificate(new byte[] {0x04, 0x01, 0x00})
                .leaf(new byte[] {(byte) 0xFF})
                .chuidValue(new byte[] {0x53})
                .build());
    assertFalse(report.valid());
    assertFails(report, AttestationVerifier.DER_ROOT);
  }

  @Test
  void subjectNameCodecRoundTrips() {
    X500Name template =
        new X500Name(
            new RDN[] {new RDN(AttestationVerifier.COMMON_NAME, new DERPrintableString("F9"))});
    X500Name name = F9SubjectNames.withOpid(template, SAMPLE_OPID);
    assertEquals(SAMPLE_OPID, F9SubjectNames.extractOpid(name));
    assertThrows(IllegalArgumentException.class, () -> F9SubjectNames.withOpid(name, SAMPLE_OPID));
    assertThrows(IllegalArgumentException.class, () -> F9SubjectNames.extractOpid(template));
  }

  // ---- build and card measurements ----

  @Test
  void measurementsAreReportedAndSkippedWithoutExpectations() throws Exception {
    VerificationReport report =
        AttestationVerifier.verify(AttestationTestChains.build().request().build());
    assertValid(report);
    assertEquals(Status.SKIP, status(report, AttestationVerifier.F9_EXPECT_CAP));
    assertEquals(Status.SKIP, status(report, AttestationVerifier.F9_EXPECT_CPLC));
    assertEquals(Status.SKIP, status(report, AttestationVerifier.LEAF_EXPECT_BUILD));
    String issuance = detail(report, AttestationVerifier.F9_ISSUANCE_EXTENSION);
    assertTrue(issuance.contains("capSha256 " + hex(AttestationTestChains.CAP_SHA256)), issuance);
    assertTrue(issuance.contains("cplcSha256 " + hex(AttestationTestChains.CPLC_SHA256)), issuance);
    String leaf = detail(report, AttestationVerifier.LEAF_EXTENSION);
    assertTrue(leaf.contains("buildSha256 " + hex(AttestationTestChains.BUILD_SHA256)), leaf);
  }

  @Test
  void matchingMeasurementsPass() throws Exception {
    VerificationReport report =
        AttestationVerifier.verify(
            AttestationTestChains.build()
                .request()
                .expectCapSha256(AttestationTestChains.CAP_SHA256)
                .expectCplcSha256(AttestationTestChains.CPLC_SHA256)
                .expectBuildSha256(AttestationTestChains.BUILD_SHA256)
                .build());
    assertValid(report);
    assertEquals(Status.PASS, status(report, AttestationVerifier.F9_EXPECT_CAP));
    assertEquals(Status.PASS, status(report, AttestationVerifier.F9_EXPECT_CPLC));
    assertEquals(Status.PASS, status(report, AttestationVerifier.LEAF_EXPECT_BUILD));
  }

  @Test
  void mismatchedCapHashFails() throws Exception {
    byte[] other = AttestationTestChains.CAP_SHA256.clone();
    other[31] ^= 1;
    assertFails(
        AttestationVerifier.verify(
            AttestationTestChains.build().request().expectCapSha256(other).build()),
        AttestationVerifier.F9_EXPECT_CAP);
  }

  @Test
  void mismatchedCplcHashFails() throws Exception {
    byte[] other = AttestationTestChains.CPLC_SHA256.clone();
    other[0] ^= 1;
    assertFails(
        AttestationVerifier.verify(
            AttestationTestChains.build().request().expectCplcSha256(other).build()),
        AttestationVerifier.F9_EXPECT_CPLC);
  }

  @Test
  void mismatchedBuildHashFails() throws Exception {
    byte[] other = AttestationTestChains.BUILD_SHA256.clone();
    other[7] ^= 1;
    assertFails(
        AttestationVerifier.verify(
            AttestationTestChains.build().request().expectBuildSha256(other).build()),
        AttestationVerifier.LEAF_EXPECT_BUILD);
  }

  @Test
  void expectedBuildWithoutLeafFails() throws Exception {
    Chain chain = AttestationTestChains.build();
    VerificationReport report =
        AttestationVerifier.verify(
            VerificationRequest.builder()
                .anchor(chain.root)
                .samCertificate(chain.sam)
                .f9Certificate(chain.f9)
                .at(AT)
                .expectBuildSha256(AttestationTestChains.BUILD_SHA256)
                .build());
    assertFails(report, AttestationVerifier.LEAF_EXPECT_BUILD);
  }

  @Test
  void versionOneExtensionsAreRejected() throws Exception {
    Options issuance = new Options();
    issuance.issuanceVersion = 1;
    assertFails(build(issuance), AttestationVerifier.F9_ISSUANCE_EXTENSION);
    Options leaf = new Options();
    leaf.leafVersion = 1;
    assertFails(build(leaf), AttestationVerifier.LEAF_EXTENSION);
    Options shortHash = new Options();
    shortHash.buildSha256 = new byte[31];
    assertFails(build(shortHash), AttestationVerifier.LEAF_EXTENSION);
  }

  @Test
  void measurementLengthsAreEnforcedByTheRequest() {
    assertThrows(
        IllegalArgumentException.class,
        () -> VerificationRequest.builder().expectCapSha256(new byte[31]));
  }

  // ---- helpers ----

  private static String detail(VerificationReport report, String id) {
    for (Entry entry : report.checks()) {
      if (entry.checkId().equals(id)) {
        return entry.detail();
      }
    }
    throw new AssertionError("no entry " + id);
  }

  private static String hex(byte[] value) {
    return org.bouncycastle.util.encoders.Hex.toHexString(value).toUpperCase(java.util.Locale.ROOT);
  }

  private static VerificationReport build(Options options) throws Exception {
    return AttestationVerifier.verify(AttestationTestChains.build(options).request().build());
  }

  private static Status status(VerificationReport report, String id) {
    return report.status(id).orElseThrow(() -> new AssertionError("no entry " + id));
  }

  private static void assertValid(VerificationReport report) {
    assertTrue(report.valid(), report.toTable());
    for (Entry entry : report.checks()) {
      assertFalse(entry.status() == Status.FAIL, entry.checkId() + ": " + entry.detail());
    }
  }

  private static void assertFails(VerificationReport report, String id) {
    assertFalse(report.valid(), report.toTable());
    assertEquals(Status.FAIL, status(report, id), report.toTable());
  }
}
