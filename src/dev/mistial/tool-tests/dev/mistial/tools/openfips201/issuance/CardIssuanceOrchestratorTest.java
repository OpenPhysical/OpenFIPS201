/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.SecureFiles;
import dev.mistial.tools.openfips201.opid.Opid;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** The per-card sequence against the {@link SoftIssuerSam} oracle and a software card. */
class CardIssuanceOrchestratorTest {
  @TempDir Path home;
  private String previousHome;
  private SoftBatch soft;

  @BeforeEach
  void bindBatch() throws Exception {
    previousHome = System.getProperty("openfips201.home");
    soft = SoftBatch.create(home, "orchestrated", 1234, 5);
  }

  @AfterEach
  void restoreHome() {
    if (previousHome == null) {
      System.clearProperty("openfips201.home");
    } else {
      System.setProperty("openfips201.home", previousHome);
    }
  }

  private CardIssuanceOrchestrator.Result produce(
      FakePivCard card, CardIssuanceOrchestrator.StageHooks hooks) throws Exception {
    return new CardIssuanceOrchestrator(soft.inputs(), soft.sam, card, hooks).produce();
  }

  private static CardIssuanceOrchestrator.StageHooks failAt(final IssuanceStage target) {
    return new CardIssuanceOrchestrator.StageHooks() {
      @Override
      public void before(IssuanceStage stage) {
        if (stage == target) {
          throw new IllegalStateException("injected fault at " + stage);
        }
      }
    };
  }

  private static final CardIssuanceOrchestrator.StageHooks NONE = failAt(null);

  @Test
  void producesAndRecordsEveryStage() throws Exception {
    FakePivCard card = new FakePivCard();
    CardIssuanceOrchestrator.Result result = produce(card, NONE);

    assertEquals(CardIssuanceOrchestrator.EXIT_OK, result.exitCode);
    IssuanceReceipt receipt = IssuanceReceipt.read(result.receipt);
    assertEquals(IssuanceReceipt.SCHEMA, receipt.schema);
    assertEquals(IssuanceReceipt.STATUS_COMPLETED, receipt.status);
    assertEquals(IssuanceStage.values().length, receipt.stages.size());
    for (int i = 0; i < IssuanceStage.values().length; i++) {
      assertEquals(IssuanceStage.values()[i].name(), receipt.stages.get(i).stage);
    }
    Opid expected = soft.expected(1);
    assertEquals(expected.toPrinted(), receipt.sam.opid);
    assertEquals(expected.toPrinted(), receipt.identifiers.opid);
    assertNotNull(receipt.identifiers.fascN);
    assertTrue(receipt.f9.readBackIdentical);
    assertTrue(receipt.proof.keyDeleted);
    assertTrue(receipt.verification.containsKey("f9"));
    assertTrue(receipt.verification.containsKey("proof"));
    assertNotNull(card.rotated, "keys rotated");
    if (SecureFiles.isPosix(home)) {
      assertEquals(
          "rw-------",
          PosixFilePermissions.toString(Files.getPosixFilePermissions(result.receipt)));
    }
    IssuanceLedger.Report report = verifyLedger();
    assertTrue(report.valid(), report.problems.toString());
    assertTrue(report.warnings.isEmpty(), report.warnings.toString());
    assertEquals(1, report.issued);
    assertEquals(1, report.receiptsVerified);
    List<IssuanceLedger.Line> lines = soft.ledger().read();
    IssuanceLedger.Line outcome = lines.get(lines.size() - 1);
    assertEquals(IssuanceLedger.OUTCOME, outcome.type());
    // The outcome binds the receipt's final octets; every stage after ISSUED was bound on the way.
    assertEquals(sha256(result.receipt), outcome.string("receiptSha256"));
    IssuanceLedger.Line issue = soft.ledger().issueLine(1);
    assertNotNull(issue.string("receiptSha256"));
    int receiptLines = 0;
    for (IssuanceLedger.Line line : lines) {
      if (IssuanceLedger.RECEIPT.equals(line.type())) {
        receiptLines++;
      }
    }
    assertEquals(IssuanceStage.COMPLETED.ordinal() - IssuanceStage.ISSUED.ordinal(), receiptLines);
    String csv =
        new String(
            Files.readAllBytes(soft.batch.directory().resolve(soft.batch.receiptsCsv)), "UTF-8");
    assertTrue(csv.contains("\"COMPLETED\""), csv);
  }

  @ParameterizedTest
  @EnumSource(
      value = IssuanceStage.class,
      names = {"APPLET_INSTALLED", "F9_GENERATED", "SAM_NONCE", "F9_PROVED", "ISSUE_REQUESTED"})
  void faultBeforeIssueBurnsNothing(IssuanceStage stage) throws Exception {
    CardIssuanceOrchestrator.Result result = produce(new FakePivCard(), failAt(stage));

    assertEquals(CardIssuanceOrchestrator.EXIT_FAILED, result.exitCode, stage.name());
    IssuanceReceipt receipt = IssuanceReceipt.read(result.receipt);
    assertEquals(IssuanceReceipt.STATUS_FAILED, receipt.status);
    assertEquals(stage.name(), receipt.failure.stage);
    assertFalse(receipt.burned);
    assertEquals(0, soft.sam.issued);
    assertEquals(0, soft.ledger().lastIssueSeq());
    assertEquals(sha256(result.receipt), lastBinding(result.receipt));
    assertTrue(verifyLedger().valid());
    // The next card still receives the first OPID.
    CardIssuanceOrchestrator.Result next = produce(new FakePivCard(), NONE);
    assertEquals(soft.expected(1).toPrinted(), IssuanceReceipt.read(next.receipt).sam.opid);
  }

  @ParameterizedTest
  @EnumSource(
      value = IssuanceStage.class,
      names = {
        "F9_VERIFIED",
        "F9_LOADED",
        "PROOF_VERIFIED",
        "APPLET_READBACK",
        "KEYS_ROTATED",
        "COMPLETED"
      })
  void faultAfterIssueBurnsTheOpidAndTheNextCardGetsTheNext(IssuanceStage stage) throws Exception {
    CardIssuanceOrchestrator.Result result = produce(new FakePivCard(), failAt(stage));

    assertEquals(CardIssuanceOrchestrator.EXIT_BURNED, result.exitCode, stage.name());
    IssuanceReceipt receipt = IssuanceReceipt.read(result.receipt);
    assertTrue(receipt.burned);
    assertEquals(stage.name(), receipt.failure.stage);
    List<IssuanceLedger.Line> lines = soft.ledger().read();
    IssuanceLedger.Line outcome = lines.get(lines.size() - 1);
    assertEquals(IssuanceLedger.OUTCOME, outcome.type());
    assertEquals(IssuanceReceipt.STATUS_FAILED, outcome.string("status"));
    assertTrue(verifyLedger().valid());

    CardIssuanceOrchestrator.Result next = produce(new FakePivCard(), NONE);
    assertEquals(CardIssuanceOrchestrator.EXIT_OK, next.exitCode);
    assertEquals(soft.expected(2).toPrinted(), IssuanceReceipt.read(next.receipt).sam.opid);
  }

  @Test
  void burnedCardIsRefusedThenReissuedUnderTheNextOpid() throws Exception {
    FakePivCard card = new FakePivCard();
    CardIssuanceOrchestrator.Result burned = produce(card, failAt(IssuanceStage.F9_LOADED));
    assertEquals(CardIssuanceOrchestrator.EXIT_BURNED, burned.exitCode);

    IllegalStateException refused =
        assertThrows(IllegalStateException.class, () -> produce(card, NONE));
    assertTrue(refused.getMessage().contains("--reissue"), refused.getMessage());

    CardIssuanceOrchestrator.Inputs inputs = soft.inputs();
    inputs.reissue = true;
    CardIssuanceOrchestrator.Result again =
        new CardIssuanceOrchestrator(inputs, soft.sam, card, NONE).produce();
    assertEquals(CardIssuanceOrchestrator.EXIT_OK, again.exitCode);
    assertTrue(card.calls.contains("delete"), card.calls.toString());
    IssuanceReceipt receipt = IssuanceReceipt.read(again.receipt);
    assertEquals(soft.expected(2).toPrinted(), receipt.sam.opid);
    assertEquals(burned.receipt.getFileName().toString(), receipt.reissueOf);
    assertEquals(
        again.receipt.getFileName().toString(), IssuanceReceipt.read(burned.receipt).supersededBy);
    // The supersededBy rewrite of the burned receipt is bound by a receipt line.
    assertEquals(sha256(burned.receipt), lastBinding(burned.receipt));
    assertEquals(sha256(again.receipt), lastBinding(again.receipt));
    IssuanceLedger.Report report = verifyLedger();
    assertTrue(report.valid(), report.problems.toString());
    assertEquals(2, report.receiptsVerified);
    assertTrue(report.voided.contains(soft.expected(1).toPrinted()), report.voided.toString());

    // Pointing the burned receipt at another card afterwards is detected.
    IssuanceReceipt edited = IssuanceReceipt.read(burned.receipt);
    edited.card.kddInitial = "00";
    edited.replace(burned.receipt);
    IssuanceLedger.Report tampered = verifyLedger();
    assertFalse(tampered.valid());
    assertTrue(
        tampered.problems.toString().contains(burned.receipt.getFileName() + " differs"),
        tampered.problems.toString());
  }

  @Test
  void producedReceiptEditedOrDeletedFailsVerification() throws Exception {
    CardIssuanceOrchestrator.Result first = produce(new FakePivCard(), NONE);
    CardIssuanceOrchestrator.Result second = produce(new FakePivCard(), NONE);
    assertTrue(verifyLedger().valid(), verifyLedger().problems.toString());

    IssuanceReceipt edited = IssuanceReceipt.read(first.receipt);
    edited.sam.opid = soft.expected(3).toPrinted();
    edited.replace(first.receipt);
    IssuanceLedger.Report report = verifyLedger();
    assertFalse(report.valid());
    assertTrue(
        report.problems.toString().contains(first.receipt.getFileName() + " differs"),
        report.problems.toString());

    Files.delete(second.receipt);
    report = verifyLedger();
    assertTrue(
        report.problems.toString().contains(second.receipt.getFileName() + " is missing"),
        report.problems.toString());
  }

  @Test
  void lostIssueResponseNeedsReconcileBeforeTheNextCard() throws Exception {
    CardIssuanceOrchestrator.Result result =
        produce(new FakePivCard(), failAt(IssuanceStage.ISSUED));

    assertEquals(CardIssuanceOrchestrator.EXIT_BURNED, result.exitCode);
    IssuanceReceipt receipt = IssuanceReceipt.read(result.receipt);
    assertTrue(receipt.burned);
    assertNull(receipt.sam.issueResponse, "nothing of the response was persisted");
    assertTrue(receipt.failure.redactedMessage.contains("ledger reconcile"));
    assertEquals(1, soft.sam.issued);
    assertEquals(0, soft.ledger().lastIssueSeq());

    IllegalStateException refused =
        assertThrows(IllegalStateException.class, () -> produce(new FakePivCard(), NONE));
    assertTrue(refused.getMessage().contains("ledger reconcile"), refused.getMessage());

    assertEquals(
        LedgerReconciler.Outcome.RECOVERED_ISSUE,
        LedgerReconciler.recover(soft.sam, soft.ledger(), soft.sam.publicKey(), null, "test"));
    List<IssuanceLedger.Line> lines = soft.ledger().read();
    assertEquals(IssuanceLedger.LOST, lines.get(lines.size() - 1).type());
    assertTrue(verifyLedger().valid());
    assertEquals(
        LedgerReconciler.Outcome.IN_SYNC,
        LedgerReconciler.recover(soft.sam, soft.ledger(), soft.sam.publicKey(), null, "test"));
    CardIssuanceOrchestrator.Result next = produce(new FakePivCard(), NONE);
    assertEquals(soft.expected(2).toPrinted(), IssuanceReceipt.read(next.receipt).sam.opid);
  }

  @Test
  void failureAfterCommitIsRecoveredInline() throws Exception {
    soft.sam.failAfterCommit = true;
    CardIssuanceOrchestrator.Result result = produce(new FakePivCard(), NONE);

    assertEquals(CardIssuanceOrchestrator.EXIT_BURNED, result.exitCode);
    List<IssuanceLedger.Line> lines = soft.ledger().read();
    assertEquals(IssuanceLedger.ISSUE, lines.get(lines.size() - 3).type());
    assertTrue(lines.get(lines.size() - 3).json.get("recovered").getAsBoolean());
    assertEquals(IssuanceLedger.LOST, lines.get(lines.size() - 2).type());
    // The failure record written after the recovery is bound by a receipt line.
    assertEquals(IssuanceLedger.RECEIPT, lines.get(lines.size() - 1).type());
    assertEquals(sha256(result.receipt), lines.get(lines.size() - 1).string("sha256"));
    assertTrue(verifyLedger().valid());
  }

  @Test
  void issuanceBindsTheCapAndCplcHashes() throws Exception {
    CardIssuanceOrchestrator.Result result = produce(new FakePivCard(), NONE);
    assertEquals(CardIssuanceOrchestrator.EXIT_OK, result.exitCode);
    IssuanceReceipt receipt = IssuanceReceipt.read(result.receipt);
    byte[] cplcSha256 = IssuanceCrypto.sha256(HexUtil.parse(FakePivCard.CPLC));
    assertEquals(HexUtil.format(cplcSha256), receipt.card.cplcSha256);
    SamLedgerEntry entry = soft.ledger().issueLine(1).samEntry().entry;
    assertArrayEquals(HexUtil.parse(SoftBatch.CAP_SHA256), entry.capSha256());
    assertArrayEquals(cplcSha256, entry.cplcSha256());
  }

  @Test
  void cardWithoutCplcBurnsNothing() throws Exception {
    FakePivCard card = new FakePivCard();
    card.cplc = "unavailable";
    CardIssuanceOrchestrator.Result result = produce(card, NONE);

    assertEquals(CardIssuanceOrchestrator.EXIT_FAILED, result.exitCode);
    IssuanceReceipt receipt = IssuanceReceipt.read(result.receipt);
    assertFalse(receipt.burned);
    assertTrue(receipt.failure.redactedMessage.contains("CPLC"), receipt.failure.redactedMessage);
    assertEquals(0, soft.sam.issued);
  }

  @Test
  void capWithoutBuildIdentityIsRefusedBeforeAnyReceipt() throws Exception {
    CardIssuanceOrchestrator.Inputs inputs = soft.inputs();
    inputs.cap.properties.remove("build.sha256");
    IllegalStateException refused =
        assertThrows(
            IllegalStateException.class,
            () ->
                new CardIssuanceOrchestrator(inputs, soft.sam, new FakePivCard(), NONE).produce());
    assertTrue(refused.getMessage().contains("build.sha256"), refused.getMessage());
    assertEquals(0, soft.sam.issued);
  }

  @Test
  void leafOfAnotherBuildFailsTheProof() throws Exception {
    FakePivCard card = new FakePivCard();
    card.buildSha256 = IssuanceCrypto.sha256(new byte[] {1});
    CardIssuanceOrchestrator.Result result = produce(card, NONE);

    assertEquals(CardIssuanceOrchestrator.EXIT_BURNED, result.exitCode);
    IssuanceReceipt receipt = IssuanceReceipt.read(result.receipt);
    assertEquals(IssuanceStage.PROOF_VERIFIED.name(), receipt.failure.stage);
    assertTrue(
        receipt.failure.redactedMessage.contains("leaf.expect-build"),
        receipt.failure.redactedMessage);
  }

  @Test
  void samRejectionBeforeCommitBurnsNothing() throws Exception {
    soft.sam.rejectIssueWith = 0x6A80;
    CardIssuanceOrchestrator.Result result = produce(new FakePivCard(), NONE);

    assertEquals(CardIssuanceOrchestrator.EXIT_FAILED, result.exitCode);
    assertFalse(IssuanceReceipt.read(result.receipt).burned);
    assertEquals(0, soft.ledger().lastIssueSeq());
  }

  @Test
  void opidOffTheBatchSequenceFailsVerificationAndIsNeverLoaded() throws Exception {
    soft.sam.skipOpid = true;
    FakePivCard card = new FakePivCard();
    CardIssuanceOrchestrator.Result result = produce(card, NONE);

    assertEquals(CardIssuanceOrchestrator.EXIT_BURNED, result.exitCode);
    assertEquals(
        IssuanceReceipt.STAGE_VERIFY_FAILED, IssuanceReceipt.read(result.receipt).failure.stage);
    assertFalse(card.calls.contains("load"), "an unverified certificate is never loaded");
    // Production verifies by DECIPHER only; the root audit replays the sequence and flags it.
    IssuanceLedger.Report report = verifyLedger();
    final String printed = report.opids.get(1L);
    assertNotNull(printed);
    assertThrows(
        IllegalStateException.class,
        () -> new BatchLcgAuditor(soft.sequence()).require(1, printed));
  }

  @Test
  void kddChangeBeforeRotationIsRefused() throws Exception {
    FakePivCard card = new FakePivCard();
    card.finalKdd = new byte[10];
    CardIssuanceOrchestrator.Result result = produce(card, NONE);

    assertEquals(CardIssuanceOrchestrator.EXIT_BURNED, result.exitCode);
    IssuanceReceipt receipt = IssuanceReceipt.read(result.receipt);
    assertEquals(IssuanceStage.KEYS_ROTATED.name(), receipt.failure.stage);
    assertNull(card.rotated, "keys are never rotated on a different card");
  }

  @Test
  void exhaustedQuotaIsRefusedInPreflightAndTopUpRestoresIt() throws Exception {
    for (int i = 0; i < 5; i++) {
      assertEquals(0, produce(new FakePivCard(), NONE).exitCode);
    }
    FakePivCard card = new FakePivCard();
    IllegalStateException refused =
        assertThrows(IllegalStateException.class, () -> produce(card, NONE));
    assertTrue(refused.getMessage().contains("quota exhausted"), refused.getMessage());
    assertTrue(card.calls.isEmpty(), "no card command before the SAM preflight passes");

    SamOperationsService operations = new SamOperationsService();
    TopUpAuthorization authorization =
        operations
            .request(soft.batch, soft.sam, soft.sam.publicKey(), 2)
            .sign(soft.root().rootSigner());
    SamStatus status =
        operations.topUp(
            soft.batch,
            soft.sam,
            authorization,
            soft.custody().rootCertificate().getPublicKey(),
            soft.sam.publicKey());
    assertEquals(7, status.quota);
    assertEquals(0, produce(new FakePivCard(), NONE).exitCode);

    IllegalArgumentException replay =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                operations.topUp(
                    soft.batch,
                    soft.sam,
                    authorization,
                    soft.custody().rootCertificate().getPublicKey(),
                    soft.sam.publicKey()));
    assertTrue(replay.getMessage().contains("replay"), replay.getMessage());
    // The SAM refuses the same timestamp on its own.
    SamApduException samReplay =
        assertThrows(
            SamApduException.class,
            () ->
                soft.sam.topUp(
                    authorization.timestamp, authorization.add, authorization.signatureBytes()));
    assertEquals(0x6985, samReplay.sw);
    assertTrue(verifyLedger().valid());
  }

  @Test
  void unboundBatchIsRefusedBeforeAnySamCommand() throws Exception {
    soft.batch.state = dev.mistial.tools.openfips201.producer.BatchMetadata.STATE_CLOSED;
    int before = soft.sam.calls;
    assertThrows(IllegalStateException.class, () -> produce(new FakePivCard(), NONE));
    assertEquals(before, soft.sam.calls);
  }

  @Test
  void decipherResponseIsParsedAndRequiresTheIssuance() throws Exception {
    assertEquals(0, produce(new FakePivCard(), NONE).exitCode);
    Opid issued = soft.expected(1);

    DecipherResult result = soft.sam.decipher(issued.toPrinted());
    assertTrue(result.sameBatch);
    assertEquals(1, result.count);
    assertTrue(result.issued);
    result.requireIssuance(soft.batch.opid.batch, 1);
    assertThrows(
        IllegalStateException.class, () -> result.requireIssuance(soft.batch.opid.batch, 2));
    assertThrows(
        IllegalStateException.class, () -> result.requireIssuance(soft.batch.opid.batch + 1, 1));

    DecipherResult later = soft.sam.decipher(soft.expected(3).toPrinted());
    assertEquals(3, later.count);
    assertFalse(later.issued);
    assertThrows(
        IllegalStateException.class, () -> later.requireIssuance(soft.batch.opid.batch, 3));

    assertThrows(
        IllegalArgumentException.class,
        () -> DecipherResult.parse(dev.mistial.tools.openfips201.common.HexUtil.parse("820101")));
    DecipherResult foreign =
        DecipherResult.parse(
            dev.mistial.tools.openfips201.common.HexUtil.parse("810430303432820100"));
    assertEquals(42, foreign.batch);
    assertFalse(foreign.sameBatch);
    assertEquals(-1, foreign.count);
  }

  @Test
  void redactionRemovesKeyLengthHex() {
    assertEquals(
        "bad <redacted> 9000",
        CardIssuanceOrchestrator.redact(
            new IllegalStateException("bad 00112233445566778899AABBCCDDEEFF 9000")));
  }

  private IssuanceLedger.Report verifyLedger() throws Exception {
    return soft.ledger()
        .verify(
            soft.sam.publicKey(),
            soft.sam.certificate,
            soft.sam.parameters.paramsDigest(),
            soft.batch.quota.initial,
            soft.batch.opid.iin,
            soft.batch.directory().resolve("receipts"));
  }

  /** The hash the ledger last recorded for {@code receipt}, or null. */
  private String lastBinding(Path receipt) throws Exception {
    String name = receipt.getFileName().toString();
    String last = null;
    for (IssuanceLedger.Line line : soft.ledger().read()) {
      if (name.equals(line.string("receipt"))) {
        String sha256 =
            IssuanceLedger.RECEIPT.equals(line.type())
                ? line.string("sha256")
                : line.string("receiptSha256");
        if (sha256 != null) {
          last = sha256;
        }
      }
    }
    return last;
  }

  private static String sha256(Path file) throws Exception {
    return HexUtil.format(IssuanceCrypto.sha256(Files.readAllBytes(file)));
  }
}
