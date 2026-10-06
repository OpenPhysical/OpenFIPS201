/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import dev.mistial.tools.openfips201.common.HexUtil;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Tamper detection in {@code ledger.jsonl} and in the receipts it binds. */
class IssuanceLedgerTest {
  @TempDir Path home;
  private String previousHome;
  private SoftBatch soft;
  private Path file;

  @BeforeEach
  void issueThree() throws Exception {
    previousHome = System.getProperty("openfips201.home");
    soft = SoftBatch.create(home, "ledgered", 4321, 10);
    file = soft.ledger().file();
    for (int i = 0; i < 3; i++) {
      CardIssuanceOrchestrator.Result result =
          new CardIssuanceOrchestrator(soft.inputs(), soft.sam, new FakePivCard()).produce();
      assertEquals(0, result.exitCode);
    }
  }

  @AfterEach
  void restoreHome() {
    if (previousHome == null) {
      System.clearProperty("openfips201.home");
    } else {
      System.setProperty("openfips201.home", previousHome);
    }
  }

  private IssuanceLedger.Report verify() throws Exception {
    return soft.ledger()
        .verify(
            soft.sam.publicKey(),
            soft.sam.certificate,
            soft.sam.parameters.paramsDigest(),
            soft.batch.quota.initial,
            soft.batch.opid.iin,
            receipts());
  }

  private Path receipts() {
    return soft.batch.directory().resolve("receipts");
  }

  /** The receipt file named by the {@code issue} line of issuance {@code seq}. */
  private Path receiptOf(int seq) throws Exception {
    return receipts().resolve(soft.ledger().issueLine(seq).string("receipt"));
  }

  private List<String> lines() throws Exception {
    String content = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
    List<String> out = new ArrayList<String>();
    for (String line : content.split("\n")) {
      out.add(line);
    }
    return out;
  }

  private void write(List<String> lines) throws Exception {
    StringBuilder out = new StringBuilder();
    for (String line : lines) {
      out.append(line).append('\n');
    }
    Files.write(file, out.toString().getBytes(StandardCharsets.UTF_8));
  }

  /** Rewrites every prev so the line hash chain is intact, as a forger would. */
  private void writeRechained(List<String> lines) throws Exception {
    List<String> out = new ArrayList<String>();
    String previous = null;
    for (String line : lines) {
      JsonObject json = JsonParser.parseString(line).getAsJsonObject();
      json.addProperty(
          "prev", previous == null ? IssuanceLedger.ZERO_HASH : IssuanceLedger.hash(previous));
      previous = new Gson().toJson(json);
      out.add(previous);
    }
    write(out);
  }

  private int indexOfIssue(int seq) throws Exception {
    List<String> lines = lines();
    for (int i = 0; i < lines.size(); i++) {
      JsonObject json = JsonParser.parseString(lines.get(i)).getAsJsonObject();
      if ("issue".equals(json.get("type").getAsString()) && json.get("seq").getAsInt() == seq) {
        return i;
      }
    }
    throw new AssertionError("no issue " + seq);
  }

  private static boolean mentions(IssuanceLedger.Report report, String text) {
    for (String problem : report.problems) {
      if (problem.contains(text)) {
        return true;
      }
    }
    return false;
  }

  @Test
  void untouchedLedgerVerifies() throws Exception {
    IssuanceLedger.Report report = verify();
    assertTrue(report.valid(), report.problems.toString());
    assertTrue(report.warnings.isEmpty(), report.warnings.toString());
    assertEquals(IssuanceLedger.VERSION, report.version);
    assertEquals(3, report.issued);
    assertEquals(3, report.receiptsVerified);
  }

  @ParameterizedTest
  @ValueSource(strings = {"card.cplc", "card.kddInitial", "sam.opid", "identifiers.opid"})
  void editedReceiptFieldFailsVerification(String field) throws Exception {
    Path receipt = receiptOf(2);
    JsonObject json =
        JsonParser.parseString(new String(Files.readAllBytes(receipt), StandardCharsets.UTF_8))
            .getAsJsonObject();
    String[] path = field.split("\\.");
    JsonObject parent = json.getAsJsonObject(path[0]);
    String original = parent.get(path[1]).getAsString();
    String edited =
        original.substring(0, original.length() - 1) + (original.endsWith("0") ? "1" : "0");
    parent.addProperty(path[1], edited);
    Files.write(
        receipt,
        new GsonBuilder()
            .setPrettyPrinting()
            .disableHtmlEscaping()
            .create()
            .toJson(json)
            .getBytes(StandardCharsets.UTF_8));

    IssuanceLedger.Report report = verify();
    assertFalse(report.valid());
    assertTrue(
        mentions(report, receipt.getFileName() + " differs from its last ledger binding"),
        report.problems.toString());
  }

  @Test
  void deletedReceiptFailsVerification() throws Exception {
    Path receipt = receiptOf(3);
    Files.delete(receipt);
    IssuanceLedger.Report report = verify();
    assertFalse(report.valid());
    assertTrue(mentions(report, receipt.getFileName() + " is missing"), report.problems.toString());
  }

  @Test
  void receiptReplacedBySymbolicLinkFailsVerification() throws Exception {
    Path receipt = receiptOf(1);
    Path copy = receipt.resolveSibling("copy.bin");
    Files.move(receipt, copy);
    try {
      Files.createSymbolicLink(receipt, copy);
    } catch (UnsupportedOperationException | java.io.IOException noLinks) {
      org.junit.jupiter.api.Assumptions.assumeTrue(false, "symbolic links unavailable");
    }
    assertTrue(mentions(verify(), receipt.getFileName() + " is missing"));
  }

  @Test
  void receiptHashWithoutAReceiptOrOfTheWrongFormIsFlagged() throws Exception {
    List<String> lines = lines();
    int index = indexOfIssue(2);
    JsonObject json = JsonParser.parseString(lines.get(index)).getAsJsonObject();
    json.addProperty("receiptSha256", "00");
    lines.set(index, new Gson().toJson(json));
    writeRechained(lines);
    assertTrue(mentions(verify(), "is not 64 hex digits"));

    json.remove("receipt");
    lines.set(index, new Gson().toJson(json));
    writeRechained(lines);
    assertTrue(mentions(verify(), "receipt hash without a receipt"));
  }

  @Test
  void receiptNameWithAPathIsFlagged() throws Exception {
    soft.ledger().appendReceipt("../ledger.jsonl", IssuanceLedger.ZERO_HASH, "test");
    assertTrue(mentions(verify(), "is not a plain receipt file name"));
  }

  @Test
  void unboundReceiptNameIsFlagged() throws Exception {
    List<String> lines = lines();
    int index = indexOfIssue(2);
    JsonObject json = JsonParser.parseString(lines.get(index)).getAsJsonObject();
    String name = json.get("receipt").getAsString();
    // Drop every binding of the receipt of issuance 2, as a forger rewriting the ledger would.
    json.remove("receiptSha256");
    lines.set(index, new Gson().toJson(json));
    List<String> kept = new ArrayList<String>();
    for (String line : lines) {
      JsonObject parsed = JsonParser.parseString(line).getAsJsonObject();
      boolean binds =
          name.equals(parsed.has("receipt") ? parsed.get("receipt").getAsString() : null)
              && (parsed.has("receiptSha256") || parsed.has("sha256"));
      if (!binds) {
        kept.add(line);
      }
    }
    writeRechained(kept);
    assertTrue(mentions(verify(), name + " is named but no ledger line binds its hash"));
  }

  @Test
  void legacyLedgerVerifiesOnlyWithTheUnboundReceiptsWarning() throws Exception {
    // A v1 ledger: same lines without receipt bindings.
    List<String> legacy = new ArrayList<String>();
    for (String line : lines()) {
      JsonObject json = JsonParser.parseString(line).getAsJsonObject();
      if (IssuanceLedger.RECEIPT.equals(json.get("type").getAsString())) {
        continue;
      }
      json.addProperty("v", IssuanceLedger.LEGACY_VERSION);
      json.remove("receiptSha256");
      legacy.add(new Gson().toJson(json));
    }
    writeRechained(legacy);
    // Receipt files are not compared in a legacy ledger, so an edit is not detected: the warning
    // says so.
    Files.write(receiptOf(1), "{}".getBytes(StandardCharsets.UTF_8));

    IssuanceLedger.Report report = verify();
    assertTrue(report.valid(), report.problems.toString());
    assertEquals(IssuanceLedger.LEGACY_VERSION, report.version);
    assertEquals(
        java.util.Collections.singletonList(IssuanceLedger.LEGACY_WARNING), report.warnings);

    // The ledger stays v1 when appended, and binds nothing.
    assertNull(soft.ledger().appendReceipt(receiptOf(1).getFileName().toString(), "AA", "test"));
    IssuanceLedger.Line outcome =
        soft.ledger()
            .appendOutcome(
                1,
                soft.ledger().issueLine(1).string("opid"),
                "x",
                null,
                receiptOf(1).getFileName().toString(),
                IssuanceLedger.ZERO_HASH,
                null,
                null);
    assertEquals(IssuanceLedger.LEGACY_VERSION, outcome.number("v"));
    assertFalse(outcome.json.has("receiptSha256"));
    assertTrue(verify().valid());
  }

  @Test
  void mixedVersionsAreFlagged() throws Exception {
    List<String> lines = lines();
    int index = indexOfIssue(2);
    JsonObject json = JsonParser.parseString(lines.get(index)).getAsJsonObject();
    json.addProperty("v", IssuanceLedger.LEGACY_VERSION);
    lines.set(index, new Gson().toJson(json));
    writeRechained(lines);
    assertTrue(mentions(verify(), "version is not 2"));
  }

  @Test
  void unsupportedVersionFails() throws Exception {
    List<String> lines = lines();
    List<String> out = new ArrayList<String>();
    for (String line : lines) {
      JsonObject json = JsonParser.parseString(line).getAsJsonObject();
      json.addProperty("v", 3);
      out.add(new Gson().toJson(json));
    }
    writeRechained(out);
    IssuanceLedger.Report report = verify();
    assertTrue(mentions(report, "unsupported ledger format version 3"), report.problems.toString());
  }

  @Test
  void flippedByteBreaksTheChain() throws Exception {
    List<String> lines = lines();
    int index = indexOfIssue(2);
    lines.set(index, lines.get(index).replace("\"recovered\":false", "\"recovered\":true"));
    write(lines);
    assertTrue(mentions(verify(), "prev does not hash the previous line"));
  }

  @Test
  void deletedLineBreaksTheChain() throws Exception {
    List<String> lines = lines();
    lines.remove(indexOfIssue(2));
    write(lines);
    IssuanceLedger.Report report = verify();
    assertFalse(report.valid());
    assertTrue(mentions(report, "prev does not hash the previous line"));
  }

  @Test
  void reorderedLinesBreakTheChain() throws Exception {
    List<String> lines = lines();
    int first = indexOfIssue(1);
    int second = indexOfIssue(2);
    String swap = lines.get(first);
    lines.set(first, lines.get(second));
    lines.set(second, swap);
    write(lines);
    assertFalse(verify().valid());
  }

  @Test
  void reorderedAndRechainedLinesBreakTheSamChain() throws Exception {
    List<String> lines = lines();
    int first = indexOfIssue(1);
    int second = indexOfIssue(2);
    String swap = lines.get(first);
    lines.set(first, lines.get(second));
    lines.set(second, swap);
    writeRechained(lines);
    IssuanceLedger.Report report = verify();
    assertTrue(mentions(report, "SAM eventSeq"), report.problems.toString());
  }

  @Test
  void forgedSignatureIsDetectedEvenWhenRechained() throws Exception {
    List<String> lines = lines();
    int index = indexOfIssue(2);
    JsonObject json = JsonParser.parseString(lines.get(index)).getAsJsonObject();
    byte[] other = HexUtil.parse(json.get("sig").getAsString());
    other[other.length - 1] ^= 0x01;
    json.addProperty("sig", HexUtil.format(other));
    lines.set(index, new Gson().toJson(json));
    writeRechained(lines);
    assertTrue(mentions(verify(), "SAM signature does not verify"));
  }

  @Test
  void duplicateOpidIsFlagged() throws Exception {
    List<String> lines = lines();
    lines.add(lines.get(indexOfIssue(3)));
    writeRechained(lines);
    IssuanceLedger.Report report = verify();
    assertTrue(mentions(report, "duplicate OPID"), report.problems.toString());
    assertTrue(mentions(report, "duplicate F9 key identifier"), report.problems.toString());
  }

  @Test
  void sameF9KeyCertifiedTwiceIsFlagged() throws Exception {
    // A host that re-sends ISSUE with the same F9 key after a post-commit failure obtains two
    // genuine SAM entries, under different OPIDs, for one key.
    java.security.KeyPair f9 = IssuanceTestKeys.p256();
    byte[] point = IssuanceCrypto.point(f9.getPublic());
    for (int i = 0; i < 2; i++) {
      byte[] nonce = soft.sam.beginIssuance();
      java.security.Signature signature = java.security.Signature.getInstance("SHA256withECDSA");
      signature.initSign(f9.getPrivate());
      signature.update(
          dev.mistial.tools.openfips201.common.ByteArrays.concat(
              CardIssuanceOrchestrator.PREFIX_POP, nonce, point));
      byte[] validity =
          new org.bouncycastle.asn1.DERSequence(
                  new org.bouncycastle.asn1.ASN1Encodable[] {
                    new org.bouncycastle.asn1.x509.Time(new java.util.Date()),
                    new org.bouncycastle.asn1.x509.Time(
                        new java.util.Date(System.currentTimeMillis() + 86_400_000L))
                  })
              .getEncoded();
      IssueResponse response =
          IssueResponse.parse(soft.sam.issue(point, signature.sign(), validity));
      soft.ledger().appendIssue(response.signedEntry, null, null, null, false);
    }
    IssuanceLedger.Report report = verify();
    assertTrue(mentions(report, "duplicate F9 key identifier"), report.problems.toString());
    assertFalse(mentions(report, "duplicate OPID"), report.problems.toString());
  }

  @Test
  void truncatedTailPassesOfflineButNotAgainstTheSam() throws Exception {
    List<String> lines = lines();
    int index = indexOfIssue(3);
    write(new ArrayList<String>(lines.subList(0, index)));
    IssuanceLedger.Report offline = verify();
    assertTrue(offline.valid(), offline.problems.toString());

    LedgerService.compare(offline, soft.sam.status());
    assertTrue(mentions(offline, "truncated or diverged"), offline.problems.toString());
  }

  @Test
  void closeThenTerminateVerifiesAndNothingMayFollowTheTerminate() throws Exception {
    BatchLifecycleService lifecycle = new BatchLifecycleService();
    SamLedgerEntry close = lifecycle.close(soft.batch, soft.sam, soft.sam.publicKey());
    assertEquals(SamLedgerEntry.TYPE_CLOSE, close.type);
    assertEquals(3, close.issued);
    assertTrue(soft.sam.status().isClosed());
    lifecycle.terminate(soft.batch, soft.sam, soft.sam.publicKey());
    IssuanceLedger.Report report = verify();
    assertTrue(report.valid(), report.problems.toString());
    assertTrue(report.closed && report.terminated);

    soft.ledger().appendOutcome(3, soft.ledger().read().get(1).string("opid"), "x", "x", null);
    assertTrue(mentions(verify(), "after the SAM was terminated"));
  }

  @Test
  void closeRefusesALedgerBehindTheSam() throws Exception {
    // The SAM issues once more without the host recording it.
    java.security.KeyPair f9 = IssuanceTestKeys.p256();
    byte[] point = IssuanceCrypto.point(f9.getPublic());
    byte[] nonce = soft.sam.beginIssuance();
    java.security.Signature signature = java.security.Signature.getInstance("SHA256withECDSA");
    signature.initSign(f9.getPrivate());
    signature.update(
        dev.mistial.tools.openfips201.common.ByteArrays.concat(
            CardIssuanceOrchestrator.PREFIX_POP, nonce, point));
    byte[] validity =
        new org.bouncycastle.asn1.DERSequence(
                new org.bouncycastle.asn1.ASN1Encodable[] {
                  new org.bouncycastle.asn1.x509.Time(new java.util.Date()),
                  new org.bouncycastle.asn1.x509.Time(
                      new java.util.Date(System.currentTimeMillis() + 86_400_000L))
                })
            .getEncoded();
    soft.sam.issue(point, signature.sign(), validity);

    IllegalStateException refused =
        assertThrows(
            IllegalStateException.class,
            () -> new BatchLifecycleService().close(soft.batch, soft.sam, soft.sam.publicKey()));
    assertTrue(refused.getMessage().contains("ledger reconcile"), refused.getMessage());
    assertEquals(
        dev.mistial.tools.openfips201.producer.BatchMetadata.STATE_SAM_BOUND, soft.batch.state);
  }

  @Test
  void outcomeForAnUnissuedOpidIsFlagged() throws Exception {
    soft.ledger().appendOutcome(9, "000000000000000000", "COMPLETED", "COMPLETED", null);
    assertTrue(mentions(verify(), "names an OPID that was not issued"));
  }
}
