/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import dev.mistial.tools.openfips201.OpenFips201Tool;
import dev.mistial.tools.openfips201.attestation.AttestationProofService;
import dev.mistial.tools.openfips201.common.CardTransport;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.SecureFiles;
import dev.mistial.tools.openfips201.gp.DerivedScpKeys;
import dev.mistial.tools.openfips201.producer.BatchMetadata;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

/**
 * On emulated card and SAM readers: a produced card carries no known PIN, its attestation verifies
 * from the card ({@code attestation verify --from-card}), the producer's trust material exports,
 * and the batch closes and its SAM terminates.
 */
@Timeout(value = 120, unit = TimeUnit.SECONDS)
class BatchLifecycleEmulatorTest {
  private static final String CARDHOLDER_PIN = "24681357";

  @TempDir Path rootHome;
  @TempDir Path productionHome;
  @TempDir Path out;
  private String previousHome;
  private EmulatorBed bed;
  private String batchName;
  private final IssuanceTestKeys.LocalRoot root = new IssuanceTestKeys.LocalRoot();
  private final IssuanceTestKeys.LocalCustody custody =
      new IssuanceTestKeys.LocalCustody(root.rootCertificate());
  private CardIssuanceOrchestrator.Result produced;
  private String lastError = "";

  @BeforeEach
  void produceOneCard() throws Exception {
    EmulatorBed.requireAttestationCap();
    previousHome = System.getProperty("openfips201.home");
    bed = EmulatorBed.start(SoftBatch.PRODUCER, rootHome, productionHome, 4711, 5);
    bed.bringUp(root, custody);
    batchName = bed.batch;
    produced = new IssuanceService().produce(bed.produceRequest(), custody);
    assertEquals(0, produced.exitCode);
  }

  @AfterEach
  void stop() throws Exception {
    if (bed != null) {
      bed.close();
    }
    if (previousHome == null) {
      System.clearProperty("openfips201.home");
    } else {
      System.setProperty("openfips201.home", previousHome);
    }
  }

  private int cli(String... args) {
    CommandLine commandLine = new CommandLine(new OpenFips201Tool());
    ByteArrayOutputStream err = new ByteArrayOutputStream();
    commandLine.setErr(new PrintWriter(err, true));
    commandLine.setOut(new PrintWriter(new ByteArrayOutputStream(), true));
    commandLine.setExecutionExceptionHandler(
        (exception, parsed, result) -> {
          parsed.getErr().println("Error: " + exception);
          return 1;
        });
    int exit = commandLine.execute(args);
    lastError = new String(err.toByteArray(), StandardCharsets.UTF_8);
    return exit;
  }

  @Test
  void producedCardDoesNotAcceptTheProofPin() throws Exception {
    OpenFIPS201IssuanceEndToEndTest.assertProofPinRefused(bed);
  }

  @Test
  void attestationVerifiesFromTheCard() throws Exception {
    // Personalization (simulated): a cardholder PIN and a generated 9A over the issuer channel.
    try (CardTransport transport = bed.card.target().openTransport()) {
      DerivedScpKeys keys =
          custody.keyDeriver().derive(HexUtil.parse(produced.record.card.kddFinal));
      try (GlobalPlatformSession piv =
          transport.openGlobalPlatformSession(GlobalPlatformSession.PIV_AID, keys.config)) {
        AttestationProofService proofs = new AttestationProofService();
        proofs.setProofPin(piv, CARDHOLDER_PIN.getBytes(StandardCharsets.US_ASCII));
        proofs.createAndGenerateProofKey(piv, (byte) 0x9A);
      }
    }
    Path pin =
        SecureFiles.writeNew(
            out.resolve("pin"), CARDHOLDER_PIN.getBytes(StandardCharsets.US_ASCII));
    String target = "zmq:" + bed.card.endpoint();
    assertEquals(
        0,
        cli(
            "attestation",
            "verify",
            "--from-card",
            "--target",
            target,
            "--slot",
            "9A",
            "--pin-file",
            pin.toString(),
            "--producer",
            SoftBatch.PRODUCER,
            "--batch",
            batchName,
            "--expect-opid",
            produced.record.sam.opid),
        lastError);
    // 9A's access rule requires the PIN; without one the command is a usage error.
    assertEquals(
        2,
        cli(
            "attestation",
            "verify",
            "--from-card",
            "--target",
            target,
            "--slot",
            "9A",
            "--producer",
            SoftBatch.PRODUCER,
            "--batch",
            batchName));
    assertTrue(lastError.contains("requires the PIV PIN"), lastError);
    // Another producer's root does not anchor this card.
    Path foreign = out.resolve("foreign-root.pem");
    StringWriter pem = new StringWriter();
    try (JcaPEMWriter writer = new JcaPEMWriter(pem)) {
      writer.writeObject(new IssuanceTestKeys.TestRoot().certificate());
    }
    Files.write(foreign, pem.toString().getBytes(StandardCharsets.US_ASCII));
    assertEquals(
        1,
        cli(
            "attestation",
            "verify",
            "--from-card",
            "--target",
            target,
            "--slot",
            "9A",
            "--pin-file",
            pin.toString(),
            "--anchor",
            foreign.toString(),
            "--producer",
            SoftBatch.PRODUCER,
            "--batch",
            batchName));
  }

  @Test
  void trustExportWritesPublicMaterialOnce() throws Exception {
    Path trust = out.resolve("trust");
    assertEquals(
        0,
        cli("producer", "export-trust", "--name", SoftBatch.PRODUCER, "--out", trust.toString()),
        lastError);
    BatchMetadata batch = BatchMetadata.read(SoftBatch.PRODUCER, batchName);
    JsonObject manifest =
        JsonParser.parseString(
                new String(Files.readAllBytes(trust.resolve("trust.json")), StandardCharsets.UTF_8))
            .getAsJsonObject();
    assertEquals(
        dev.mistial.tools.openfips201.producer.TrustExportService.SCHEMA,
        manifest.get("schema").getAsString());
    assertEquals("production", manifest.get("station").getAsString());
    JsonObject sam = manifest.getAsJsonArray("sams").get(0).getAsJsonObject();
    assertEquals(batchName, sam.get("batch").getAsString());
    assertEquals(batch.sam.certificateSha256, sam.get("sha256").getAsString());
    assertEquals(batch.sam.ski, sam.get("ski").getAsString());
    assertTrue(Files.exists(trust.resolve("root.pem")));
    assertTrue(Files.exists(trust.resolve("sam-" + batchName + ".pem")));
    String everything = manifest.toString().toLowerCase(java.util.Locale.ROOT);
    for (String secret : new String[] {"\"key\"", "fpe", "lcg", "pin", "\"x0\""}) {
      assertTrue(!everything.contains(secret), everything);
    }
    assertNotEquals(
        0,
        cli("producer", "export-trust", "--name", SoftBatch.PRODUCER, "--out", trust.toString()));
    assertTrue(lastError.contains("already exists"), lastError);
  }

  @Test
  void closedBatchRefusesCardsAndTopUpsAndItsSamTerminates() throws Exception {
    IssuanceService service = new IssuanceService();
    SamLedgerEntry close =
        service.closeBatch(
            SoftBatch.PRODUCER, batchName, bed.sam.target(), EmulatorBed.OPERATOR_PIN, custody);
    assertEquals(SamLedgerEntry.TYPE_CLOSE, close.type);
    assertEquals(1, close.issued);
    BatchMetadata batch = BatchMetadata.read(SoftBatch.PRODUCER, batchName);
    assertEquals(BatchMetadata.STATE_CLOSED, batch.state);
    // Closing again is idempotent.
    service.closeBatch(
        SoftBatch.PRODUCER, batchName, bed.sam.target(), EmulatorBed.OPERATOR_PIN, custody);
    assertEquals(
        BatchMetadata.STATE_CLOSED, BatchMetadata.read(SoftBatch.PRODUCER, batchName).state);

    bed.newCard();
    IllegalStateException refused =
        assertThrows(
            IllegalStateException.class, () -> service.produce(bed.produceRequest(), custody));
    assertTrue(refused.getMessage().contains("CLOSED"), refused.getMessage());
    assertThrows(
        IllegalStateException.class,
        () -> service.topUpRequest(SoftBatch.PRODUCER, batchName, bed.sam.target(), 1, custody));

    SamLedgerEntry term =
        service.terminateSam(
            SoftBatch.PRODUCER, batchName, bed.sam.target(), EmulatorBed.OPERATOR_PIN, custody);
    assertEquals(SamLedgerEntry.TYPE_TERMINATE, term.type);
    assertEquals(1, term.issued);

    batch = BatchMetadata.read(SoftBatch.PRODUCER, batchName);
    IssuanceLedger.Report report =
        new LedgerService()
            .verify(
                batch,
                custody.rootCertificate(),
                bed.sam.target(),
                custody,
                EmulatorBed.OPERATOR_PIN,
                LedgerService.DEFAULT_DECIPHER_SAMPLE);
    assertTrue(report.valid(), report.problems.toString());
    assertTrue(report.closed);
    assertTrue(report.terminated);
  }
}
