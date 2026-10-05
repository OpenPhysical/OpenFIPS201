/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import dev.mistial.tools.openfips201.producer.BatchMetadata;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

/**
 * The root-to-production handoff on emulated readers under software custody: the bundle is bound to
 * its root signature and to the station it is wrapped to, the handoff keys stop working once the
 * SAM is received, and a burned card is reissued under the next OPID with its old OPID voided.
 */
@Timeout(value = 120, unit = TimeUnit.SECONDS)
class StationHandoffEmulatorTest {
  @TempDir Path rootHome;
  @TempDir Path productionHome;
  private String previousHome;
  private EmulatorBed bed;
  private final IssuanceTestKeys.LocalRoot root = new IssuanceTestKeys.LocalRoot();
  private final IssuanceTestKeys.LocalCustody custody =
      new IssuanceTestKeys.LocalCustody(root.rootCertificate());

  @BeforeEach
  void personalize() throws Exception {
    EmulatorBed.requireAttestationCap();
    previousHome = System.getProperty("openfips201.home");
    bed = EmulatorBed.start(SoftBatch.PRODUCER, rootHome, productionHome, 4712, 4);
    bed.writeLocalProfiles(root.rootCertificate(), SoftBatch.F9_TEMPLATE);
    bed.personalize(root, custody.stationPoint(), SoftBatch.F9_TEMPLATE);
    bed.useProduction();
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

  private SamReceiveService.Result receive(Path bundle, Custody station) throws Exception {
    return new IssuanceService()
        .receive(
            SoftBatch.PRODUCER,
            bed.sam.target(),
            bundle,
            EmulatorBed.OPERATOR_PIN.clone(),
            null,
            station);
  }

  @Test
  void tamperedBundleIsRejected() throws Exception {
    JsonObject json =
        JsonParser.parseString(
                new String(Files.readAllBytes(bed.bundle), StandardCharsets.UTF_8).trim())
            .getAsJsonObject();
    json.addProperty("quota", 1_000_000L);
    Path tampered = productionHome.resolve("tampered.json");
    Files.write(tampered, json.toString().getBytes(StandardCharsets.UTF_8));

    assertThrows(RuntimeException.class, () -> receive(tampered, custody));
    assertFalse(BatchMetadata.exists(SoftBatch.PRODUCER, bed.batch));
  }

  @Test
  void bundleWrappedToAnotherStationIsRejected() throws Exception {
    IssuanceTestKeys.LocalCustody other = new IssuanceTestKeys.LocalCustody(root.rootCertificate());
    IllegalArgumentException refused =
        assertThrows(IllegalArgumentException.class, () -> receive(bed.bundle, other));
    assertTrue(refused.getMessage().contains("not to this station"), refused.getMessage());
    assertFalse(BatchMetadata.exists(SoftBatch.PRODUCER, bed.batch));
  }

  @Test
  void receivedSamRefusesTheHandoffKeysAndAReceiptTwice() throws Exception {
    SamReceiveService.Result received = receive(bed.bundle, custody);
    BatchMetadata batch = received.batch;
    assertEquals(BatchMetadata.STATE_SAM_BOUND, batch.state);
    assertEquals(bed.batch, batch.name);
    assertFalse(
        new String(Files.readAllBytes(BatchMetadata.file(SoftBatch.PRODUCER, bed.batch)), "UTF-8")
            .contains("\"lcg\""),
        "the production batch record carries no LCG");

    // The batch record was written; a second receipt is refused before the SAM is touched again.
    IllegalStateException again =
        assertThrows(IllegalStateException.class, () -> receive(bed.bundle, custody));
    assertTrue(again.getMessage().contains("already exists"), again.getMessage());
    // With the record gone, the SAM itself refuses the handoff keys.
    Files.move(batch.directory(), productionHome.resolve("moved-" + bed.batch));
    IllegalStateException rotated =
        assertThrows(IllegalStateException.class, () -> receive(bed.bundle, custody));
    assertTrue(rotated.getMessage().contains("already received"), rotated.getMessage());
  }

  @Test
  void rootStationRefusesAReaderHoldingAPivCard() throws Exception {
    bed.receive(custody);
    CardIssuanceOrchestrator.Result produced =
        new IssuanceService().produce(bed.produceRequest(), custody);
    assertEquals(0, produced.exitCode);

    bed.useRoot();
    new RootStationService().allocate(SoftBatch.PRODUCER, root, EmulatorBed.IIN, 4713, 2);
    IssuanceService.PersonalizeRequest request = bed.personalizeRequest();
    request.batch = 4713;
    request.sam = bed.card.target();
    request.install = false;
    request.bundleOut = rootHome.resolve("piv-bundle.json");
    IllegalStateException refused =
        assertThrows(
            IllegalStateException.class,
            () -> new IssuanceService().personalize(request, root, SoftBatch.F9_TEMPLATE));
    assertTrue(refused.getMessage().contains("PIV card"), refused.getMessage());
    assertFalse(Files.exists(request.bundleOut));
    assertEquals(
        null,
        AllocationRegistry.open(SoftBatch.PRODUCER, root).binding(EmulatorBed.IIN, 4713),
        "the allocation stays unbound");
  }

  @Test
  void burnedCardIsReissuedUnderTheNextOpidWithItsOldOpidVoided() throws Exception {
    bed.receive(custody);
    List<String> expected = bed.rootOpids(root, 2);
    IssuanceService.ProduceRequest burn = bed.produceRequest();
    burn.hooks =
        stage -> {
          if (stage == IssuanceStage.F9_LOADED) {
            throw new IllegalStateException("injected fault at " + stage);
          }
        };
    CardIssuanceOrchestrator.Result burned = new IssuanceService().produce(burn, custody);
    assertEquals(CardIssuanceOrchestrator.EXIT_BURNED, burned.exitCode);
    assertEquals(expected.get(0), burned.record.sam.opid);

    // The same card again: refused without --reissue.
    IllegalStateException refused =
        assertThrows(
            IllegalStateException.class,
            () -> new IssuanceService().produce(bed.produceRequest(), custody));
    assertTrue(refused.getMessage().contains("--reissue"), refused.getMessage());

    IssuanceService.ProduceRequest reissue = bed.produceRequest();
    reissue.reissue = true;
    CardIssuanceOrchestrator.Result again = new IssuanceService().produce(reissue, custody);
    assertEquals(0, again.exitCode, again.record.failure == null ? "" : again.record.failure.stage);
    assertEquals(expected.get(1), again.record.sam.opid);
    assertEquals(burned.receipt.getFileName().toString(), again.record.reissueOf);
    assertEquals(
        again.receipt.getFileName().toString(), IssuanceReceipt.read(burned.receipt).supersededBy);

    BatchMetadata batch = BatchMetadata.read(SoftBatch.PRODUCER, bed.batch);
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
    assertTrue(report.voided.contains(expected.get(0)), report.voided.toString());
  }
}
