/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.producer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.SecureFiles;
import dev.mistial.tools.openfips201.gp.ScpKeyChecks;
import dev.mistial.tools.openfips201.issuance.IssuanceService;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pro.javacard.gp.GPCrypto;

/**
 * The production station's batch record ({@code sam receive} writes it): the stock SCP key is
 * recorded by its GP KCV only, files are owner-only, and {@code card produce} refuses a wrong stock
 * key before any card I/O.
 */
class BatchProductionKeyCheckTest {
  private static final String PRODUCER = "bigcorp_01";
  private static final String BATCH = BatchRules.batchName(1234, 1);

  @TempDir Path home;
  private String previousHome;

  @BeforeEach
  void useTemporaryHome() {
    previousHome = System.getProperty("openfips201.home");
    System.setProperty("openfips201.home", home.toString());
  }

  @AfterEach
  void restoreHome() {
    if (previousHome == null) {
      System.clearProperty("openfips201.home");
    } else {
      System.setProperty("openfips201.home", previousHome);
    }
  }

  /** A received batch record, as {@code sam receive} lays it out. */
  private static BatchMetadata received(String name, Path stockKeyOut, String[] stockKey)
      throws Exception {
    BatchMetadata batch = new BatchMetadata();
    batch.producer = PRODUCER;
    batch.name = name;
    batch.state = BatchMetadata.STATE_SAM_BOUND;
    batch.opid.iin = 1234;
    batch.opid.batch = 1;
    batch.quota.initial = 100;
    stockKey[0] = BatchRules.newStockKey(batch, stockKeyOut);
    batch.writeNew();
    BatchRules.ensureCsvHeader(batch.directory().resolve(batch.receiptsCsv));
    return batch;
  }

  @Test
  void gpKcvVectorMatchesGpPro() {
    byte[] key = HexUtil.parse("404142434445464748494A4B4C4D4E4F");

    assertEquals("504A77", ScpKeyChecks.kcvAes(key));
    assertEquals(HexUtil.format(GPCrypto.kcv_aes(key)).substring(0, 6), ScpKeyChecks.kcvAes(key));
  }

  @Test
  void batchRecordHoldsTheGpKcvInOwnerOnlyFiles() throws Exception {
    String[] stockKey = new String[1];
    BatchMetadata batch = received(BATCH, null, stockKey);

    BatchMetadata metadata = BatchMetadata.read(PRODUCER, BATCH);
    assertEquals(BatchMetadata.SCHEMA, metadata.schema);
    assertEquals(BatchMetadata.STATE_SAM_BOUND, metadata.state);
    assertEquals(ScpKeyChecks.kcvAes(HexUtil.parse(stockKey[0])), metadata.stockScp.kcv);
    assertEquals(ScpKeyChecks.KCV_ALGORITHM_GP_B6_AES, metadata.stockScp.kcvAlgorithm);
    assertTrue(stockKey[0].matches("[0-9A-F]{32}"));
    String json =
        new String(
            Files.readAllBytes(batch.directory().resolve("batch.json")), StandardCharsets.UTF_8);
    assertFalse(json.contains(stockKey[0]), "batch.json refers to the stock key by KCV only");
    assertFalse(json.contains("\"lcg\""), "the LCG never leaves the root station");
    String csv =
        new String(
            Files.readAllBytes(batch.directory().resolve("receipts.csv")), StandardCharsets.UTF_8);
    assertEquals(BatchRules.CSV_HEADER, csv);
    if (SecureFiles.isPosix(home)) {
      assertEquals("rw-------", mode(batch.directory().resolve("batch.json")));
      assertEquals("rw-------", mode(batch.directory().resolve("receipts.csv")));
      assertEquals("rwx------", mode(batch.directory()));
      assertEquals("rwx------", mode(batch.directory().resolve("receipts")));
      assertEquals("rwx------", mode(home.resolve("producers")));
    }
  }

  @Test
  void stockKeyCanBeWrittenToANewOwnerOnlyFile() throws Exception {
    Path out = home.resolve("stock.key");
    String[] stockKey = new String[1];
    received(BATCH, out, stockKey);

    assertNull(stockKey[0]);
    String key = new String(Files.readAllBytes(out), StandardCharsets.US_ASCII).trim();
    assertEquals(
        BatchMetadata.read(PRODUCER, BATCH).stockScp.kcv, ScpKeyChecks.kcvAes(HexUtil.parse(key)));
    if (SecureFiles.isPosix(home)) {
      assertEquals("rw-------", mode(out));
    }
    assertThrows(Exception.class, () -> received("other", out, new String[1]));
  }

  @Test
  void secondBatchRecordIsRefusedAndKeepsTheFirst() throws Exception {
    BatchMetadata first = received(BATCH, null, new String[1]);
    byte[] before = Files.readAllBytes(first.directory().resolve("batch.json"));

    assertThrows(Exception.class, () -> received(BATCH, null, new String[1]));
    assertArrayEquals(before, Files.readAllBytes(first.directory().resolve("batch.json")));
  }

  @Test
  void recordWithLcgParametersIsRefused() throws Exception {
    BatchMetadata batch = received(BATCH, null, new String[1]);
    Path file = batch.directory().resolve("batch.json");
    String json = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
    Files.write(
        file,
        json.replaceFirst("\\{", "{\"lcg\":{\"a\":1,\"c\":1,\"x0\":1},")
            .getBytes(StandardCharsets.UTF_8));
    assertThrows(IllegalStateException.class, () -> BatchMetadata.read(PRODUCER, BATCH));
    assertThrows(IllegalStateException.class, () -> StationGuard.requireNoLcgRecords(PRODUCER));
  }

  @Test
  void subjectsMustFitTheSamLimits() {
    StringBuilder longName = new StringBuilder();
    for (int i = 0; i < 90; i++) {
      longName.append('X');
    }
    IllegalArgumentException failure =
        assertThrows(
            IllegalArgumentException.class,
            () -> BatchRules.requireF9SubjectFits("CN=" + longName + ",O=Long", 1234));
    assertTrue(failure.getMessage().contains("octets"), failure.getMessage());
    BatchRules.requireF9SubjectFits("CN=BigCorp F9,O=BigCorp", 1234);
  }

  @Test
  void produceWithWrongStockKeyIsRefusedBeforeAnyCardIo() throws Exception {
    received(BATCH, null, new String[1]);
    IssuanceService.ProduceRequest produce = new IssuanceService.ProduceRequest();
    produce.producer = PRODUCER;
    produce.batch = BATCH;
    produce.target = CardTarget.parse("pcsc:No Such Reader");
    produce.sam = CardTarget.parse("pcsc:No Such SAM");
    produce.stockScpKey = HexUtil.parse("000102030405060708090A0B0C0D0E0F");

    // Readers that do not exist: reaching a transport would fail with a reader error.
    IllegalArgumentException failure =
        assertThrows(IllegalArgumentException.class, () -> new IssuanceService().produce(produce));

    assertTrue(failure.getMessage().contains("does not match batch"), failure.getMessage());
    assertTrue(failure.getMessage().contains("before any card I/O"), failure.getMessage());
  }

  private static String mode(Path path) throws Exception {
    return PosixFilePermissions.toString(Files.getPosixFilePermissions(path));
  }
}
