/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import dev.mistial.tools.openfips201.producer.ProducerSetupService;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The root station's allocation registry: one allocation per (IIN, batch) within the OPID layout,
 * root-signed hash-chained lines, and a custody head that exposes a stale or forked file.
 */
class AllocationRegistryTest {
  @TempDir Path home;
  private String previousHome;
  private final IssuanceTestKeys.LocalRoot root = new IssuanceTestKeys.LocalRoot();
  private final RootStationService station = new RootStationService();

  @BeforeEach
  void initRegistry() throws Exception {
    previousHome = System.getProperty("openfips201.home");
    SoftBatch.producer(home, ProducerSetupService.STATION_ROOT);
    station.init(SoftBatch.PRODUCER, root);
  }

  @AfterEach
  void restoreHome() {
    if (previousHome == null) {
      System.clearProperty("openfips201.home");
    } else {
      System.setProperty("openfips201.home", previousHome);
    }
  }

  @Test
  void initTwiceIsRefused() {
    assertThrows(IllegalStateException.class, () -> station.init(SoftBatch.PRODUCER, root));
  }

  @Test
  void allocationsAreUniquePerIinAndBatch() throws Exception {
    JsonObject first = station.allocate(SoftBatch.PRODUCER, root, 1234, 42, 100);
    assertEquals(1, first.get("seq").getAsLong());
    IllegalArgumentException clash =
        assertThrows(
            IllegalArgumentException.class,
            () -> station.allocate(SoftBatch.PRODUCER, root, 1234, 42, 5));
    assertTrue(clash.getMessage().contains("0042"), clash.getMessage());
    station.allocate(SoftBatch.PRODUCER, root, 9, 42, 100);
    station.allocate(SoftBatch.PRODUCER, root, 1234, 43, 100);

    AllocationRegistry registry = AllocationRegistry.open(SoftBatch.PRODUCER, root);
    assertEquals(4, registry.lines().size());
    AllocationRegistry.verifyChain(registry.lines(), root.rootCertificate().getPublicKey());
  }

  @Test
  void quotaIinAndBatchMustFitTheLayout() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            station.allocate(SoftBatch.PRODUCER, root, 1234, 3, AllocationRegistry.MAX_QUOTA + 1));
    assertThrows(
        IllegalArgumentException.class,
        () -> station.allocate(SoftBatch.PRODUCER, root, 1234, 3, 0));
    assertThrows(
        IllegalArgumentException.class,
        () -> station.allocate(SoftBatch.PRODUCER, root, 1234, 10_000, 1));
    assertThrows(
        IllegalArgumentException.class,
        () -> station.allocate(SoftBatch.PRODUCER, root, 10_000, 1, 1));
  }

  @Test
  void bindingNeedsAnAllocationAndHappensOnce() throws Exception {
    AllocationRegistry registry = AllocationRegistry.open(SoftBatch.PRODUCER, root);
    assertThrows(IllegalArgumentException.class, () -> registry.prepareBind(1234, 1, "0A0B"));
    station.allocate(SoftBatch.PRODUCER, root, 1234, 1, 10);
    AllocationRegistry reopened = AllocationRegistry.open(SoftBatch.PRODUCER, root);
    String bind = reopened.prepareBind(1234, 1, "0A0B");
    reopened.commit(bind);
    assertNotNull(reopened.binding(1234, 1));
    assertThrows(IllegalStateException.class, () -> reopened.prepareBind(1234, 1, "0C0D"));
    AllocationRegistry.verifyBinding(
        reopened.line(1), bind, root.rootCertificate().getPublicKey(), "0A0B");
    assertThrows(
        RuntimeException.class,
        () ->
            AllocationRegistry.verifyBinding(
                reopened.line(1), bind, root.rootCertificate().getPublicKey(), "0C0D"));
  }

  @Test
  void staleCopyIsDetectedAgainstTheCustodyHead() throws Exception {
    Path file = AllocationRegistry.file(SoftBatch.PRODUCER);
    byte[] before = Files.readAllBytes(file);
    station.allocate(SoftBatch.PRODUCER, root, 1234, 1, 10);
    // An older copy of the file restored over the current one.
    Files.write(file, before);
    IllegalStateException stale =
        assertThrows(
            IllegalStateException.class, () -> AllocationRegistry.open(SoftBatch.PRODUCER, root));
    assertTrue(stale.getMessage().contains("stale or forked"), stale.getMessage());
  }

  @Test
  void forkedOrEditedLinesAreDetected() throws Exception {
    station.allocate(SoftBatch.PRODUCER, root, 1234, 1, 10);
    Path file = AllocationRegistry.file(SoftBatch.PRODUCER);
    String content = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
    Files.write(
        file, content.replace("\"quota\":10", "\"quota\":11").getBytes(StandardCharsets.UTF_8));
    assertThrows(RuntimeException.class, () -> AllocationRegistry.open(SoftBatch.PRODUCER, root));

    // A second root's registry signed lines do not verify under this root.
    IssuanceTestKeys.LocalRoot other = new IssuanceTestKeys.LocalRoot();
    List<String> lines = java.util.Arrays.asList(content.trim().split("\n"));
    assertThrows(
        RuntimeException.class,
        () -> AllocationRegistry.verifyChain(lines, other.rootCertificate().getPublicKey()));
  }
}
