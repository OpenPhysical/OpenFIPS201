/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import dev.mistial.tools.openfips201.common.SecureFiles;
import dev.mistial.tools.openfips201.opid.Lcg;
import dev.mistial.tools.openfips201.producer.BatchRules;
import dev.mistial.tools.openfips201.producer.ProducerPaths;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/**
 * The root station's record of one batch, under {@code root/batches/}.
 *
 * <ul>
 *   <li>{@code IIII-NNNN-<samId>.lcg.json} ({@code openfips201.root-lcg/1}): the LCG, initial quota
 *       and timestamp and the paramsDigest drawn for one SAM of the batch. Owner-only, created once
 *       with {@code CREATE_NEW} before PUT PARAMETERS. This is the only place the LCG exists
 *       outside the SAM. A personalization retried on the same, freshly installed SAM reuses it; a
 *       different SAM gets a new LCG, so no two SAMs share a sequence.
 *   <li>{@code IIII-NNNN.sam.json} ({@code openfips201.root-sam/1}): the bound SAM: its id, key
 *       identifier and certificate. Public material.
 * </ul>
 */
public final class RootBatchRecord {
  private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

  /** {@code IIII-NNNN.lcg.json}. */
  public static final class LcgFile {
    public String schema = "openfips201.root-lcg/1";
    public int iin;
    public int batch;
    public String samId;
    public long a;
    public long c;
    public long x0;
    public long quota;
    public long initialTs;
    public String fpeKcv;
    public String paramsDigest;

    public Lcg lcg() {
      return Lcg.of(a, c, x0);
    }
  }

  /** {@code IIII-NNNN.sam.json}. */
  public static final class SamFile {
    public String schema = "openfips201.root-sam/1";
    public int iin;
    public int batch;
    public String samId;
    public String samSki;
    public String certificate;
    public String certificateSha256;
    public long allocationSeq;
    public String registryHead;
  }

  private RootBatchRecord() {}

  static Path directory(String producer) {
    return ProducerPaths.producer(producer).resolve("root").resolve("batches");
  }

  public static Path lcgFile(String producer, int iin, int batch, String samId) {
    if (samId == null || !samId.matches("[0-9A-F]{2,64}")) {
      throw new IllegalArgumentException("samId must be upper-case hex");
    }
    return directory(producer)
        .resolve(BatchRules.batchName(iin, batch) + "-" + samId + ".lcg.json");
  }

  public static Path samFile(String producer, int iin, int batch) {
    return directory(producer).resolve(BatchRules.batchName(iin, batch) + ".sam.json");
  }

  static void writeLcg(String producer, LcgFile record) throws IOException {
    ProducerPaths.createDirectories(directory(producer));
    SecureFiles.writeNew(
        lcgFile(producer, record.iin, record.batch, record.samId),
        GSON.toJson(record).getBytes(StandardCharsets.UTF_8));
  }

  /** The LCG record drawn for {@code samId}, or null when none was written. */
  public static LcgFile readLcg(String producer, int iin, int batch, String samId)
      throws IOException {
    Path file = lcgFile(producer, iin, batch, samId);
    if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
      return null;
    }
    SecureFiles.requireOwnerOnly(file);
    LcgFile record =
        GSON.fromJson(new String(Files.readAllBytes(file), StandardCharsets.UTF_8), LcgFile.class);
    if (record == null
        || record.iin != iin
        || record.batch != batch
        || !samId.equals(record.samId)) {
      throw new IllegalStateException(file + " does not describe this batch and SAM");
    }
    return record;
  }

  static void writeSam(String producer, SamFile record) throws IOException {
    ProducerPaths.createDirectories(directory(producer));
    SecureFiles.writeNew(
        samFile(producer, record.iin, record.batch),
        GSON.toJson(record).getBytes(StandardCharsets.UTF_8));
  }

  /** The bound SAM record, or null. */
  public static SamFile readSam(String producer, int iin, int batch) throws IOException {
    Path file = samFile(producer, iin, batch);
    if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
      return null;
    }
    return GSON.fromJson(
        new String(Files.readAllBytes(file), StandardCharsets.UTF_8), SamFile.class);
  }
}
