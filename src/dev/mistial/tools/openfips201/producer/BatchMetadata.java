/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.producer;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import dev.mistial.tools.openfips201.common.SecureFiles;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/**
 * The production station's batch record: {@code batches/IIII-NNNN/batch.json}, schema {@code
 * openfips201.batch/4}, written owner-only (0600) by {@code sam receive}.
 *
 * <p>It carries no LCG parameters and no FF1 key: those exist only at the root station and inside
 * the SAM. The record holds the public batch identity, the SAM certificate reference, the
 * root-signed paramsDigest and registry lines, the stock card key's check value and the ledger.
 *
 * <p>State: {@code SAM_BOUND} once received; {@code CLOSED} once the SAM is closed; {@code
 * TERMINATED} once the SAM is terminated.
 */
public final class BatchMetadata {
  public static final String SCHEMA = "openfips201.batch/4";
  public static final String STATE_SAM_BOUND = "SAM_BOUND";
  public static final String STATE_CLOSED = "CLOSED";
  public static final String STATE_TERMINATED = "TERMINATED";

  private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

  public String schema = SCHEMA;
  public String producer;
  public String name;
  public String created;
  public String state;
  public OpidSpec opid = new OpidSpec();

  /** Root-signed paramsDigest (hex) the SAM must report in PARAMS tag 93. */
  public String paramsDigest;

  /** The root-signed allocate and bind registry lines, verbatim. */
  public Registry registry = new Registry();

  public Quota quota = new Quota();
  public StockScp stockScp = new StockScp();
  public Sam sam;
  public F9 f9 = new F9();
  public String ledger = "ledger.jsonl";
  public String receiptsCsv = "receipts.csv";

  /** OPID identity of the batch: its IIN and its batch number, unique under that IIN. */
  public static final class OpidSpec {
    public int iin;
    public int batch;
  }

  /** The registry lines that authorize the batch and bind its SAM. */
  public static final class Registry {
    public String allocate;
    public String bind;
    public long allocationSeq;
    public String head;
  }

  /** Initial quota, the total authorized so far, and the timestamps the SAM has accepted. */
  public static final class Quota {
    public long initial;
    public long authorizedTotal;
    public long initialTs;
    public long lastTopUpTs;
  }

  /** The batch stock SCP key: only its KCV is recorded. */
  public static final class StockScp {
    public String mode;
    public int keyVersion;
    public String kcv;

    /** {@code gp-b6-aes} (GlobalPlatform v2.3.1 Section B.6). */
    public String kcvAlgorithm;
  }

  /** The SAM bound to the batch. */
  public static final class Sam {
    public String samId;
    public String certificate;
    public String certificateSha256;
    public String ski;
    public String subject;
    public String notBefore;
    public String notAfter;
    public int scpKeyVersion;
    public String kdd;
  }

  /** F9 certificate validity requested from the SAM. */
  public static final class F9 {
    public int validityDays;
  }

  public static Path file(String producer, String batch) {
    return ProducerPaths.batch(producer, batch).resolve("batch.json");
  }

  public static boolean exists(String producer, String batch) {
    return Files.exists(file(producer, batch), LinkOption.NOFOLLOW_LINKS);
  }

  public static BatchMetadata read(String producer, String batch) throws IOException {
    Path file = file(producer, batch);
    if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
      throw new IllegalArgumentException("Batch does not exist: " + batch);
    }
    String json = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
    JsonObject document = JsonParser.parseString(json).getAsJsonObject();
    if (!document.has("schema") || !SCHEMA.equals(document.get("schema").getAsString())) {
      throw new IllegalArgumentException(
          "Batch " + batch + " is not schema " + SCHEMA + "; receive its SAM again");
    }
    if (document.has("lcg")) {
      throw new IllegalStateException(
          "Batch record " + file + " holds LCG parameters; they never leave the root station");
    }
    return GSON.fromJson(json, BatchMetadata.class);
  }

  /** Creates {@code batch.json}; an existing file is refused. */
  public Path writeNew() throws IOException {
    ProducerPaths.createDirectories(directory().resolve("receipts"));
    return SecureFiles.writeNew(file(producer, name), toJson());
  }

  /** Replaces {@code batch.json} atomically. */
  public Path replace() throws IOException {
    return SecureFiles.replaceAtomically(file(producer, name), toJson());
  }

  public Path directory() {
    return ProducerPaths.batch(producer, name);
  }

  private byte[] toJson() {
    return GSON.toJson(this).getBytes(StandardCharsets.UTF_8);
  }
}
