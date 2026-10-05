/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import com.google.gson.JsonObject;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.SecureFiles;
import dev.mistial.tools.openfips201.producer.ProducerPaths;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * The root station's allocation registry: {@code registry/allocations.jsonl}, one root-signed
 * canonical JSON line per event ({@link CanonicalJson}).
 *
 * <p>Line members: {@code v} (1), {@code seq} (0 for genesis, then +1), {@code type} ({@code
 * genesis | allocate | bind | topup}), {@code iin}, {@code batch}, {@code at}, {@code prev} (hex
 * SHA-256 of the previous line's UTF-8 text; 64 zeros for genesis) and {@code sig}. {@code
 * allocate} adds {@code quota}; {@code bind} adds {@code samId} and {@code allocationSeq}; {@code
 * topup} adds {@code samId}, {@code ts} and {@code add}.
 *
 * <p>The head ({@code seq(4) || SHA-256(last line)}) is also held by the root custody. Every
 * registry command first requires the file head to equal the custody head, which refuses a stale or
 * forked copy of the file. Batch numbers are unique per IIN: a second allocation of an (IIN, batch)
 * is refused.
 */
public final class AllocationRegistry {
  public static final String GENESIS = "genesis";
  public static final String ALLOCATE = "allocate";
  public static final String BIND = "bind";
  public static final String TOPUP = "topup";
  public static final long MAX_QUOTA = 100_000_000L;

  private final Path file;
  private final RootKeys keys;
  private final List<String> lines;

  private AllocationRegistry(Path file, RootKeys keys, List<String> lines) {
    this.file = file;
    this.keys = keys;
    this.lines = lines;
  }

  public static Path file(String producer) {
    return ProducerPaths.producer(producer).resolve("registry").resolve("allocations.jsonl");
  }

  /** {@code root init}: creates the registry with its genesis line. */
  public static AllocationRegistry create(String producer, RootKeys keys) throws Exception {
    Path file = file(producer);
    if (Files.exists(file) || keys.readRegistryHead() != null) {
      throw new IllegalStateException("The allocation registry of " + producer + " exists");
    }
    ProducerPaths.createDirectories(file.getParent());
    JsonObject genesis = header(0, GENESIS, IssuanceLedger.ZERO_HASH);
    genesis.addProperty("producer", producer);
    String text = CanonicalJson.sign(genesis, keys.rootSigner());
    SecureFiles.writeNew(file, (text + "\n").getBytes(StandardCharsets.UTF_8));
    keys.writeRegistryHead(head(0, text));
    return new AllocationRegistry(
        file, keys, new ArrayList<String>(Collections.singletonList(text)));
  }

  /**
   * Opens the registry: every line must verify under the root and chain to its predecessor, and the
   * file head must equal the custody head.
   */
  public static AllocationRegistry open(String producer, RootKeys keys) throws IOException {
    Path file = file(producer);
    if (!Files.exists(file)) {
      throw new IllegalStateException("No allocation registry; run 'root init'");
    }
    List<String> lines = read(file);
    verifyChain(lines, keys.rootCertificate().getPublicKey());
    byte[] expected = head(lines.size() - 1, lines.get(lines.size() - 1));
    if (!Arrays.equals(expected, keys.readRegistryHead())) {
      throw new IllegalStateException(
          "The allocation registry file does not match the root token head (stale or forked copy)");
    }
    return new AllocationRegistry(file, keys, new ArrayList<String>(lines));
  }

  static List<String> read(Path file) throws IOException {
    String content = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
    if (content.isEmpty() || !content.endsWith("\n")) {
      throw new IllegalStateException(file + " is not a complete registry");
    }
    List<String> lines = new ArrayList<String>();
    for (String line : content.substring(0, content.length() - 1).split("\n", -1)) {
      lines.add(line);
    }
    return lines;
  }

  /** Verifies signatures, sequence numbers and the hash chain of a whole registry. */
  public static void verifyChain(List<String> lines, PublicKey root) {
    String previous = null;
    for (int i = 0; i < lines.size(); i++) {
      JsonObject line = CanonicalJson.verify(lines.get(i), root);
      if (line.get("seq").getAsLong() != i) {
        throw new IllegalStateException("registry line " + i + " has seq " + line.get("seq"));
      }
      String prev = previous == null ? IssuanceLedger.ZERO_HASH : IssuanceLedger.hash(previous);
      if (!prev.equals(line.get("prev").getAsString())) {
        throw new IllegalStateException(
            "registry line " + i + " does not chain to its predecessor");
      }
      if (i == 0 && !GENESIS.equals(line.get("type").getAsString())) {
        throw new IllegalStateException("the registry does not start with genesis");
      }
      previous = lines.get(i);
    }
  }

  private static byte[] head(long seq, String lastLine) {
    byte[] out = new byte[36];
    System.arraycopy(IssuanceCrypto.unsigned(seq, 4), 0, out, 0, 4);
    System.arraycopy(
        IssuanceCrypto.sha256(lastLine.getBytes(StandardCharsets.UTF_8)), 0, out, 4, 32);
    return out;
  }

  private static JsonObject header(long seq, String type, String prev) {
    JsonObject line = new JsonObject();
    line.addProperty("v", 1);
    line.addProperty("seq", seq);
    line.addProperty("type", type);
    line.addProperty("at", Instant.now().toString());
    line.addProperty("prev", prev);
    return line;
  }

  public List<String> lines() {
    return Collections.unmodifiableList(lines);
  }

  /** The allocate line of (iin, batch), or null. */
  public JsonObject allocation(int iin, int batch) {
    return find(ALLOCATE, iin, batch);
  }

  /** The bind line of (iin, batch), or null. */
  public JsonObject binding(int iin, int batch) {
    return find(BIND, iin, batch);
  }

  /** The text of line {@code seq}. */
  public String line(long seq) {
    return lines.get((int) seq);
  }

  private JsonObject find(String type, int iin, int batch) {
    JsonObject found = null;
    for (String text : lines) {
      JsonObject line = com.google.gson.JsonParser.parseString(text).getAsJsonObject();
      if (type.equals(line.get("type").getAsString())
          && line.get("iin").getAsInt() == iin
          && line.get("batch").getAsInt() == batch) {
        found = line;
      }
    }
    return found;
  }

  /** The latest topup timestamp authorized for (iin, batch), or -1. */
  public long lastTopUpTs(int iin, int batch) {
    long ts = -1;
    for (String text : lines) {
      JsonObject line = com.google.gson.JsonParser.parseString(text).getAsJsonObject();
      if (TOPUP.equals(line.get("type").getAsString())
          && line.get("iin").getAsInt() == iin
          && line.get("batch").getAsInt() == batch) {
        ts = Math.max(ts, line.get("ts").getAsLong());
      }
    }
    return ts;
  }

  /** {@code root allocate}: appends an allocation; refuses a duplicate (IIN, batch). */
  public JsonObject allocate(int iin, int batch, long quota) throws Exception {
    if (iin < 0 || iin > 9999 || batch < 0 || batch > 9999) {
      throw new IllegalArgumentException("IIN and batch must be 0..9999");
    }
    if (quota < 1 || quota > MAX_QUOTA) {
      throw new IllegalArgumentException("quota must be 1.." + MAX_QUOTA);
    }
    if (allocation(iin, batch) != null) {
      throw new IllegalArgumentException(
          String.format("IIN %04d batch %04d is already allocated", iin, batch));
    }
    JsonObject line = next(ALLOCATE, iin, batch);
    line.addProperty("quota", quota);
    return append(line);
  }

  /**
   * Prepares the bind line of an unbound allocation without appending it, so the SAM certificate
   * can commit to the registry head that follows it ({@link #headAfter}).
   */
  public String prepareBind(int iin, int batch, String samId) throws Exception {
    JsonObject allocation = allocation(iin, batch);
    if (allocation == null) {
      throw new IllegalArgumentException(
          String.format("IIN %04d batch %04d is not allocated; run 'root allocate'", iin, batch));
    }
    if (binding(iin, batch) != null) {
      throw new IllegalStateException(
          String.format("IIN %04d batch %04d is already bound to a SAM", iin, batch));
    }
    JsonObject line = next(BIND, iin, batch);
    line.addProperty("samId", samId);
    line.addProperty("allocationSeq", allocation.get("seq").getAsLong());
    return CanonicalJson.sign(line, keys.rootSigner());
  }

  /** SHA-256 of a prepared line: the registry head once it is appended. */
  public static byte[] headAfter(String preparedLine) {
    return IssuanceCrypto.sha256(preparedLine.getBytes(StandardCharsets.UTF_8));
  }

  /** Appends a line prepared by {@link #prepareBind}; nothing may have been appended since. */
  public void commit(String preparedLine) throws IOException {
    JsonObject line = com.google.gson.JsonParser.parseString(preparedLine).getAsJsonObject();
    if (line.get("seq").getAsLong() != lines.size()
        || !IssuanceLedger.hash(lines.get(lines.size() - 1))
            .equals(line.get("prev").getAsString())) {
      throw new IllegalStateException("the registry changed since the line was prepared");
    }
    write(preparedLine);
  }

  /** {@code root sign-top-up}: records an authorized top-up of a bound batch. */
  public JsonObject topUp(int iin, int batch, String samId, long ts, long add) throws Exception {
    JsonObject binding = binding(iin, batch);
    if (binding == null || !samId.equals(binding.get("samId").getAsString())) {
      throw new IllegalArgumentException("the top-up names a SAM that is not bound to the batch");
    }
    if (ts <= lastTopUpTs(iin, batch)) {
      throw new IllegalArgumentException("top-up timestamps must strictly increase");
    }
    JsonObject line = next(TOPUP, iin, batch);
    line.addProperty("samId", samId);
    line.addProperty("ts", ts);
    line.addProperty("add", add);
    return append(line);
  }

  private JsonObject next(String type, int iin, int batch) {
    JsonObject line = header(lines.size(), type, IssuanceLedger.hash(lines.get(lines.size() - 1)));
    line.addProperty("iin", iin);
    line.addProperty("batch", batch);
    return line;
  }

  private JsonObject append(JsonObject line) throws Exception {
    String text = CanonicalJson.sign(line, keys.rootSigner());
    write(text);
    return com.google.gson.JsonParser.parseString(text).getAsJsonObject();
  }

  private void write(String text) throws IOException {
    SecureFiles.appendLine(file, text + "\n");
    lines.add(text);
    keys.writeRegistryHead(head(lines.size() - 1, text));
  }

  /**
   * Verifies an allocate/bind pair exported from a registry: both signed by the root, the same IIN
   * and batch, the bind naming the allocation's seq and {@code samId}.
   *
   * @return the parsed bind line
   */
  public static JsonObject verifyBinding(
      String allocateText, String bindText, PublicKey root, String samId) {
    JsonObject allocate = CanonicalJson.verify(allocateText, root);
    JsonObject bind = CanonicalJson.verify(bindText, root);
    if (!ALLOCATE.equals(allocate.get("type").getAsString())
        || !BIND.equals(bind.get("type").getAsString())
        || allocate.get("iin").getAsInt() != bind.get("iin").getAsInt()
        || allocate.get("batch").getAsInt() != bind.get("batch").getAsInt()
        || bind.get("allocationSeq").getAsLong() != allocate.get("seq").getAsLong()
        || bind.get("seq").getAsLong() <= allocate.get("seq").getAsLong()
        || !samId.equals(bind.get("samId").getAsString())) {
      throw new IllegalStateException("the registry lines do not bind this SAM to its allocation");
    }
    return bind;
  }

  /** Hex of {@link #headAfter}, as recorded by the SAM certificate. */
  public static String headHex(String line) {
    return HexUtil.format(headAfter(line));
  }
}
