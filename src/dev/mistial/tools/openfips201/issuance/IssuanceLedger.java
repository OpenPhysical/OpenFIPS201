/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.SecureFiles;
import dev.mistial.tools.openfips201.crypto.KeyIdentifiers;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * {@code batches/<b>/ledger.jsonl}: the host's hash-chained record of every SAM event and card
 * outcome of a batch.
 *
 * <p>Each line is one compact JSON object whose first members are {@code v} (1), {@code type},
 * {@code at} (ISO-8601) and {@code prev}: the hex SHA-256 of the previous line's UTF-8 octets, or
 * 64 zeros on the first line. Types:
 *
 * <ul>
 *   <li>{@code genesis}, {@code topup}, {@code issue}, {@code void}, {@code close}, {@code term}:
 *       carry the SAM ledger {@code entry}, its SAM {@code sig}, {@code eventSeq} and {@code head};
 *   <li>{@code outcome}: the final status of an issued OPID's card, optionally linked to the
 *       attempt it replaces ({@code reissueOf}) or that replaces it ({@code supersededBy});
 *   <li>{@code lost}: an issued OPID whose card will never carry it.
 * </ul>
 *
 * <p>{@code void} records a SAM VOID of an issued OPID; {@code close} the SAM's CLOSE, after which
 * the batch produces no cards; {@code term} the SAM's TERMINATE.
 *
 * <p>Lines are appended under the batch lock held by the caller; {@link SecureFiles#appendLine}
 * additionally serializes writers on the file.
 */
public final class IssuanceLedger {
  public static final String GENESIS = "genesis";
  public static final String TOPUP = "topup";
  public static final String ISSUE = "issue";
  public static final String OUTCOME = "outcome";
  public static final String LOST = "lost";
  public static final String VOID = "void";
  public static final String CLOSE = "close";
  public static final String TERM = "term";

  static final String ZERO_HASH = HexUtil.format(new byte[32]);
  private static final Gson GSON = new Gson();

  private final Path file;

  public IssuanceLedger(Path file) {
    this.file = file;
  }

  public Path file() {
    return file;
  }

  /** One ledger line: its exact text and parsed members. */
  public static final class Line {
    public final int number;
    public final String text;
    public final JsonObject json;

    Line(int number, String text, JsonObject json) {
      this.number = number;
      this.text = text;
      this.json = json;
    }

    public String type() {
      return string("type");
    }

    public String string(String name) {
      JsonElement element = json.get(name);
      return element == null || element.isJsonNull() ? null : element.getAsString();
    }

    public long number(String name) {
      JsonElement element = json.get(name);
      return element == null || element.isJsonNull() ? -1 : element.getAsLong();
    }

    /** The SAM entry carried by a genesis, topup or issue line, or null. */
    public SamLedgerEntry.Signed samEntry() {
      String entry = string("entry");
      if (entry == null) {
        return null;
      }
      String sig = string("sig");
      return new SamLedgerEntry.Signed(
          SamLedgerEntry.parse(HexUtil.parse(entry)), sig == null ? null : HexUtil.parse(sig));
    }
  }

  /** Reads every line; an absent file is an empty ledger. A malformed line fails. */
  public List<Line> read() throws IOException {
    if (!Files.exists(file)) {
      return Collections.emptyList();
    }
    List<Line> lines = new ArrayList<Line>();
    String content = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
    if (content.isEmpty()) {
      return lines;
    }
    if (!content.endsWith("\n")) {
      throw new IllegalStateException(file + " does not end with a complete line");
    }
    String[] texts = content.substring(0, content.length() - 1).split("\n", -1);
    for (int i = 0; i < texts.length; i++) {
      JsonElement parsed;
      try {
        parsed = JsonParser.parseString(texts[i]);
      } catch (RuntimeException e) {
        throw new IllegalStateException("ledger line " + (i + 1) + " is not JSON", e);
      }
      if (!parsed.isJsonObject()) {
        throw new IllegalStateException("ledger line " + (i + 1) + " is not a JSON object");
      }
      lines.add(new Line(i + 1, texts[i], parsed.getAsJsonObject()));
    }
    return lines;
  }

  public Line appendGenesis(SamLedgerEntry.Signed genesis) throws IOException {
    JsonObject line = samLine(GENESIS, genesis);
    line.addProperty("quota", genesis.entry.quota);
    line.addProperty("paramsDigest", HexUtil.format(genesis.entry.paramsDigest()));
    return append(line);
  }

  public Line appendTopUp(SamLedgerEntry.Signed topUp) throws IOException {
    JsonObject line = samLine(TOPUP, topUp);
    line.addProperty("ts", topUp.entry.timestamp);
    line.addProperty("add", topUp.entry.added);
    line.addProperty("quota", topUp.entry.quota);
    return append(line);
  }

  /**
   * @param certificateSha256 hex SHA-256 of the issued F9 certificate, or null when only the entry
   *     was recovered
   * @param recovered whether the entry came from GET LAST ENTRY rather than the ISSUE response
   */
  public Line appendIssue(
      SamLedgerEntry.Signed issue, String certificateSha256, String receipt, boolean recovered)
      throws IOException {
    JsonObject line = samLine(ISSUE, issue);
    line.addProperty("seq", issue.entry.issuanceSeq);
    line.addProperty("opid", issue.entry.opid);
    line.addProperty("f9Ski", HexUtil.format(issue.entry.f9Ski()));
    if (certificateSha256 != null) {
      line.addProperty("certificateSha256", certificateSha256);
    }
    if (receipt != null) {
      line.addProperty("receipt", receipt);
    }
    line.addProperty("recovered", recovered);
    return append(line);
  }

  public Line appendOutcome(long seq, String opid, String status, String stage, String receipt)
      throws IOException {
    return appendOutcome(seq, opid, status, stage, receipt, null, null);
  }

  /**
   * @param reissueOf the receipt of the burned attempt this card replaces, or null
   * @param supersededBy the receipt of the attempt that replaces this one, or null
   */
  public Line appendOutcome(
      long seq,
      String opid,
      String status,
      String stage,
      String receipt,
      String reissueOf,
      String supersededBy)
      throws IOException {
    JsonObject line = header(OUTCOME);
    line.addProperty("seq", seq);
    line.addProperty("opid", opid);
    line.addProperty("status", status);
    if (stage != null) {
      line.addProperty("stage", stage);
    }
    if (receipt != null) {
      line.addProperty("receipt", receipt);
    }
    if (reissueOf != null) {
      line.addProperty("reissueOf", reissueOf);
    }
    if (supersededBy != null) {
      line.addProperty("supersededBy", supersededBy);
    }
    return append(line);
  }

  /** The SAM's signed VOID entry. */
  public Line appendVoid(SamLedgerEntry.Signed voided, String receipt) throws IOException {
    JsonObject line = samLine(VOID, voided);
    line.addProperty("seq", voided.entry.issuanceSeq);
    line.addProperty("opid", voided.entry.opid);
    line.addProperty("reason", voided.entry.reason);
    if (receipt != null) {
      line.addProperty("receipt", receipt);
    }
    return append(line);
  }

  public Line appendLost(long seq, String opid, String reason) throws IOException {
    JsonObject line = header(LOST);
    line.addProperty("seq", seq);
    line.addProperty("opid", opid);
    line.addProperty("reason", reason);
    return append(line);
  }

  /** The SAM's signed CLOSE entry: the final issued count and quota. */
  public Line appendClose(SamLedgerEntry.Signed close) throws IOException {
    JsonObject line = samLine(CLOSE, close);
    line.addProperty("issued", close.entry.issued);
    line.addProperty("quota", close.entry.quota);
    return append(line);
  }

  /** Whether a {@code close} line was recorded. */
  public boolean isClosed() throws IOException {
    for (Line line : read()) {
      if (CLOSE.equals(line.type())) {
        return true;
      }
    }
    return false;
  }

  /** The {@code issue} line of issuance {@code seq}, or null. */
  public Line issueLine(long seq) throws IOException {
    for (Line line : read()) {
      if (ISSUE.equals(line.type()) && line.number("seq") == seq) {
        return line;
      }
    }
    return null;
  }

  /** The {@code issue} line naming {@code receipt}, or null. */
  public Line issueLineOf(String receipt) throws IOException {
    for (Line line : read()) {
      if (ISSUE.equals(line.type()) && receipt.equals(line.string("receipt"))) {
        return line;
      }
    }
    return null;
  }

  /** The SAM's signed TERM entry (TERMINATE). */
  public Line appendTerminate(SamLedgerEntry.Signed term) throws IOException {
    JsonObject line = samLine(TERM, term);
    line.addProperty("issued", term.entry.issued);
    line.addProperty("quota", term.entry.quota);
    return append(line);
  }

  /** The last SAM entry recorded, or null for an empty ledger. */
  public SamLedgerEntry.Signed lastSamEntry() throws IOException {
    SamLedgerEntry.Signed last = null;
    for (Line line : read()) {
      SamLedgerEntry.Signed entry = line.samEntry();
      if (entry != null) {
        last = entry;
      }
    }
    return last;
  }

  /** The highest issuance sequence recorded (0 when nothing was issued). */
  public long lastIssueSeq() throws IOException {
    long seq = 0;
    for (Line line : read()) {
      if (ISSUE.equals(line.type())) {
        seq = Math.max(seq, line.number("seq"));
      }
    }
    return seq;
  }

  private JsonObject samLine(String type, SamLedgerEntry.Signed signed) {
    JsonObject line = header(type);
    line.addProperty("eventSeq", signed.entry.eventSeq);
    line.addProperty("head", HexUtil.format(signed.entry.head()));
    line.addProperty("entry", HexUtil.format(signed.entry.encoded()));
    byte[] signature = signed.signature();
    if (signature != null) {
      line.addProperty("sig", HexUtil.format(signature));
    }
    return line;
  }

  private static JsonObject header(String type) {
    JsonObject line = new JsonObject();
    line.addProperty("v", 1);
    line.addProperty("type", type);
    line.addProperty("at", Instant.now().toString());
    return line;
  }

  private Line append(JsonObject body) throws IOException {
    List<Line> existing = read();
    JsonObject line = new JsonObject();
    line.add("v", body.get("v"));
    line.add("type", body.get("type"));
    line.add("at", body.get("at"));
    line.addProperty(
        "prev", existing.isEmpty() ? ZERO_HASH : hash(existing.get(existing.size() - 1).text));
    for (Map.Entry<String, JsonElement> member : body.entrySet()) {
      if (!line.has(member.getKey())) {
        line.add(member.getKey(), member.getValue());
      }
    }
    String text = GSON.toJson(line);
    if (text.indexOf('\n') >= 0) {
      throw new IllegalStateException("ledger lines are single-line JSON");
    }
    if (!Files.exists(file)) {
      SecureFiles.writeNew(file, (text + "\n").getBytes(StandardCharsets.UTF_8));
    } else {
      SecureFiles.appendLine(file, text + "\n");
    }
    return new Line(existing.size() + 1, text, line);
  }

  static String hash(String text) {
    return HexUtil.format(IssuanceCrypto.sha256(text.getBytes(StandardCharsets.UTF_8)));
  }

  /**
   * Offline verification.
   *
   * <ul>
   *   <li>every line is version 1 JSON; the first is genesis; each {@code prev} is the hash of the
   *       previous line;
   *   <li>every SAM entry verifies under the SAM key and names the SAM SKI; entries form the SAM
   *       chain (eventSeq + 1, prevHead = previous head; genesis event 1 with prevHead 0^32);
   *   <li>genesis commits to the SAM certificate hash, the batch paramsDigest and the initial
   *       quota;
   *   <li>issuance numbers run 1, 2, ...; each OPID is a canonical 17-digit OPID of the batch IIN;
   *       no OPID and no F9 key identifier appears twice (the OPIDs themselves are the SAM's: the
   *       production station never recomputes them);
   *   <li>every outcome, lost and void line names an issued (seq, OPID) pair;
   *   <li>close records the final issued count; after it no issue or topup follows; nothing follows
   *       term.
   * </ul>
   *
   * @param samKey public key of the SAM certificate
   * @param samCertificate the SAM certificate DER (sam.pem)
   * @param paramsDigest the batch paramsDigest
   * @param iin the batch IIN
   */
  public Report verify(
      PublicKey samKey, byte[] samCertificate, byte[] paramsDigest, long initialQuota, int iin)
      throws IOException {
    Report report = new Report();
    List<Line> lines;
    try {
      lines = read();
    } catch (IllegalStateException e) {
      report.problem(e.getMessage());
      return report;
    }
    if (lines.isEmpty()) {
      report.problem("ledger is empty; it has no genesis line");
      return report;
    }
    byte[] samSki = KeyIdentifiers.ski(samKey);
    String previousText = null;
    SamLedgerEntry previousEntry = null;
    long expectedSeq = 1;
    Set<String> opids = new HashSet<String>();
    Set<String> f9Skis = new HashSet<String>();
    Map<Long, String> issued = new HashMap<Long, String>();
    for (Line line : lines) {
      String where = "line " + line.number;
      if (line.number("v") != 1) {
        report.problem(where + ": version is not 1");
      }
      String expectedPrev = previousText == null ? ZERO_HASH : hash(previousText);
      if (!expectedPrev.equals(line.string("prev"))) {
        report.problem(where + ": prev does not hash the previous line");
      }
      previousText = line.text;
      String type = line.type();
      if (line.number == 1 && !GENESIS.equals(type)) {
        report.problem(where + ": the first line is not genesis");
      }
      if (report.terminated) {
        report.problem(where + ": " + type + " line after the SAM was terminated");
      }
      if (report.closed && (ISSUE.equals(type) || TOPUP.equals(type) || CLOSE.equals(type))) {
        report.problem(where + ": " + type + " line after the batch was closed");
      }
      if (GENESIS.equals(type)
          || TOPUP.equals(type)
          || ISSUE.equals(type)
          || VOID.equals(type)
          || CLOSE.equals(type)
          || TERM.equals(type)) {
        SamLedgerEntry.Signed signed;
        try {
          signed = line.samEntry();
        } catch (RuntimeException e) {
          report.problem(where + ": SAM entry is malformed: " + e.getMessage());
          continue;
        }
        if (signed == null) {
          report.problem(where + ": " + type + " line carries no SAM entry");
          continue;
        }
        SamLedgerEntry entry = signed.entry;
        if (!signed.verify(samKey)) {
          report.problem(where + ": SAM signature does not verify");
        }
        if (!Arrays.equals(entry.samSki(), samSki)) {
          report.problem(where + ": entry names a different SAM");
        }
        if (!type.equals(entry.typeName().toLowerCase(java.util.Locale.ROOT))) {
          report.problem(where + ": line type " + type + " carries a " + entry.typeName());
        }
        if (previousEntry == null) {
          if (entry.type != SamLedgerEntry.TYPE_GENESIS
              || entry.eventSeq != 1
              || !Arrays.equals(entry.prevHead(), new byte[32])) {
            report.problem(where + ": the SAM chain does not start at its genesis entry");
          }
        } else {
          if (entry.eventSeq != previousEntry.eventSeq + 1) {
            report.problem(
                where
                    + ": SAM eventSeq "
                    + entry.eventSeq
                    + " does not follow "
                    + previousEntry.eventSeq);
          }
          if (!Arrays.equals(entry.prevHead(), previousEntry.head())) {
            report.problem(where + ": SAM prevHead is not the previous entry's head");
          }
        }
        previousEntry = entry;
        report.lastEntry = signed;
        if (entry.type == SamLedgerEntry.TYPE_GENESIS) {
          if (!Arrays.equals(entry.samCertificateSha256(), IssuanceCrypto.sha256(samCertificate))) {
            report.problem(where + ": genesis does not commit to sam.pem");
          }
          if (!Arrays.equals(entry.paramsDigest(), paramsDigest)) {
            report.problem(where + ": genesis paramsDigest differs from batch.json");
          }
          if (entry.quota != initialQuota) {
            report.problem(where + ": genesis quota differs from batch.json");
          }
        }
        if (entry.type == SamLedgerEntry.TYPE_TERMINATE) {
          report.terminated = true;
          if (entry.issued != report.issued) {
            report.problem(where + ": the TERM entry's issued count differs from the ledger");
          }
        }
        if (entry.type == SamLedgerEntry.TYPE_CLOSE) {
          report.closed = true;
          if (entry.issued != report.issued) {
            report.problem(where + ": the CLOSE entry's issued count differs from the ledger");
          }
        }
        if (entry.type == SamLedgerEntry.TYPE_VOID) {
          String opid = issued.get(entry.issuanceSeq);
          if (opid == null || !opid.equals(entry.opid)) {
            report.problem(where + ": VOID names an OPID that was not issued");
          } else {
            report.voided.add(entry.opid);
          }
        }
        if (entry.type == SamLedgerEntry.TYPE_ISSUE) {
          if (entry.issuanceSeq != expectedSeq) {
            report.problem(
                where + ": issuance " + entry.issuanceSeq + " where " + expectedSeq + " was due");
          }
          expectedSeq = entry.issuanceSeq + 1;
          try {
            dev.mistial.tools.openfips201.opid.Opid parsed =
                dev.mistial.tools.openfips201.opid.Opid.parseCanonical(entry.opid);
            if (parsed.iin != iin) {
              report.problem(where + ": OPID " + entry.opid + " is not of IIN " + iin);
            }
          } catch (RuntimeException e) {
            report.problem(where + ": " + e.getMessage());
          }
          if (!opids.add(entry.opid)) {
            report.problem(where + ": duplicate OPID " + entry.opid);
          }
          String ski = HexUtil.format(entry.f9Ski());
          if (!f9Skis.add(ski)) {
            report.problem(where + ": duplicate F9 key identifier " + ski);
          }
          issued.put(entry.issuanceSeq, entry.opid);
          report.opids.put(entry.issuanceSeq, entry.opid);
          report.issued = Math.max(report.issued, entry.issuanceSeq);
        }
      } else if (OUTCOME.equals(type) || LOST.equals(type)) {
        String opid = issued.get(line.number("seq"));
        if (opid == null || !opid.equals(line.string("opid"))) {
          report.problem(where + ": " + type + " names an OPID that was not issued");
        }
      } else {
        report.problem(where + ": unknown line type " + type);
      }
    }
    return report;
  }

  /** Result of {@link #verify}. */
  public static final class Report {
    public final List<String> problems = new ArrayList<String>();

    /** Issued OPIDs by issuance number. */
    public final Map<Long, String> opids = new java.util.TreeMap<Long, String>();

    /** OPIDs the SAM voided. */
    public final Set<String> voided = new HashSet<String>();

    public SamLedgerEntry.Signed lastEntry;
    public long issued;

    /** Issued OPIDs replayed against the batch sequence (root audit only). */
    public long audited;

    /** Issued OPIDs the live SAM DECIPHERed back to their issuance numbers. */
    public long deciphered;

    public boolean closed;
    public boolean terminated;

    void problem(String text) {
      problems.add(text);
    }

    public boolean valid() {
      return problems.isEmpty();
    }
  }
}
