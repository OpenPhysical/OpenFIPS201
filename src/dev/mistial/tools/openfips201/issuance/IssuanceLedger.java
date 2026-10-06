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
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * {@code batches/<b>/ledger.jsonl}: the host's hash-chained record of every SAM event and card
 * outcome of a batch.
 *
 * <p>Each line is one compact JSON object whose first members are {@code v} (the format version),
 * {@code type}, {@code at} (ISO-8601) and {@code prev}: the hex SHA-256 of the previous line's
 * UTF-8 octets, or 64 zeros on the first line. Types:
 *
 * <ul>
 *   <li>{@code genesis}, {@code topup}, {@code issue}, {@code void}, {@code close}, {@code term}:
 *       carry the SAM ledger {@code entry}, its SAM {@code sig}, {@code eventSeq} and {@code head};
 *   <li>{@code outcome}: the final status of an issued OPID's card, optionally linked to the
 *       attempt it replaces ({@code reissueOf}) or that replaces it ({@code supersededBy});
 *   <li>{@code lost}: an issued OPID whose card will never carry it;
 *   <li>{@code receipt} (v2): binds a receipt rewrite that no {@code issue}, {@code outcome} or
 *       {@code void} line binds: {@code receipt} (file name), {@code sha256}, {@code reason}.
 * </ul>
 *
 * <p>{@code void} records a SAM VOID of an issued OPID; {@code close} the SAM's CLOSE, after which
 * the batch produces no cards; {@code term} the SAM's TERMINATE.
 *
 * <p>Format versions. The genesis line fixes the version of the whole ledger; every later line
 * carries the same {@code v}.
 *
 * <ul>
 *   <li>{@value #VERSION} (current): receipts are bound. An {@code issue}, {@code outcome} or
 *       {@code void} line that follows a rewrite of the receipt it names carries {@code
 *       receiptSha256}, the hex SHA-256 of the receipt file's octets as written; every other
 *       rewrite of a receipt is followed by a {@code receipt} line. {@link #verify} requires each
 *       receipt the ledger names to exist and to hash to the last value the ledger recorded for it.
 *   <li>{@value #LEGACY_VERSION} (legacy): receipts are named but not bound. Such a ledger is still
 *       appended in v1 and verifies only with the warning {@value #LEGACY_WARNING}.
 * </ul>
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
  public static final String RECEIPT = "receipt";

  /** Ledger format version written for a new ledger: receipts bound by hash. */
  public static final int VERSION = 2;

  /** The previous format version, whose receipts are not bound. */
  public static final int LEGACY_VERSION = 1;

  /** The verification warning of a {@value #LEGACY_VERSION} ledger. */
  public static final String LEGACY_WARNING =
      "ledger format v1 (legacy): receipts not bound; their contents are not tamper-evident";

  /** A receipt file name as the orchestrator creates it: no path separator, no leading dot. */
  private static final Pattern RECEIPT_NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]*\\.json");

  private static final Pattern SHA256_HEX = Pattern.compile("[0-9A-F]{64}");

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
   * @param receiptSha256 hex SHA-256 of {@code receipt} as just rewritten by the caller, or null
   *     when the caller did not rewrite it
   * @param recovered whether the entry came from GET LAST ENTRY rather than the ISSUE response
   */
  public Line appendIssue(
      SamLedgerEntry.Signed issue,
      String certificateSha256,
      String receipt,
      String receiptSha256,
      boolean recovered)
      throws IOException {
    JsonObject line = samLine(ISSUE, issue);
    line.addProperty("seq", issue.entry.issuanceSeq);
    line.addProperty("opid", issue.entry.opid);
    line.addProperty("f9Ski", HexUtil.format(issue.entry.f9Ski()));
    if (certificateSha256 != null) {
      line.addProperty("certificateSha256", certificateSha256);
    }
    addReceipt(line, receipt, receiptSha256);
    line.addProperty("recovered", recovered);
    return append(line);
  }

  public Line appendOutcome(long seq, String opid, String status, String stage, String receipt)
      throws IOException {
    return appendOutcome(seq, opid, status, stage, receipt, null, null, null);
  }

  /**
   * @param receiptSha256 hex SHA-256 of {@code receipt} as just rewritten by the caller, or null
   *     when the caller did not rewrite it
   * @param reissueOf the receipt of the burned attempt this card replaces, or null
   * @param supersededBy the receipt of the attempt that replaces this one, or null
   */
  public Line appendOutcome(
      long seq,
      String opid,
      String status,
      String stage,
      String receipt,
      String receiptSha256,
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
    addReceipt(line, receipt, receiptSha256);
    if (reissueOf != null) {
      line.addProperty("reissueOf", reissueOf);
    }
    if (supersededBy != null) {
      line.addProperty("supersededBy", supersededBy);
    }
    return append(line);
  }

  /** The SAM's signed VOID entry, naming a receipt the caller did not rewrite. */
  public Line appendVoid(SamLedgerEntry.Signed voided, String receipt) throws IOException {
    return appendVoid(voided, receipt, null);
  }

  /**
   * The SAM's signed VOID entry.
   *
   * @param receiptSha256 hex SHA-256 of {@code receipt} as just rewritten by the caller, or null
   *     when the caller did not rewrite it
   */
  public Line appendVoid(SamLedgerEntry.Signed voided, String receipt, String receiptSha256)
      throws IOException {
    JsonObject line = samLine(VOID, voided);
    line.addProperty("seq", voided.entry.issuanceSeq);
    line.addProperty("opid", voided.entry.opid);
    line.addProperty("reason", voided.entry.reason);
    addReceipt(line, receipt, receiptSha256);
    return append(line);
  }

  /**
   * Binds a rewrite of {@code receipt} that no {@code issue}, {@code outcome} or {@code void} line
   * binds. The caller appends it immediately after the rewrite.
   *
   * @param sha256 hex SHA-256 of the receipt file's octets as written
   * @param reason why the receipt was rewritten (for example its new stage)
   * @return the line, or null for a {@value #LEGACY_VERSION} ledger, which does not bind receipts
   */
  public Line appendReceipt(String receipt, String sha256, String reason) throws IOException {
    if (receipt == null || sha256 == null || reason == null) {
      throw new IllegalArgumentException("a receipt line needs the receipt, its hash and a reason");
    }
    JsonObject line = header(RECEIPT);
    line.addProperty("receipt", receipt);
    line.addProperty("sha256", sha256);
    line.addProperty("reason", reason);
    return append(line);
  }

  private static void addReceipt(JsonObject line, String receipt, String receiptSha256) {
    if (receipt != null) {
      line.addProperty("receipt", receipt);
      if (receiptSha256 != null) {
        line.addProperty("receiptSha256", receiptSha256);
      }
    } else if (receiptSha256 != null) {
      throw new IllegalArgumentException("a receipt hash needs the receipt it binds");
    }
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
    line.addProperty("type", type);
    line.addProperty("at", Instant.now().toString());
    return line;
  }

  /**
   * The format version of a ledger: that of its genesis (first) line, or {@value #VERSION} for an
   * empty ledger. Any other version than {@value #VERSION} and {@value #LEGACY_VERSION} fails.
   */
  static int formatVersion(List<Line> lines) {
    if (lines.isEmpty()) {
      return VERSION;
    }
    long version = lines.get(0).number("v");
    if (version != VERSION && version != LEGACY_VERSION) {
      throw new IllegalStateException("unsupported ledger format version " + version);
    }
    return (int) version;
  }

  /**
   * Appends {@code body} in the ledger's format version. A {@value #LEGACY_VERSION} ledger keeps
   * its format: receipt hashes are not recorded and a {@code receipt} line is not written (null).
   */
  private Line append(JsonObject body) throws IOException {
    List<Line> existing = read();
    int version = formatVersion(existing);
    if (version == LEGACY_VERSION) {
      if (RECEIPT.equals(body.get("type").getAsString())) {
        return null;
      }
      body.remove("receiptSha256");
    }
    JsonObject line = new JsonObject();
    line.addProperty("v", version);
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
   *   <li>every line is JSON of the genesis line's format version ({@value #VERSION}, or {@value
   *       #LEGACY_VERSION} with the warning {@value #LEGACY_WARNING}); the first is genesis; each
   *       {@code prev} is the hash of the previous line;
   *   <li>every SAM entry verifies under the SAM key and names the SAM SKI; entries form the SAM
   *       chain (eventSeq + 1, prevHead = previous head; genesis event 1 with prevHead 0^32);
   *   <li>genesis commits to the SAM certificate hash, the batch paramsDigest and the initial
   *       quota;
   *   <li>issuance numbers run 1, 2, ...; each OPID is a canonical 17-digit OPID of the batch IIN;
   *       no OPID and no F9 key identifier appears twice (the OPIDs themselves are the SAM's: the
   *       production station never recomputes them);
   *   <li>every outcome, lost and void line names an issued (seq, OPID) pair;
   *   <li>close records the final issued count; after it no issue or topup follows; nothing follows
   *       term;
   *   <li>(v{@value #VERSION}) every receipt hash is 64 hex digits and binds a named receipt; every
   *       receipt name is a plain file name; with {@code receipts}, every receipt any line names
   *       exists there and its octets hash to the last value the ledger recorded for it.
   * </ul>
   *
   * @param samKey public key of the SAM certificate
   * @param samCertificate the SAM certificate DER (sam.pem)
   * @param paramsDigest the batch paramsDigest
   * @param iin the batch IIN
   * @param receipts the batch's {@code receipts} directory; null only for a ledger verified apart
   *     from its batch directory (the root audit of an exported ledger), whose receipt files are
   *     then not compared
   */
  public Report verify(
      PublicKey samKey,
      byte[] samCertificate,
      byte[] paramsDigest,
      long initialQuota,
      int iin,
      Path receipts)
      throws IOException {
    Report report = new Report();
    List<Line> lines;
    int version;
    try {
      lines = read();
      version = formatVersion(lines);
    } catch (IllegalStateException e) {
      report.problem(e.getMessage());
      return report;
    }
    if (lines.isEmpty()) {
      report.problem("ledger is empty; it has no genesis line");
      return report;
    }
    report.version = version;
    if (version == LEGACY_VERSION) {
      report.warning(LEGACY_WARNING);
    }
    // Receipt name -> the last hash the ledger recorded for it, or null while none is recorded.
    Map<String, String> boundReceipts = new LinkedHashMap<String, String>();
    byte[] samSki = KeyIdentifiers.ski(samKey);
    String previousText = null;
    SamLedgerEntry previousEntry = null;
    long expectedSeq = 1;
    Set<String> opids = new HashSet<String>();
    Set<String> f9Skis = new HashSet<String>();
    Map<Long, String> issued = new HashMap<Long, String>();
    for (Line line : lines) {
      String where = "line " + line.number;
      if (line.number("v") != version) {
        report.problem(where + ": version is not " + version + ", the genesis line's");
      }
      if (version == VERSION) {
        try {
          bindReceipt(report, where, line, boundReceipts);
        } catch (RuntimeException e) {
          report.problem(where + ": receipt binding is malformed: " + e.getMessage());
        }
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
      } else if (!(RECEIPT.equals(type) && version == VERSION)) {
        report.problem(where + ": unknown line type " + type);
      }
    }
    if (receipts != null) {
      for (Map.Entry<String, String> bound : boundReceipts.entrySet()) {
        checkReceipt(report, receipts, bound.getKey(), bound.getValue());
      }
    }
    return report;
  }

  /**
   * Records the receipt a v{@value #VERSION} line names and, when the line binds one, its hash: the
   * {@code receiptSha256} of an {@code issue}, {@code outcome} or {@code void} line, or the {@code
   * sha256} of a {@code receipt} line. A later binding of the same receipt supersedes an earlier
   * one.
   */
  private static void bindReceipt(
      Report report, String where, Line line, Map<String, String> bound) {
    boolean receiptLine = RECEIPT.equals(line.type());
    String receipt = line.string("receipt");
    String sha256 = line.string(receiptLine ? "sha256" : "receiptSha256");
    if (receiptLine && (receipt == null || sha256 == null || line.string("reason") == null)) {
      report.problem(where + ": receipt line lacks its receipt, sha256 or reason");
      return;
    }
    if (receipt == null) {
      if (sha256 != null) {
        report.problem(where + ": receipt hash without a receipt");
      }
      return;
    }
    if (!RECEIPT_NAME.matcher(receipt).matches()) {
      report.problem(where + ": receipt name " + receipt + " is not a plain receipt file name");
      return;
    }
    if (sha256 == null) {
      if (!bound.containsKey(receipt)) {
        bound.put(receipt, null);
      }
      return;
    }
    if (!SHA256_HEX.matcher(sha256).matches()) {
      report.problem(where + ": receipt hash of " + receipt + " is not 64 hex digits");
      return;
    }
    bound.put(receipt, sha256);
  }

  /** Fails a named receipt that is missing, never bound, or differs from its last binding. */
  private static void checkReceipt(Report report, Path receipts, String name, String sha256)
      throws IOException {
    Path file = receipts.resolve(name);
    if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
      report.problem("receipt " + name + " is missing");
      return;
    }
    if (sha256 == null) {
      report.problem("receipt " + name + " is named but no ledger line binds its hash");
      return;
    }
    if (!sha256.equals(HexUtil.format(IssuanceCrypto.sha256(Files.readAllBytes(file))))) {
      report.problem("receipt " + name + " differs from its last ledger binding (edited)");
      return;
    }
    report.receiptsVerified++;
  }

  /** Result of {@link #verify}. */
  public static final class Report {
    public final List<String> problems = new ArrayList<String>();

    /**
     * Conditions that do not invalidate the ledger but limit what verification established (a
     * legacy ledger's unbound receipts). Callers report them; a valid ledger with warnings is not a
     * clean pass.
     */
    public final List<String> warnings = new ArrayList<String>();

    /** The ledger's format version (0 when it could not be read). */
    public int version;

    /** Receipt files that matched their last ledger binding. */
    public long receiptsVerified;

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

    void warning(String text) {
      warnings.add(text);
    }

    public boolean valid() {
      return problems.isEmpty();
    }
  }
}
