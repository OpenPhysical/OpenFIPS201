/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.SecureFiles;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Receipt of one card issuance, schema {@code openfips201.receipt/2}. It is created owner-only with
 * {@code CREATE_NEW} at {@link IssuanceStage#PREFLIGHT} and replaced atomically at every later
 * stage, so a crash leaves the last completed stage on disk. From its {@code issue} line on (and
 * for every rewrite on the failure path), each replacement is followed by a ledger line carrying
 * the SHA-256 of the new file, so {@code ledger verify} detects any later edit or deletion.
 */
public final class IssuanceReceipt {
  public static final String SCHEMA = "openfips201.receipt/2";
  public static final String STATUS_IN_PROGRESS = "IN_PROGRESS";
  public static final String STATUS_COMPLETED = "COMPLETED";
  public static final String STATUS_FAILED = "FAILED";

  /** Ledger outcome status of a burned OPID the SAM voided for a reissue. */
  public static final String STATUS_VOIDED = "VOIDED";

  /** Failure stage of an issuance whose SAM response did not verify; its OPID is burned. */
  public static final String STAGE_VERIFY_FAILED = "VERIFY_FAILED";

  private static final Gson GSON =
      new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

  public String schema = SCHEMA;
  public String producer;
  public String batch;
  public String target;
  public String samTarget;
  public String custody;
  public String created;
  public String updated;
  public String stage;
  public String status = STATUS_IN_PROGRESS;

  /** Whether the SAM committed an OPID to this card's issuance. */
  public boolean burned;

  public final List<StageRecord> stages = new ArrayList<StageRecord>();
  public Failure failure;
  public Cap cap = new Cap();
  public Card card = new Card();
  public Sam sam = new Sam();
  public F9 f9 = new F9();
  public Proof proof = new Proof();
  public final Map<String, JsonElement> verification = new LinkedHashMap<String, JsonElement>();
  public Identifiers identifiers;
  public Keys keys;

  /** The receipt of the burned attempt on the same card that this attempt replaces. */
  public String reissueOf;

  /** The receipt of the attempt that replaced this burned one after its OPID was voided. */
  public String supersededBy;

  public static final class StageRecord {
    public String stage;
    public String at;
  }

  public static final class Failure {
    public String stage;
    public String errorClass;
    public String redactedMessage;
  }

  public static final class Cap {
    public String path;
    public String sha256;
    public String loadFileHash;
    public boolean loaded;
    public Map<String, String> properties = new LinkedHashMap<String, String>();
  }

  public static final class Card {
    public String cplc;

    /** SHA-256 of the CPLC data octets, as the SAM binds it into the F9 issuance extension. */
    public String cplcSha256;

    public Map<String, String> cplcFields;
    public String kddInitial;
    public String kddFinal;
    public String version;
    public String status;
  }

  public static final class Sam {
    public String ski;
    public String nonce;
    public long issuanceSeq;
    public long eventSeq;
    public String opid;
    public String issueResponse;
    public String entry;
    public String signature;
  }

  public static final class F9 {
    public String point;
    public String ski;
    public String subject;
    public String certificateBase64;
    public String certificateSha256;
    public boolean readBackIdentical;
  }

  public static final class Proof {
    public String slot;
    public String point;
    public String leafBase64;
    public boolean keyDeleted;
  }

  public static final class Identifiers {
    public String opid;
    public String guid;
    public String guidBytes;
    public String uuidOid;
    public String fascN;
    public String ccc;
  }

  public static final class Keys {
    public String mode = "SCP03";
    public String kdf = "scp03-kdf3";
    public int keyVersion;
    public String encKcv;
    public String macKcv;
    public String dekKcv;
  }

  void enter(IssuanceStage next) {
    stage = next.name();
    StageRecord record = new StageRecord();
    record.stage = next.name();
    record.at = Instant.now().toString();
    stages.add(record);
    updated = record.at;
  }

  Path writeNew(Path file) throws IOException {
    return SecureFiles.writeNew(file, json());
  }

  /**
   * Atomically replaces {@code file} with this receipt.
   *
   * @return the hex SHA-256 of the octets written, which the caller binds in the ledger ({@link
   *     IssuanceLedger}, format v2) with the line that follows the rewrite
   */
  String replace(Path file) throws IOException {
    updated = Instant.now().toString();
    byte[] json = json();
    SecureFiles.replaceAtomically(file, json);
    return HexUtil.format(IssuanceCrypto.sha256(json));
  }

  private byte[] json() {
    return GSON.toJson(this).getBytes(StandardCharsets.UTF_8);
  }

  public static IssuanceReceipt read(Path file) throws IOException {
    return GSON.fromJson(
        new String(Files.readAllBytes(file), StandardCharsets.UTF_8), IssuanceReceipt.class);
  }
}
