/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import com.google.gson.JsonParser;
import dev.mistial.tools.openfips201.attestation.AttestationVerifier;
import dev.mistial.tools.openfips201.attestation.F9SubjectNames;
import dev.mistial.tools.openfips201.attestation.StrictDer;
import dev.mistial.tools.openfips201.attestation.VerificationReport;
import dev.mistial.tools.openfips201.attestation.VerificationRequest;
import dev.mistial.tools.openfips201.common.BerTlvReader;
import dev.mistial.tools.openfips201.common.ByteArrays;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.SecureFiles;
import dev.mistial.tools.openfips201.crypto.KeyIdentifiers;
import dev.mistial.tools.openfips201.gp.DerivedScpKeys;
import dev.mistial.tools.openfips201.opid.Opid;
import dev.mistial.tools.openfips201.opid.OpidIdentifiers;
import dev.mistial.tools.openfips201.producer.BatchMetadata;
import dev.mistial.tools.openfips201.producer.BatchRules;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.Time;

/**
 * Runs the per-card issuance sequence for one card against one SAM.
 *
 * <p>Production is SAM-driven: the host relays, persists and verifies what the SAM returns, and
 * never computes an OPID.
 *
 * <ol>
 *   <li>PREFLIGHT: the batch is bound to a SAM; the CAP carries attestation; the SAM's signed
 *       STATUS is OPERATIONAL, names the batch SAM, has quota left and agrees with the ledger. A
 *       card that already carries a PIV instance is refused unless a burned receipt of this batch
 *       names it (CPLC and KDD) and {@code --reissue} is given. The receipt is created with {@code
 *       CREATE_NEW}.
 *   <li>APPLET_INSTALLED: CPLC and KDD are read. For a reissue the SAM first VOIDs the burned OPID
 *       (the ledger {@code void} line carries its signed entry), the old instance is deleted with
 *       the keys its receipt records as current, and stock keys are restored if they were rotated.
 *       The applet is installed over the stock channel.
 *   <li>F9_GENERATED, SAM_NONCE, F9_PROVED: the card generates F9, the SAM issues a nonce, the card
 *       proves possession and the host pre-verifies the proof.
 *   <li>ISSUE_REQUESTED, ISSUED: the SAM allocates the OPID and certifies F9. The raw response is
 *       persisted in the receipt and the ledger {@code issue} line appended before it is parsed.
 *   <li>F9_VERIFIED: entry signature and chain position, the OPID syntax (17 digits, Luhn, the
 *       batch IIN), SPKI, certificate OPID == entry OPID, SKI and TBS hash, PKIX root to SAM to F9,
 *       and DECIPHER(OPID) on the SAM == (this batch, issuance seq, issued). A failure is recorded
 *       as stage {@code VERIFY_FAILED}; the OPID is burned and nothing is loaded.
 *   <li>F9_LOADED: the card loads the certificate, which must read back byte-identical.
 *   <li>PROOF_VERIFIED: a temporary proof key is attested and the leaf validated to the root.
 *   <li>APPLET_READBACK: GET VERSION; GET STATUS reports authority ACTIVE, the OPID and F9 SKI.
 *   <li>KEYS_ROTATED: CPLC and KDD are re-read (a different card fails) and the card's keys are
 *       rotated to keys derived from its KDD.
 *   <li>COMPLETED: identifiers recorded, the ledger {@code outcome} and the CSV row written.
 * </ol>
 *
 * <p>Receipt binding (ledger format v2): from the {@code issue} line on, and for every rewrite on
 * the failure path or of a superseded receipt, each receipt rewrite is immediately followed by a
 * ledger line carrying the SHA-256 of the octets written ({@code receiptSha256} on the {@code
 * issue} and {@code outcome} lines, otherwise a {@code receipt} line).
 *
 * <p>Exit codes: {@value #EXIT_OK} completed; {@value #EXIT_FAILED} failed before any OPID was
 * committed; {@value #EXIT_BURNED} failed after the SAM committed the OPID, which is never reused.
 */
public final class CardIssuanceOrchestrator {
  public static final int EXIT_OK = 0;
  public static final int EXIT_FAILED = 1;
  public static final int EXIT_BURNED = 3;

  static final byte[] PREFIX_POP = "OPF9POP".getBytes(StandardCharsets.US_ASCII);
  private static final long DAY_MILLIS = 24L * 60L * 60L * 1000L;
  private static final byte AUTHORITY_ACTIVE = 0x03;
  private static final Pattern LONG_HEX_RUN = Pattern.compile("[0-9A-Fa-f]{32,}");

  /** Fault-injection points: invoked at the start of each stage. */
  interface StageHooks {
    void before(IssuanceStage stage) throws Exception;
  }

  private static final StageHooks NO_HOOKS =
      new StageHooks() {
        @Override
        public void before(IssuanceStage stage) {}
      };

  /** The fixed inputs of one issuance. */
  public static final class Inputs {
    public BatchMetadata batch;
    public X509Certificate root;
    public byte[] samCertificate;
    public CapInfo cap;
    public boolean capLoaded;
    public ScpKeyDeriver keyDeriver;
    public String target;
    public String samTarget;
    public String custody;
    public byte proofSlot = (byte) 0x9A;

    /** Replace a burned card's instance and OPID ({@code --reissue}). */
    public boolean reissue;
  }

  /** Outcome of {@link #produce}. */
  public static final class Result {
    public final int exitCode;
    public final Path receipt;
    public final IssuanceReceipt record;

    Result(int exitCode, Path receipt, IssuanceReceipt record) {
      this.exitCode = exitCode;
      this.receipt = receipt;
      this.record = record;
    }
  }

  private final Inputs inputs;
  private final SamClient sam;
  private final PivIssuanceClient card;
  private final IssuanceLedger ledger;
  private final StageHooks hooks;
  private final SecureRandom random = new SecureRandom();

  public CardIssuanceOrchestrator(Inputs inputs, SamClient sam, PivIssuanceClient card)
      throws java.io.IOException {
    this(inputs, sam, card, NO_HOOKS);
  }

  CardIssuanceOrchestrator(Inputs inputs, SamClient sam, PivIssuanceClient card, StageHooks hooks)
      throws java.io.IOException {
    this.inputs = inputs;
    this.sam = sam;
    this.card = card;
    this.hooks = hooks;
    this.ledger = new IssuanceLedger(inputs.batch.directory().resolve(inputs.batch.ledger));
  }

  /** State that later stages and the failure path need. */
  private static final class Run {
    IssuanceStage stage = IssuanceStage.PREFLIGHT;
    Path receiptPath;
    SamStatus status;
    long lastEventSeq;
    byte[] lastHead;
    Burned reissue;
    boolean issueRequested;
    boolean issueLogged;
    boolean verifyFailed;
    IssueResponse issued;
  }

  /** A burned earlier attempt on the card in the reader. */
  private static final class Burned {
    Path receiptPath;
    IssuanceReceipt receipt;

    /** The issuance the SAM committed for it, or 0 when none is recorded. */
    long seq;

    String opid;
    boolean voided;
  }

  /** Runs the sequence; never throws once the receipt exists. */
  public Result produce() throws Exception {
    IssuanceReceipt receipt = new IssuanceReceipt();
    Run run = new Run();
    PublicKey samKey = StrictDer.parseCertificate(inputs.samCertificate).getPublicKey();
    try (BatchLock ignored = BatchLock.acquire(inputs.batch.directory())) {
      preflight(receipt, run, samKey);
      try {
        issue(receipt, run, samKey);
        return new Result(EXIT_OK, run.receiptPath, receipt);
      } catch (Exception failure) {
        return fail(receipt, run, samKey, failure);
      }
    }
  }

  private void preflight(IssuanceReceipt receipt, Run run, PublicKey samKey) throws Exception {
    hooks.before(IssuanceStage.PREFLIGHT);
    BatchMetadata batch = inputs.batch;
    if (!BatchMetadata.STATE_SAM_BOUND.equals(batch.state)) {
      throw new IllegalStateException(
          "Batch " + batch.name + " is " + batch.state + ", not bound to a SAM");
    }
    byte[] nonce = new byte[32];
    random.nextBytes(nonce);
    SamStatus status = SamStatus.parseSigned(sam.signedStatus(nonce), nonce, samKey);
    if (!status.isOperational()) {
      throw new IllegalStateException(
          "SAM is " + SamStatus.lifecycleName(status.lifecycle) + ", not OPERATIONAL");
    }
    if (!HexUtil.format(status.samSki()).equals(batch.sam.ski)) {
      throw new IllegalStateException("The SAM is not the SAM bound to batch " + batch.name);
    }
    if (status.remaining() <= 0) {
      throw new IllegalStateException(
          "SAM quota exhausted ("
              + status.issued
              + " of "
              + status.quota
              + " issued); run 'sam top-up'");
    }
    SamLedgerEntry.Signed last = ledger.lastSamEntry();
    if (last == null
        || ledger.lastIssueSeq() != status.issued
        || last.entry.eventSeq != status.eventSeq
        || !Arrays.equals(last.entry.head(), status.chainHead())) {
      throw new IllegalStateException(
          "The batch ledger does not match the SAM (SAM issued "
              + status.issued
              + ", eventSeq "
              + status.eventSeq
              + "); run 'ledger reconcile'");
    }
    run.status = status;
    run.lastEventSeq = status.eventSeq;
    run.lastHead = status.chainHead();
    if (card.pivInstancePresent()) {
      PivIssuanceClient.CardIdentity identity = card.readIdentity();
      Burned burned = findBurned(identity);
      if (burned == null) {
        throw new IllegalStateException(
            "The card already carries a PIV instance and no burned receipt of batch "
                + batch.name
                + " names it; refusing to overwrite it");
      }
      if (!inputs.reissue) {
        throw new IllegalStateException(
            "The card is the burned card of receipt "
                + burned.receiptPath.getFileName()
                + "; rerun with --reissue to void its OPID and produce it again");
      }
      run.reissue = burned;
    }

    receipt.producer = batch.producer;
    receipt.batch = batch.name;
    receipt.target = inputs.target;
    receipt.samTarget = inputs.samTarget;
    receipt.custody = inputs.custody;
    receipt.created = java.time.Instant.now().toString();
    receipt.cap.path = inputs.cap.path.toString();
    receipt.cap.sha256 = inputs.cap.sha256;
    receipt.cap.loadFileHash = inputs.cap.loadFileHash;
    receipt.cap.loaded = inputs.capLoaded;
    receipt.cap.properties.putAll(inputs.cap.properties);
    receipt.sam.ski = batch.sam.ski;
    if (run.reissue != null) {
      receipt.reissueOf = run.reissue.receiptPath.getFileName().toString();
    }
    receipt.enter(IssuanceStage.PREFLIGHT);
    Path directory = batch.directory().resolve("receipts");
    run.receiptPath =
        directory.resolve(
            batch.name + "-" + (status.issued + 1) + "-" + System.currentTimeMillis() + ".json");
    receipt.writeNew(run.receiptPath);
  }

  private void issue(IssuanceReceipt receipt, Run run, PublicKey samKey) throws Exception {
    advance(receipt, run, IssuanceStage.APPLET_INSTALLED);
    PivIssuanceClient.CardIdentity initial = card.readIdentity();
    receipt.card.cplc = initial.cplc;
    receipt.card.cplcFields = initial.cplcFields;
    receipt.card.kddInitial = HexUtil.format(initial.kdd());
    if (run.reissue != null) {
      reissue(run, initial);
    }
    card.installApplet();

    advance(receipt, run, IssuanceStage.F9_GENERATED);
    byte[] point = card.generateF9();
    PublicKey f9Key = IssuanceCrypto.publicKey(point);
    receipt.f9.point = HexUtil.format(point);

    advance(receipt, run, IssuanceStage.SAM_NONCE);
    byte[] nonce = sam.beginIssuance();
    receipt.sam.nonce = HexUtil.format(nonce);

    advance(receipt, run, IssuanceStage.F9_PROVED);
    byte[] pop = card.proveF9(nonce);
    if (!IssuanceCrypto.verify(f9Key, ByteArrays.concat(PREFIX_POP, nonce, point), pop)) {
      throw new IllegalStateException("The card's F9 proof of possession does not verify");
    }

    advance(receipt, run, IssuanceStage.ISSUE_REQUESTED);
    byte[] validity = validity(StrictDer.parseCertificate(inputs.samCertificate), new Date());
    run.issueRequested = true;
    byte[] raw = sam.issue(point, pop, validity);

    hooks.before(IssuanceStage.ISSUED);
    receipt.burned = true;
    receipt.sam.issueResponse = HexUtil.format(raw);
    receipt.enter(IssuanceStage.ISSUED);
    String receiptSha256 = receipt.replace(run.receiptPath);
    run.stage = IssuanceStage.ISSUED;
    IssueResponse response = IssueResponse.parse(raw);
    byte[] certificate = response.certificate();
    String certificateSha256 = HexUtil.format(IssuanceCrypto.sha256(certificate));
    ledger.appendIssue(
        response.signedEntry,
        certificateSha256,
        run.receiptPath.getFileName().toString(),
        receiptSha256,
        false);
    run.issueLogged = true;
    run.issued = response;
    SamLedgerEntry entry = response.signedEntry.entry;
    receipt.sam.issuanceSeq = entry.issuanceSeq;
    receipt.sam.eventSeq = entry.eventSeq;
    receipt.sam.opid = entry.opid;
    receipt.sam.entry = HexUtil.format(entry.encoded());
    receipt.sam.signature = HexUtil.format(response.signedEntry.signature());
    receipt.f9.certificateBase64 = Base64.getEncoder().encodeToString(certificate);
    receipt.f9.certificateSha256 = certificateSha256;

    advance(receipt, run, IssuanceStage.F9_VERIFIED);
    Opid opid;
    try {
      opid = verifyIssued(receipt, run, samKey, response, point);
    } catch (Exception mismatch) {
      run.verifyFailed = true;
      throw mismatch;
    }

    advance(receipt, run, IssuanceStage.F9_LOADED);
    card.loadF9Certificate(certificate);
    byte[] readBack = card.readF9Certificate();
    if (!Arrays.equals(readBack, certificate)) {
      throw new IllegalStateException("The card serves a different F9 certificate than it loaded");
    }
    receipt.f9.readBackIdentical = true;

    advance(receipt, run, IssuanceStage.PROOF_VERIFIED);
    PivIssuanceClient.ProofResult proof = card.attestProofKey();
    receipt.proof.slot = String.format("%02X", inputs.proofSlot & 0xFF);
    receipt.proof.point = HexUtil.format(proof.point());
    receipt.proof.leafBase64 = Base64.getEncoder().encodeToString(proof.leaf());
    receipt.proof.keyDeleted = proof.deleted;
    VerificationReport leafReport =
        require(
            "proof",
            receipt,
            VerificationRequest.builder()
                .anchor(inputs.root)
                .samCertificate(inputs.samCertificate)
                .f9Certificate(certificate)
                .leaf(proof.leaf())
                .expectOpid(opid)
                .build());
    if (!Arrays.equals(
        IssuanceCrypto.point(StrictDer.parseCertificate(proof.leaf()).getPublicKey()),
        proof.point())) {
      throw new IllegalStateException("The attestation leaf does not certify the proof key");
    }
    if (!proof.deleted) {
      throw new IllegalStateException("The proof key was not deleted");
    }
    if (leafReport == null) {
      throw new IllegalStateException("proof verification produced no report");
    }

    advance(receipt, run, IssuanceStage.APPLET_READBACK);
    receipt.card.version = HexUtil.format(card.getVersion());
    byte[] status = card.getStatus();
    receipt.card.status = HexUtil.format(status);
    requireActiveStatus(status, opid, KeyIdentifiers.ski(f9KeyOf(certificate)));

    advance(receipt, run, IssuanceStage.KEYS_ROTATED);
    PivIssuanceClient.CardIdentity fin = card.readIdentity();
    receipt.card.kddFinal = HexUtil.format(fin.kdd());
    if (!Arrays.equals(fin.kdd(), initial.kdd())
        || (initial.cplc != null && !initial.cplc.equals(fin.cplc))) {
      throw new IllegalStateException(
          "The card's KDD or CPLC changed during issuance; a different card is present");
    }
    DerivedScpKeys keys = inputs.keyDeriver.derive(fin.kdd());
    card.rotateKeys(keys);
    receipt.keys = new IssuanceReceipt.Keys();
    receipt.keys.keyVersion = keys.config.keyVersion;
    receipt.keys.encKcv = keys.encKcv;
    receipt.keys.macKcv = keys.macKcv;
    receipt.keys.dekKcv = keys.dekKcv;

    advance(receipt, run, IssuanceStage.COMPLETED);
    IssuanceReceipt.Identifiers identifiers = new IssuanceReceipt.Identifiers();
    identifiers.opid = opid.toPrinted();
    identifiers.guid = OpidIdentifiers.guidString(opid);
    identifiers.guidBytes = HexUtil.format(OpidIdentifiers.guidBytes(opid));
    identifiers.uuidOid = OpidIdentifiers.uuidOid(opid);
    identifiers.fascN = HexUtil.format(OpidIdentifiers.fascNBytes(opid));
    identifiers.ccc = HexUtil.format(OpidIdentifiers.cccCardIdentifier(opid));
    receipt.identifiers = identifiers;
    receipt.status = IssuanceReceipt.STATUS_COMPLETED;
    String completedSha256 = receipt.replace(run.receiptPath);
    ledger.appendOutcome(
        entry.issuanceSeq,
        entry.opid,
        IssuanceReceipt.STATUS_COMPLETED,
        IssuanceStage.COMPLETED.name(),
        run.receiptPath.getFileName().toString(),
        completedSha256,
        receipt.reissueOf,
        null);
    appendCsv(receipt, run);
  }

  /**
   * The most recent burned receipt of this batch for the card (KDD, and CPLC when recorded) whose
   * replacement, if any, did not complete. Its issuance is taken from the receipt or from the
   * ledger {@code issue} line that names it.
   */
  private Burned findBurned(PivIssuanceClient.CardIdentity identity) throws IOException {
    Path directory = inputs.batch.directory().resolve("receipts");
    if (!Files.isDirectory(directory)) {
      return null;
    }
    String kdd = HexUtil.format(identity.kdd());
    Burned best = null;
    try (DirectoryStream<Path> entries = Files.newDirectoryStream(directory, "*.json")) {
      for (Path path : entries) {
        IssuanceReceipt candidate;
        try {
          candidate = IssuanceReceipt.read(path);
        } catch (RuntimeException unreadable) {
          continue;
        }
        if (candidate == null
            || !candidate.burned
            || !kdd.equals(candidate.card.kddInitial)
            || (candidate.card.cplc != null && !candidate.card.cplc.equals(identity.cplc))) {
          continue;
        }
        if (candidate.supersededBy != null
            && completed(directory.resolve(candidate.supersededBy))) {
          continue;
        }
        if (best == null || candidate.created.compareTo(best.receipt.created) > 0) {
          best = new Burned();
          best.receiptPath = path;
          best.receipt = candidate;
        }
      }
    }
    if (best == null) {
      return null;
    }
    String name = best.receiptPath.getFileName().toString();
    IssuanceLedger.Line issue =
        best.receipt.sam.issuanceSeq > 0
            ? ledger.issueLine(best.receipt.sam.issuanceSeq)
            : ledger.issueLineOf(name);
    if (issue != null) {
      best.seq = issue.number("seq");
      best.opid = issue.string("opid");
      for (IssuanceLedger.Line line : ledger.read()) {
        if (IssuanceLedger.VOID.equals(line.type()) && line.number("seq") == best.seq) {
          best.voided = true;
        }
      }
    }
    return best;
  }

  private static boolean completed(Path receipt) {
    try {
      return Files.exists(receipt)
          && IssuanceReceipt.STATUS_COMPLETED.equals(IssuanceReceipt.read(receipt).status);
    } catch (IOException | RuntimeException e) {
      return false;
    }
  }

  /**
   * VOIDs the burned OPID on the SAM (unless already voided), records the {@code void} line and the
   * old attempt's {@code VOIDED} outcome linked to this receipt, then deletes the old instance with
   * the keys its receipt records as current and restores the stock keys if they were rotated.
   */
  private void reissue(Run run, PivIssuanceClient.CardIdentity identity) throws Exception {
    Burned burned = run.reissue;
    String self = run.receiptPath.getFileName().toString();
    String old = burned.receiptPath.getFileName().toString();
    if (burned.seq > 0 && !burned.voided) {
      SamLedgerEntry.Signed voided =
          SamLedgerEntry.Signed.parse(sam.voidIssuance(burned.seq, SamClient.VOID_REISSUE));
      PublicKey samKey = StrictDer.parseCertificate(inputs.samCertificate).getPublicKey();
      SamLedgerEntry entry = voided.entry;
      if (!voided.verify(samKey)
          || entry.type != SamLedgerEntry.TYPE_VOID
          || entry.issuanceSeq != burned.seq
          || !entry.opid.equals(burned.opid)
          || entry.eventSeq != run.lastEventSeq + 1
          || !Arrays.equals(entry.prevHead(), run.lastHead)) {
        throw new IllegalStateException(
            "The SAM's VOID entry does not verify or extend the ledger");
      }
      ledger.appendVoid(voided, old);
      ledger.appendOutcome(
          burned.seq, burned.opid, IssuanceReceipt.STATUS_VOIDED, null, old, null, null, self);
      run.lastEventSeq = entry.eventSeq;
      run.lastHead = entry.head();
    }
    burned.receipt.supersededBy = self;
    ledger.appendReceipt(old, burned.receipt.replace(burned.receiptPath), "supersededBy " + self);
    if (burned.receipt.keys != null) {
      DerivedScpKeys keys = inputs.keyDeriver.derive(identity.kdd());
      if (keys.config.keyVersion != burned.receipt.keys.keyVersion
          || !keys.encKcv.equals(burned.receipt.keys.encKcv)
          || !keys.macKcv.equals(burned.receipt.keys.macKcv)
          || !keys.dekKcv.equals(burned.receipt.keys.dekKcv)) {
        throw new IllegalStateException(
            "The card's recorded keys differ from the keys this station derives for it");
      }
      card.deleteInstance(keys.config);
      card.restoreStockKeys(keys.config, inputs.batch.stockScp.keyVersion);
    } else {
      card.deleteInstance(null);
    }
  }

  private Opid verifyIssued(
      IssuanceReceipt receipt, Run run, PublicKey samKey, IssueResponse response, byte[] point)
      throws Exception {
    SamLedgerEntry entry = response.signedEntry.entry;
    if (!response.signedEntry.verify(samKey)) {
      throw new IllegalStateException("The ISSUE entry signature does not verify");
    }
    if (entry.type != SamLedgerEntry.TYPE_ISSUE
        || entry.eventSeq != run.lastEventSeq + 1
        || !Arrays.equals(entry.prevHead(), run.lastHead)
        || entry.issuanceSeq != run.status.issued + 1) {
      throw new IllegalStateException("The ISSUE entry does not extend the SAM chain");
    }
    Opid opid = Opid.parseCanonical(entry.opid);
    if (opid.iin != inputs.batch.opid.iin) {
      throw new IllegalStateException(
          "The SAM issued OPID " + entry.opid + " outside IIN " + inputs.batch.opid.iin);
    }
    byte[] certificate = response.certificate();
    Certificate parsed = Certificate.getInstance(certificate);
    if (!Arrays.equals(IssuanceCrypto.point(f9KeyOf(certificate)), point)) {
      throw new IllegalStateException("The F9 certificate does not certify the card's F9 key");
    }
    Opid subjectOpid = F9SubjectNames.extractOpid(parsed.getSubject());
    if (!subjectOpid.equals(opid)) {
      throw new IllegalStateException("The F9 certificate subject carries a different OPID");
    }
    Extension skiExtension =
        parsed.getTBSCertificate().getExtensions().getExtension(Extension.subjectKeyIdentifier);
    if (skiExtension == null
        || !Arrays.equals(
            SubjectKeyIdentifier.getInstance(skiExtension.getParsedValue()).getKeyIdentifier(),
            entry.f9Ski())) {
      throw new IllegalStateException("The F9 certificate SKI differs from the SAM entry");
    }
    if (!Arrays.equals(
        IssuanceCrypto.sha256(parsed.getTBSCertificate().getEncoded(ASN1Encoding.DER)),
        entry.tbsHash())) {
      throw new IllegalStateException("The F9 certificate TBS differs from the SAM entry");
    }
    require(
        "f9",
        receipt,
        VerificationRequest.builder()
            .anchor(inputs.root)
            .samCertificate(inputs.samCertificate)
            .f9Certificate(certificate)
            .expectOpid(opid)
            .build());
    sam.decipher(opid.toPrinted()).requireIssuance(inputs.batch.opid.batch, entry.issuanceSeq);
    receipt.f9.ski = HexUtil.format(entry.f9Ski());
    receipt.f9.subject = parsed.getSubject().toString();
    return opid;
  }

  private static VerificationReport require(
      String name, IssuanceReceipt receipt, VerificationRequest request) {
    VerificationReport report = AttestationVerifier.verify(request);
    receipt.verification.put(name, JsonParser.parseString(report.toJson()));
    if (!report.valid()) {
      throw new IllegalStateException(
          "Attestation verification (" + name + ") failed:\n" + report.toTable());
    }
    return report;
  }

  private static PublicKey f9KeyOf(byte[] certificate) {
    return StrictDer.parseCertificate(certificate).getPublicKey();
  }

  /**
   * GET STATUS {@code 53 { ... 89 state, 8A OPID, 8B F9 SKI }}: the authority must be ACTIVE with
   * this OPID and key identifier.
   */
  static void requireActiveStatus(byte[] status, Opid opid, byte[] f9Ski) {
    BerTlvReader.Tlv outer = BerTlvReader.read(status, 0);
    byte[] state = null;
    byte[] printed = null;
    byte[] ski = null;
    int offset = outer.tag == 0x53 ? outer.valueOffset : 0;
    int end = outer.tag == 0x53 ? outer.nextOffset : status.length;
    while (offset < end) {
      BerTlvReader.Tlv tlv = BerTlvReader.read(status, offset, end);
      byte[] value = Arrays.copyOfRange(status, tlv.valueOffset, tlv.nextOffset);
      if (tlv.tag == 0x89) {
        state = value;
      } else if (tlv.tag == 0x8A) {
        printed = value;
      } else if (tlv.tag == 0x8B) {
        ski = value;
      }
      offset = tlv.nextOffset;
    }
    if (state == null || state.length != 1 || state[0] != AUTHORITY_ACTIVE) {
      throw new IllegalStateException(
          "GET STATUS does not report the attestation authority ACTIVE");
    }
    if (printed == null
        || !opid.toPrinted().equals(new String(printed, StandardCharsets.US_ASCII))) {
      throw new IllegalStateException("GET STATUS reports a different OPID");
    }
    if (ski == null || !Arrays.equals(ski, f9Ski)) {
      throw new IllegalStateException("GET STATUS reports a different F9 key identifier");
    }
  }

  /**
   * F9 validity: from now (but not before the SAM's notBefore) to min(now + f9 validity days, the
   * SAM's notAfter), in seconds.
   */
  private byte[] validity(X509Certificate samCertificate, Date now) throws Exception {
    long start = Math.max(now.getTime(), samCertificate.getNotBefore().getTime()) / 1000L * 1000L;
    long end = start + inputs.batch.f9.validityDays * DAY_MILLIS;
    end = Math.min(end, samCertificate.getNotAfter().getTime());
    if (end <= start) {
      throw new IllegalStateException("The SAM certificate has expired");
    }
    return new DERSequence(
            new org.bouncycastle.asn1.ASN1Encodable[] {
              new Time(new Date(start)), new Time(new Date(end))
            })
        .getEncoded(ASN1Encoding.DER);
  }

  /**
   * Records {@code stage} in the receipt. Once the ledger names the receipt (its {@code issue} line
   * is written), each rewrite is bound by a {@code receipt} line before the stage runs.
   */
  private void advance(IssuanceReceipt receipt, Run run, IssuanceStage stage) throws Exception {
    run.stage = stage;
    receipt.enter(stage);
    String sha256 = receipt.replace(run.receiptPath);
    if (run.issueLogged) {
      bind(run, sha256, "stage " + stage.name());
    }
    hooks.before(stage);
  }

  /** Appends the {@code receipt} line binding this attempt's receipt as just rewritten. */
  private void bind(Run run, String sha256, String reason) throws IOException {
    ledger.appendReceipt(run.receiptPath.getFileName().toString(), sha256, reason);
  }

  private Result fail(IssuanceReceipt receipt, Run run, PublicKey samKey, Exception failure)
      throws Exception {
    IssuanceReceipt.Failure record = new IssuanceReceipt.Failure();
    String stage = run.verifyFailed ? IssuanceReceipt.STAGE_VERIFY_FAILED : run.stage.name();
    record.stage = stage;
    record.errorClass = failure.getClass().getName();
    record.redactedMessage = redact(failure);
    receipt.failure = record;
    receipt.status = IssuanceReceipt.STATUS_FAILED;
    int exit;
    if (run.issueLogged) {
      exit = EXIT_BURNED;
      SamLedgerEntry entry = run.issued.signedEntry.entry;
      String sha256 = receipt.replace(run.receiptPath);
      ledger.appendOutcome(
          entry.issuanceSeq,
          entry.opid,
          IssuanceReceipt.STATUS_FAILED,
          stage,
          run.receiptPath.getFileName().toString(),
          sha256,
          receipt.reissueOf,
          null);
    } else if (run.issueRequested && notCommitted(failure)) {
      exit = EXIT_FAILED;
      bind(run, receipt.replace(run.receiptPath), "failed " + stage);
    } else if (run.issueRequested) {
      // The SAM may have committed. 6500 is a definite burn whose entry GET LAST ENTRY recovers;
      // any other loss leaves the ledger to 'ledger reconcile'.
      exit = EXIT_BURNED;
      receipt.burned = true;
      if (failure instanceof SamApduException
          && ((SamApduException) failure).sw == SamApduException.SW_FAILURE_AFTER_COMMIT) {
        try {
          LedgerReconciler.recover(
              sam,
              ledger,
              samKey,
              run.receiptPath.getFileName().toString(),
              "SAM reported failure after commit (6500)");
        } catch (Exception recovery) {
          record.redactedMessage += "; run 'ledger reconcile': " + redact(recovery);
        }
      } else {
        record.redactedMessage += "; the OPID may be burned: run 'ledger reconcile'";
      }
      bind(run, receipt.replace(run.receiptPath), "failed " + stage);
    } else {
      exit = EXIT_FAILED;
      bind(run, receipt.replace(run.receiptPath), "failed " + stage);
    }
    appendCsv(receipt, run);
    return new Result(exit, run.receiptPath, receipt);
  }

  /** A SAM status word returned before the issuance commit (anything but 6500). */
  private static boolean notCommitted(Exception failure) {
    return failure instanceof SamApduException
        && ((SamApduException) failure).sw != SamApduException.SW_FAILURE_AFTER_COMMIT;
  }

  static String redact(Throwable failure) {
    StringBuilder message = new StringBuilder();
    for (Throwable current = failure; current != null; current = current.getCause()) {
      String part = current.getMessage();
      if (part == null || part.isEmpty()) {
        part = current.getClass().getSimpleName();
      }
      if (message.length() > 0) {
        message.append(": ");
      }
      message.append(part);
    }
    return LONG_HEX_RUN.matcher(message.toString()).replaceAll("<redacted>");
  }

  private void appendCsv(IssuanceReceipt receipt, Run run) throws Exception {
    Path csv = inputs.batch.directory().resolve(inputs.batch.receiptsCsv);
    BatchRules.ensureCsvHeader(csv);
    String[] fields = {
      receipt.updated,
      receipt.producer,
      receipt.batch,
      receipt.target,
      receipt.status,
      receipt.stage,
      receipt.sam.opid,
      receipt.sam.issuanceSeq == 0 ? "" : Long.toString(receipt.sam.issuanceSeq),
      receipt.card.cplc,
      receipt.card.kddInitial,
      receipt.card.kddFinal,
      receipt.keys == null ? "" : Integer.toString(receipt.keys.keyVersion),
      receipt.keys == null ? "" : receipt.keys.encKcv,
      receipt.keys == null ? "" : receipt.keys.macKcv,
      receipt.keys == null ? "" : receipt.keys.dekKcv,
      receipt.f9.ski,
      receipt.f9.certificateSha256,
      receipt.identifiers == null ? "" : receipt.identifiers.guid,
      receipt.identifiers == null ? "" : receipt.identifiers.fascN,
      run.receiptPath.getFileName().toString()
    };
    StringBuilder line = new StringBuilder();
    for (int i = 0; i < fields.length; i++) {
      if (i > 0) {
        line.append(',');
      }
      String value = fields[i] == null ? "" : fields[i];
      line.append('"').append(value.replace("\"", "\"\"")).append('"');
    }
    SecureFiles.appendLine(csv, line.append('\n').toString());
  }
}
