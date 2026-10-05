/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import dev.mistial.tools.openfips201.applet.AppletInstallRequest;
import dev.mistial.tools.openfips201.attestation.StrictDer;
import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.CardTransport;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.gp.CardDiversificationDataService;
import dev.mistial.tools.openfips201.gp.DerivedScpKeys;
import dev.mistial.tools.openfips201.opid.Opid;
import dev.mistial.tools.openfips201.producer.BatchMetadata;
import dev.mistial.tools.openfips201.producer.BatchRules;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * Wires station custody, the batch and the readers into the issuance services.
 *
 * <ul>
 *   <li>root station ({@link RootKeys}): {@link #personalize} (SAM only, never a card);
 *   <li>production station ({@link Custody}): {@link #receive}, {@link #produce}, {@link
 *       #decipher}, {@link #voidIssuance}, {@link #changePin}, {@link #closeBatch}, {@link
 *       #terminateSam} and the top-up file exchange. Every production entry point first requires
 *       the custody to be free of root and FF1 keys and the batch records free of LCG parameters.
 * </ul>
 */
public final class IssuanceService {
  public static final String PIV_PACKAGE_AID = "A00000030800001000";
  public static final String PIV_APPLET_AID = "A000000308000010000100";

  /** The eight-octet PIV wire-format PIN set for the proof-key attestation. */
  public static final String PROOF_PIN = "313233343536FFFF";

  /** Input to {@link #personalize}. */
  public static final class PersonalizeRequest {
    public String producer;
    public int iin;
    public int batch;
    public String station;
    public CardTarget sam;
    public byte[] samStockKey;
    public String samSubjectTemplate;
    public int samValidityDays = BatchRules.DEFAULT_SAM_VALIDITY_DAYS;
    public int f9ValidityDays = BatchRules.DEFAULT_F9_VALIDITY_DAYS;
    public boolean install;
    public Path samCap;
    public Path bundleOut;
    SamPersonalizationService.Hooks hooks;
  }

  /** Input to {@link #produce}. */
  public static final class ProduceRequest {
    public String producer;
    public String batch;
    public CardTarget target;
    public CardTarget sam;
    public byte[] stockScpKey;
    public byte[] operatorPin;
    public Path cap;
    public boolean allowDevCustody;
    public boolean reissue;
    CardIssuanceOrchestrator.StageHooks hooks;
    CardDecorator cardDecorator;
  }

  /** Test seam that wraps the card client. */
  interface CardDecorator {
    PivIssuanceClient decorate(PivIssuanceClient card);
  }

  /** {@code sam personalize} under the root station's PKCS#11 custody. */
  public SamPersonalizationService.Result personalize(PersonalizeRequest request) throws Exception {
    try (RootContext root = RootContext.load(request.producer)) {
      return personalize(request, root, root.profile.attestation.issuerSubject);
    }
  }

  /** {@code sam personalize} under {@code keys}, with the F9 subject template of the producer. */
  public SamPersonalizationService.Result personalize(
      PersonalizeRequest request, RootKeys keys, String f9SubjectTemplate) throws Exception {
    requireRootCustody(keys, request.sam);
    SamPersonalizationService.Request personalize = new SamPersonalizationService.Request();
    personalize.producer = request.producer;
    personalize.iin = request.iin;
    personalize.batch = request.batch;
    personalize.station = request.station;
    personalize.keys = keys;
    personalize.samStockScp =
        ScpConfig.fromMaster(ScpConfig.Mode.SCP03, ScpConfig.KEY_VERSION_AUTO, request.samStockKey);
    personalize.f9SubjectTemplate = f9SubjectTemplate;
    personalize.samSubjectTemplate =
        request.samSubjectTemplate != null
            ? request.samSubjectTemplate
            : "CN=" + request.producer + " Issuer SAM";
    personalize.samValidityDays = request.samValidityDays;
    personalize.f9ValidityDays = request.f9ValidityDays;
    personalize.install = request.install;
    personalize.samCap = request.samCap;
    personalize.bundleOut = request.bundleOut;
    try (CardTransport transport = request.sam.openTransport()) {
      personalize.sam = transport;
      SamPersonalizationService service =
          request.hooks == null
              ? new SamPersonalizationService()
              : new SamPersonalizationService(request.hooks);
      return service.personalize(personalize);
    }
  }

  /** {@code sam receive} under the production station's PKCS#11 custody. */
  public SamReceiveService.Result receive(
      String producer, CardTarget samTarget, Path bundle, byte[] operatorPin, Path stockKeyOut)
      throws Exception {
    try (ProductionContext context = ProductionContext.load(producer)) {
      return receive(producer, samTarget, bundle, operatorPin, stockKeyOut, context);
    }
  }

  public SamReceiveService.Result receive(
      String producer,
      CardTarget samTarget,
      Path bundle,
      byte[] operatorPin,
      Path stockKeyOut,
      Custody custody)
      throws Exception {
    requireCustody(custody, samTarget, false);
    SamReceiveService.Request request = new SamReceiveService.Request();
    request.producer = producer;
    request.custody = custody;
    request.bundle = bundle;
    request.operatorPin = operatorPin;
    request.stockKeyOut = stockKeyOut;
    try (CardTransport transport = samTarget.openTransport()) {
      request.sam = transport;
      return new SamReceiveService().receive(request);
    }
  }

  /**
   * Produces one card under the production station's PKCS#11 custody. The stock key's KCV is
   * checked against {@code batch.json} before any reader or token is opened.
   */
  public CardIssuanceOrchestrator.Result produce(ProduceRequest request) throws Exception {
    BatchMetadata batch = preflight(request);
    try (ProductionContext context = ProductionContext.load(request.producer)) {
      return produce(request, batch, context);
    }
  }

  /** Produces one card under {@code custody}. */
  public CardIssuanceOrchestrator.Result produce(ProduceRequest request, Custody custody)
      throws Exception {
    return produce(request, preflight(request), custody);
  }

  /** Host checks that need no reader: stock KCV, distinct readers, batch state. */
  private static BatchMetadata preflight(ProduceRequest request) throws Exception {
    BatchMetadata batch = BatchMetadata.read(request.producer, request.batch);
    BatchRules.requireStockKcv(batch, request.stockScpKey);
    if (request.target.displayName().equals(request.sam.displayName())) {
      throw new IllegalArgumentException("the card and SAM readers must differ");
    }
    if (!BatchMetadata.STATE_SAM_BOUND.equals(batch.state)) {
      throw new IllegalStateException(
          "Batch " + batch.name + " is " + batch.state + ", not bound to a SAM");
    }
    return batch;
  }

  private CardIssuanceOrchestrator.Result produce(
      ProduceRequest request, BatchMetadata batch, Custody custody) throws Exception {
    custody.requireProductionClean(request.producer);
    byte[] samCertificate = samCertificate(batch);
    CapInfo cap = CapInfo.read(request.cap);
    requireCustody(custody, request.target, request.allowDevCustody);
    CardIssuanceOrchestrator.Inputs inputs = new CardIssuanceOrchestrator.Inputs();
    inputs.batch = batch;
    inputs.root = custody.rootCertificate();
    inputs.samCertificate = samCertificate;
    inputs.cap = cap;
    inputs.capLoaded = !request.target.isZmq();
    inputs.keyDeriver = custody.keyDeriver();
    inputs.target = request.target.displayName();
    inputs.samTarget = request.sam.displayName();
    inputs.custody = custody.custody();
    inputs.reissue = request.reissue;
    try (CardTransport samTransport = request.sam.openTransport()) {
      try (GlobalPlatformSession samSession = openSam(samTransport, batch, custody)) {
        SamClient sam = ApduSamClient.secure(samSession);
        sam.verifyPin(request.operatorPin);
        // INITIALIZE UPDATE P1=00 lets the card select its stock key set.
        ScpConfig stock =
            ScpConfig.fromMaster(
                ScpConfig.Mode.SCP03, ScpConfig.KEY_VERSION_AUTO, request.stockScpKey);
        AppletInstallRequest install = new AppletInstallRequest();
        install.capPath = cap.path;
        install.packageAid = PIV_PACKAGE_AID;
        install.appletAid = PIV_APPLET_AID;
        install.instanceAid = PIV_APPLET_AID;
        install.loadCap = inputs.capLoaded;
        try (CardTransport cardTransport = request.target.openTransport()) {
          PivIssuanceClient card =
              new ApduPivIssuanceClient(
                  cardTransport, stock, install, inputs.proofSlot, HexUtil.parse(PROOF_PIN));
          if (request.cardDecorator != null) {
            card = request.cardDecorator.decorate(card);
          }
          CardIssuanceOrchestrator orchestrator =
              request.hooks == null
                  ? new CardIssuanceOrchestrator(inputs, sam, card)
                  : new CardIssuanceOrchestrator(inputs, sam, card, request.hooks);
          return orchestrator.produce();
        }
      }
    }
  }

  /** {@code sam decipher} under the production station's custody. */
  public DecipherResult decipher(
      String producer, String batchName, CardTarget samTarget, byte[] operatorPin, String opid)
      throws Exception {
    try (ProductionContext context = ProductionContext.load(producer)) {
      return decipher(producer, batchName, samTarget, operatorPin, opid, context);
    }
  }

  /** DECIPHER on the batch SAM; the production host has no way to check the result itself. */
  public DecipherResult decipher(
      String producer,
      String batchName,
      CardTarget samTarget,
      byte[] operatorPin,
      String opid,
      Custody custody)
      throws Exception {
    custody.requireProductionClean(producer);
    BatchMetadata batch = BatchMetadata.read(producer, batchName);
    requireReceived(batch);
    Opid parsed = Opid.parse(opid);
    try (CardTransport transport = samTarget.openTransport();
        GlobalPlatformSession session = openSam(transport, batch, custody)) {
      SamClient sam = ApduSamClient.secure(session);
      sam.verifyPin(operatorPin);
      return sam.decipher(parsed.toPrinted());
    }
  }

  /** {@code sam void} under the production station's custody. */
  public SamLedgerEntry voidIssuance(
      String producer,
      String batchName,
      CardTarget samTarget,
      byte[] operatorPin,
      long seq,
      int reason)
      throws Exception {
    try (ProductionContext context = ProductionContext.load(producer)) {
      return voidIssuance(producer, batchName, samTarget, operatorPin, seq, reason, context);
    }
  }

  /**
   * {@code sam void}: the SAM recomputes OPID {@code seq} and records a signed VOID entry, which
   * must verify, extend the ledger and name the ledger's OPID of {@code seq}; it is recorded as the
   * ledger {@code void} line.
   */
  public SamLedgerEntry voidIssuance(
      String producer,
      String batchName,
      CardTarget samTarget,
      byte[] operatorPin,
      long seq,
      int reason,
      Custody custody)
      throws Exception {
    if (reason < 0 || reason > 0xFF) {
      throw new IllegalArgumentException("--reason must be 0..255");
    }
    custody.requireProductionClean(producer);
    BatchMetadata batch = BatchMetadata.read(producer, batchName);
    requireReceived(batch);
    PublicKey samKey = StrictDer.parseCertificate(samCertificate(batch)).getPublicKey();
    IssuanceLedger ledger = new IssuanceLedger(batch.directory().resolve(batch.ledger));
    try (BatchLock ignored = BatchLock.acquire(batch.directory());
        CardTransport transport = samTarget.openTransport();
        GlobalPlatformSession session = openSam(transport, batch, custody)) {
      IssuanceLedger.Line issue = ledger.issueLine(seq);
      if (issue == null) {
        throw new IllegalArgumentException("issuance " + seq + " is not in the ledger");
      }
      SamClient sam = ApduSamClient.secure(session);
      sam.verifyPin(operatorPin);
      SamLedgerEntry.Signed last = ledger.lastSamEntry();
      SamLedgerEntry.Signed voided = SamLedgerEntry.Signed.parse(sam.voidIssuance(seq, reason));
      SamLedgerEntry entry = voided.entry;
      if (!voided.verify(samKey)
          || entry.type != SamLedgerEntry.TYPE_VOID
          || entry.issuanceSeq != seq
          || !entry.opid.equals(issue.string("opid"))
          || last == null
          || entry.eventSeq != last.entry.eventSeq + 1
          || !java.util.Arrays.equals(entry.prevHead(), last.entry.head())) {
        throw new IllegalStateException(
            "The SAM's VOID entry does not verify, extend the ledger or name the ledger's OPID");
      }
      ledger.appendVoid(voided, issue.string("receipt"));
      return entry;
    }
  }

  /** {@code sam change-pin} under the production station's custody. */
  public void changePin(
      String producer, String batchName, CardTarget samTarget, byte[] oldPin, byte[] newPin)
      throws Exception {
    try (ProductionContext context = ProductionContext.load(producer)) {
      changePin(producer, batchName, samTarget, oldPin, newPin, context);
    }
  }

  public void changePin(
      String producer,
      String batchName,
      CardTarget samTarget,
      byte[] oldPin,
      byte[] newPin,
      Custody custody)
      throws Exception {
    if (newPin.length < 6 || newPin.length > 16) {
      throw new IllegalArgumentException("the operator PIN must be 6 to 16 octets");
    }
    custody.requireProductionClean(producer);
    BatchMetadata batch = BatchMetadata.read(producer, batchName);
    requireReceived(batch);
    try (CardTransport transport = samTarget.openTransport();
        GlobalPlatformSession session = openSam(transport, batch, custody)) {
      ApduSamClient.secure(session).changeOperatorPin(oldPin, newPin);
    }
  }

  /** {@code batch close} under the production station's custody. */
  public SamLedgerEntry closeBatch(
      String producer, String batchName, CardTarget samTarget, byte[] operatorPin)
      throws Exception {
    try (ProductionContext context = ProductionContext.load(producer)) {
      return closeBatch(producer, batchName, samTarget, operatorPin, context);
    }
  }

  /** {@code batch close}: SAM CLOSE over the issuer secure channel with the operator PIN. */
  public SamLedgerEntry closeBatch(
      String producer, String batchName, CardTarget samTarget, byte[] operatorPin, Custody custody)
      throws Exception {
    custody.requireProductionClean(producer);
    BatchMetadata batch = BatchMetadata.read(producer, batchName);
    PublicKey samKey = StrictDer.parseCertificate(samCertificate(batch)).getPublicKey();
    try (CardTransport transport = samTarget.openTransport();
        GlobalPlatformSession session = openSam(transport, batch, custody)) {
      SamClient sam = ApduSamClient.secure(session);
      sam.verifyPin(operatorPin);
      return new BatchLifecycleService().close(batch, sam, samKey);
    }
  }

  /** {@code sam terminate} under the production station's custody. */
  public SamLedgerEntry terminateSam(
      String producer, String batchName, CardTarget samTarget, byte[] operatorPin)
      throws Exception {
    try (ProductionContext context = ProductionContext.load(producer)) {
      return terminateSam(producer, batchName, samTarget, operatorPin, context);
    }
  }

  /**
   * {@code sam terminate}: TERMINATE over the SAM's issuer secure channel with the operator PIN,
   * from a closed batch or an open one.
   */
  public SamLedgerEntry terminateSam(
      String producer, String batchName, CardTarget samTarget, byte[] operatorPin, Custody custody)
      throws Exception {
    custody.requireProductionClean(producer);
    BatchMetadata batch = BatchMetadata.read(producer, batchName);
    PublicKey samKey = StrictDer.parseCertificate(samCertificate(batch)).getPublicKey();
    try (CardTransport transport = samTarget.openTransport();
        GlobalPlatformSession session = openSam(transport, batch, custody)) {
      SamClient sam = ApduSamClient.secure(session);
      sam.verifyPin(operatorPin);
      return new BatchLifecycleService().terminate(batch, sam, samKey);
    }
  }

  /** {@code sam top-up --request-out}: a request carrying the SAM's signed STATUS. */
  public TopUpAuthorization topUpRequest(
      String producer, String batchName, CardTarget samTarget, long add, Custody custody)
      throws Exception {
    custody.requireProductionClean(producer);
    BatchMetadata batch = BatchMetadata.read(producer, batchName);
    PublicKey samKey = StrictDer.parseCertificate(samCertificate(batch)).getPublicKey();
    try (CardTransport transport = samTarget.openTransport()) {
      return new SamOperationsService()
          .request(batch, ApduSamClient.selectPlain(transport), samKey, add);
    }
  }

  /** {@code sam top-up --authorization-in}: applies a root-signed authorization. */
  public SamStatus topUpApply(
      String producer,
      String batchName,
      CardTarget samTarget,
      TopUpAuthorization authorization,
      Custody custody)
      throws Exception {
    custody.requireProductionClean(producer);
    BatchMetadata batch = BatchMetadata.read(producer, batchName);
    PublicKey samKey = StrictDer.parseCertificate(samCertificate(batch)).getPublicKey();
    try (CardTransport transport = samTarget.openTransport()) {
      return new SamOperationsService()
          .topUp(
              batch,
              ApduSamClient.selectPlain(transport),
              authorization,
              custody.rootCertificate().getPublicKey(),
              samKey);
    }
  }

  /**
   * The issuer secure channel to the batch SAM: the SAM's KDD must be the batch's, and the keys are
   * derived from it by the custody.
   */
  static GlobalPlatformSession openSam(
      CardTransport transport, BatchMetadata batch, Custody custody) throws Exception {
    byte[] kdd = new CardDiversificationDataService().readKdd(transport).kdd;
    if (!HexUtil.format(kdd).equals(batch.sam.kdd)) {
      throw new IllegalStateException("The SAM is not the SAM of batch " + batch.name);
    }
    DerivedScpKeys keys = custody.keyDeriver().derive(kdd);
    return transport.openGlobalPlatformSession(ApduSamClient.SAM_AID, keys.config);
  }

  private static void requireReceived(BatchMetadata batch) {
    if (batch.sam == null || batch.sam.kdd == null) {
      throw new IllegalStateException("Batch " + batch.name + " has no SAM");
    }
    if (BatchMetadata.STATE_TERMINATED.equals(batch.state)) {
      throw new IllegalStateException("The SAM of batch " + batch.name + " is terminated");
    }
  }

  /** The SAM certificate in {@code sam.pem}, which must match {@code batch.json}. */
  public static byte[] samCertificate(BatchMetadata batch) throws Exception {
    if (batch.sam == null || batch.sam.certificate == null) {
      throw new IllegalStateException("Batch " + batch.name + " has no SAM certificate");
    }
    X509Certificate certificate =
        StrictDer.readSinglePemCertificate(batch.directory().resolve(batch.sam.certificate));
    byte[] encoded = certificate.getEncoded();
    if (!HexUtil.format(IssuanceCrypto.sha256(encoded)).equals(batch.sam.certificateSha256)) {
      throw new IllegalStateException("sam.pem differs from the certificate batch.json records");
    }
    return encoded;
  }

  /** Development custody (SoftHSM) never issues to a physical card unless explicitly allowed. */
  static void requireCustody(Custody custody, CardTarget target, boolean allow) {
    if (custody.isDevelopment() && !target.isZmq() && !allow) {
      throw new IllegalArgumentException(
          "The producer uses development custody (softhsm-dev); refusing a pcsc: target without"
              + " --allow-dev-custody");
    }
  }

  /** Development root custody personalizes only emulated SAMs. */
  static void requireRootCustody(RootKeys keys, CardTarget target) {
    if (keys.isDevelopment() && !target.isZmq()) {
      throw new IllegalArgumentException(
          "The root uses development custody (softhsm-dev); refusing a pcsc: SAM");
    }
  }
}
