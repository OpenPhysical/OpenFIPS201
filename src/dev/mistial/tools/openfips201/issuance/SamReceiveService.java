/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import com.google.gson.JsonObject;
import dev.mistial.tools.openfips201.attestation.OpenPhysicalExtensions;
import dev.mistial.tools.openfips201.attestation.StrictDer;
import dev.mistial.tools.openfips201.common.CardTransport;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.common.SecureFiles;
import dev.mistial.tools.openfips201.crypto.KeyIdentifiers;
import dev.mistial.tools.openfips201.gp.CardDiversificationDataService;
import dev.mistial.tools.openfips201.gp.CardKeyRotationService;
import dev.mistial.tools.openfips201.gp.DerivedScpKeys;
import dev.mistial.tools.openfips201.producer.BatchMetadata;
import dev.mistial.tools.openfips201.producer.BatchRules;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

/**
 * {@code sam receive} at the production station: takes over a SAM personalized by the root.
 *
 * <ol>
 *   <li>the bundle's root signature, its root certificate (== {@code root.pem}), the chain root to
 *       SAM, the batch extension against the bundle, and the registry allocate and bind lines
 *       (signatures, linkage, and SHA-256 of the bind line == the certificate's registryHead);
 *   <li>the bundle is wrapped to this station (station key identifier) and names this SAM (KDD);
 *   <li>the handoff secrets are unwrapped through the custody;
 *   <li>over the handoff channel: PARAMS paramsDigest == the bundle's; signed STATUS OPERATIONAL,
 *       issued 0, at the genesis entry, with the certificate's allocationSeq and registryHead;
 *   <li>the SAM's GlobalPlatform keys are rotated to keys derived from its KDD, after which the
 *       handoff keys no longer authenticate;
 *   <li>CHANGE OPERATOR PIN from the handoff PIN to the operator's PIN;
 *   <li>{@code batch.json} ({@code openfips201.batch/4}, no LCG), {@code sam.pem} and the ledger
 *       genesis line are written.
 * </ol>
 */
public final class SamReceiveService {
  /** Input to {@link #receive}. */
  public static final class Request {
    public String producer;
    public Custody custody;
    public CardTransport sam;
    public Path bundle;
    public byte[] operatorPin;
    public Path stockKeyOut;
  }

  /** Outcome of {@link #receive}. */
  public static final class Result {
    public final BatchMetadata batch;

    /** The stock SCP03 key in hex when it was not written to a file, else null. */
    public final String stockKey;

    Result(BatchMetadata batch, String stockKey) {
      this.batch = batch;
      this.stockKey = stockKey;
    }
  }

  public Result receive(Request request) throws Exception {
    if (request.operatorPin == null
        || request.operatorPin.length < 6
        || request.operatorPin.length > 16) {
      throw new IllegalArgumentException("the operator PIN must be 6 to 16 octets");
    }
    Custody custody = request.custody;
    custody.requireProductionClean(request.producer);
    X509Certificate root = custody.rootCertificate();
    SamHandoff bundle = SamHandoff.read(request.bundle, root);
    if (!request.producer.equals(bundle.producer())) {
      throw new IllegalArgumentException("the bundle is for producer " + bundle.producer());
    }
    byte[] samCertificate = bundle.samCertificate();
    X509Certificate samX509 = StrictDer.parseCertificate(samCertificate);
    SamCertificateFactory.requireValid(root, samCertificate, new Date());
    OpenPhysicalExtensions.SamBatch extension = samBatch(samCertificate);
    if (extension.issuerId != bundle.iin()
        || extension.batch != bundle.batch()
        || extension.initialQuota != bundle.quota()
        || IssuanceCrypto.unsigned(extension.initialTimestamp(), 0, 8) != bundle.initialTs()
        || !Arrays.equals(extension.paramsDigest(), bundle.paramsDigest())) {
      throw new IllegalStateException(
          "the SAM certificate's batch extension differs from the bundle");
    }
    JsonObject allocate = CanonicalJson.verify(bundle.allocateLine(), root.getPublicKey());
    AllocationRegistry.verifyBinding(
        bundle.allocateLine(), bundle.bindLine(), root.getPublicKey(), bundle.samId());
    if (allocate.get("seq").getAsLong() != extension.allocationSeq
        || allocate.get("quota").getAsLong() != bundle.quota()
        || !Arrays.equals(
            AllocationRegistry.headAfter(bundle.bindLine()), extension.registryHead())) {
      throw new IllegalStateException("the registry lines do not match the SAM certificate");
    }
    byte[] stationSki = StationKeys.ski(custody.stationPoint());
    if (!Arrays.equals(stationSki, bundle.stationSki())) {
      throw new IllegalArgumentException(
          "the bundle is wrapped to station " + bundle.station() + ", not to this station");
    }
    String name = BatchRules.batchName(bundle.iin(), bundle.batch());
    if (BatchMetadata.exists(request.producer, name)) {
      throw new IllegalStateException("Batch " + name + " already exists at this station");
    }
    SamLedgerEntry.Signed genesis = bundle.genesis();
    SamPersonalizationService.requireGenesis(
        genesis,
        samX509,
        samCertificate,
        bundle.paramsDigest(),
        bundle.quota(),
        bundle.initialTs());

    CardTransport transport = request.sam;
    byte[] kdd = new CardDiversificationDataService().readKdd(transport).kdd;
    if (!HexUtil.format(kdd).equals(bundle.samId())) {
      throw new IllegalArgumentException(
          "the SAM in the reader (" + HexUtil.format(kdd) + ") is not the bundle's SAM");
    }
    DerivedScpKeys production = custody.keyDeriver().derive(kdd);
    byte[] encoded =
        custody.unwrapHandoff(
            bundle.ephemeralPublicKey(),
            bundle.wrapped(),
            SamHandoff.sharedInfo(bundle.samId(), stationSki));
    SamHandoff.Secret secret;
    try {
      secret = SamHandoff.Secret.decode(encoded);
    } finally {
      Arrays.fill(encoded, (byte) 0);
    }
    byte[] handoffPin = secret.pin();
    try {
      ScpConfig handoff = secret.scp(bundle.scpKeyVersion());
      PublicKey samKey = samX509.getPublicKey();
      try (GlobalPlatformSession session = openHandoff(transport, handoff, production)) {
        SamClient sam = ApduSamClient.secure(session);
        if (!Arrays.equals(ApduSamClient.paramsDigest(sam.parameters()), bundle.paramsDigest())) {
          throw new IllegalStateException("the SAM holds parameters other than the bundle's");
        }
        SamStatus status = new SamOperationsService().signedStatus(sam, samKey);
        if (!status.isOperational()
            || status.issued != 0
            || status.eventSeq != genesis.entry.eventSeq
            || !Arrays.equals(status.chainHead(), genesis.entry.head())
            || status.allocationSeq != extension.allocationSeq
            || !Arrays.equals(status.registryHead(), extension.registryHead())
            || !Arrays.equals(status.samSki(), KeyIdentifiers.ski(samKey))) {
          throw new IllegalStateException(
              "the SAM is not the freshly locked SAM of the bundle (lifecycle "
                  + SamStatus.lifecycleName(status.lifecycle)
                  + ", issued "
                  + status.issued
                  + ")");
        }
      }
      new CardKeyRotationService().rotate(transport, handoff, production, false);
      try (GlobalPlatformSession session =
          transport.openGlobalPlatformSession(ApduSamClient.SAM_AID, production.config)) {
        ApduSamClient.secure(session).changeOperatorPin(handoffPin, request.operatorPin);
      }
    } finally {
      Arrays.fill(handoffPin, (byte) 0);
      secret.wipe();
    }

    BatchMetadata batch = new BatchMetadata();
    batch.producer = request.producer;
    batch.name = name;
    batch.created = java.time.Instant.now().toString();
    batch.state = BatchMetadata.STATE_SAM_BOUND;
    batch.opid.iin = bundle.iin();
    batch.opid.batch = bundle.batch();
    batch.paramsDigest = HexUtil.format(bundle.paramsDigest());
    batch.registry.allocate = bundle.allocateLine();
    batch.registry.bind = bundle.bindLine();
    batch.registry.allocationSeq = extension.allocationSeq;
    batch.registry.head = HexUtil.format(extension.registryHead());
    batch.quota.initial = bundle.quota();
    batch.quota.authorizedTotal = bundle.quota();
    batch.quota.initialTs = bundle.initialTs();
    batch.quota.lastTopUpTs = bundle.initialTs();
    batch.f9.validityDays = bundle.f9ValidityDays();
    batch.sam = new BatchMetadata.Sam();
    batch.sam.samId = bundle.samId();
    batch.sam.kdd = bundle.samId();
    batch.sam.certificate = "sam.pem";
    batch.sam.certificateSha256 = HexUtil.format(IssuanceCrypto.sha256(samCertificate));
    batch.sam.ski = HexUtil.format(KeyIdentifiers.ski(samX509.getPublicKey()));
    batch.sam.subject = samX509.getSubjectX500Principal().getName();
    batch.sam.notBefore = samX509.getNotBefore().toInstant().toString();
    batch.sam.notAfter = samX509.getNotAfter().toInstant().toString();
    batch.sam.scpKeyVersion = production.config.keyVersion;
    String stockKey = BatchRules.newStockKey(batch, request.stockKeyOut);
    batch.writeNew();
    StringWriter text = new StringWriter();
    try (JcaPEMWriter writer = new JcaPEMWriter(text)) {
      writer.writeObject(samX509);
    }
    SecureFiles.writeNew(
        batch.directory().resolve("sam.pem"), text.toString().getBytes(StandardCharsets.US_ASCII));
    new IssuanceLedger(batch.directory().resolve(batch.ledger)).appendGenesis(genesis);
    return new Result(batch, stockKey);
  }

  /**
   * Opens the handoff channel. When the handoff keys are refused but the production keys open the
   * SAM, the SAM was already received and the command is refused.
   */
  private static GlobalPlatformSession openHandoff(
      CardTransport transport, ScpConfig handoff, DerivedScpKeys production) throws Exception {
    try {
      return transport.openGlobalPlatformSession(ApduSamClient.SAM_AID, handoff);
    } catch (Exception handoffRefused) {
      boolean received;
      try (GlobalPlatformSession ignored =
          transport.openGlobalPlatformSession(ApduSamClient.SAM_AID, production.config)) {
        received = true;
      } catch (Exception productionRefused) {
        received = false;
      }
      if (received) {
        throw new IllegalStateException(
            "This SAM was already received: the handoff keys no longer work", handoffRefused);
      }
      throw handoffRefused;
    }
  }

  static OpenPhysicalExtensions.SamBatch samBatch(byte[] samCertificate) {
    Certificate parsed = Certificate.getInstance(samCertificate);
    return OpenPhysicalExtensions.parseSamBatch(
        OpenPhysicalExtensions.requireNonCritical(
            parsed.getTBSCertificate().getExtensions(), OpenPhysicalExtensions.SAM_BATCH));
  }
}
