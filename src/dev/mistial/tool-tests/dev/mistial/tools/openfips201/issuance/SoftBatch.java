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
import dev.mistial.tools.openfips201.crypto.KeyIdentifiers;
import dev.mistial.tools.openfips201.opid.Lcg;
import dev.mistial.tools.openfips201.opid.Opid;
import dev.mistial.tools.openfips201.opid.OpidSequence;
import dev.mistial.tools.openfips201.producer.BatchMetadata;
import dev.mistial.tools.openfips201.producer.BatchRules;
import dev.mistial.tools.openfips201.producer.ProducerPaths;
import dev.mistial.tools.openfips201.producer.ProducerSetupService;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

/**
 * A batch bound to a {@link SoftIssuerSam} on disk, laid out exactly as {@code sam receive} leaves
 * it at the production station: batch.json (schema 4, no LCG) SAM_BOUND with root-signed allocate
 * and bind registry lines, sam.pem and the ledger genesis line. The root-side material (FF1 key,
 * LCG) stays in this fixture as the test oracle {@link #expected(long)}.
 */
final class SoftBatch {
  static final String PRODUCER = "soft_producer";
  static final String F9_TEMPLATE = "CN=Soft F9,O=OpenPhysical Test";
  static final int IIN = 4321;
  static final String SAM_ID = "00004242";

  final BatchMetadata batch;
  final SoftIssuerSam sam;
  final String stockKey;
  private final OpidSequence sequence;
  private final IssuanceTestKeys.LocalRoot root;
  private final IssuanceTestKeys.LocalCustody custody;

  private SoftBatch(
      BatchMetadata batch,
      SoftIssuerSam sam,
      String stockKey,
      OpidSequence sequence,
      IssuanceTestKeys.LocalRoot root) {
    this.batch = batch;
    this.sam = sam;
    this.stockKey = stockKey;
    this.sequence = sequence;
    this.root = root;
    this.custody = new IssuanceTestKeys.LocalCustody(root.rootCertificate());
  }

  /**
   * Points {@code openfips201.home} at {@code home} and writes a minimal schema-3 producer profile
   * for {@code station}.
   */
  static void producer(Path home, String station) throws Exception {
    System.setProperty("openfips201.home", home.toString());
    Path producer = ProducerPaths.producer(PRODUCER);
    ProducerPaths.createDirectories(producer);
    Path profile = producer.resolve("producer.json");
    if (!Files.exists(profile)) {
      Files.write(
          profile,
          ("{\"schema\":\""
                  + ProducerSetupService.SCHEMA
                  + "\",\"station\":\""
                  + station
                  + "\",\"name\":\""
                  + PRODUCER
                  + "\",\"custody\":\"test\",\"attestation\":{\"issuerSubject\":\""
                  + F9_TEMPLATE
                  + "\"}}")
              .getBytes(StandardCharsets.UTF_8));
    }
  }

  static SoftBatch create(Path home, String name, int batchNumber, long quota) throws Exception {
    producer(home, ProducerSetupService.STATION_PRODUCTION);
    IssuanceTestKeys.LocalRoot root = new IssuanceTestKeys.LocalRoot();
    AllocationRegistry registry = new RootStationService().init(PRODUCER, root);
    JsonObject allocation = registry.allocate(IIN, batchNumber, quota);
    long allocationSeq = allocation.get("seq").getAsLong();
    String allocateLine = registry.line(allocationSeq);
    String bindLine = registry.prepareBind(IIN, batchNumber, SAM_ID);
    byte[] registryHead = AllocationRegistry.headAfter(bindLine);
    registry.commit(bindLine);

    Lcg lcg = Lcg.generate(new SecureRandom());
    long initialTs = System.currentTimeMillis();
    SamParameters parameters =
        new SamParameters(IIN, batchNumber, quota, initialTs, lcg, root.iinCipher(IIN));
    OpidSequence sequence = OpidSequence.of(IIN, batchNumber, lcg, root.iinCipher(IIN));
    SoftIssuerSam sam =
        new SoftIssuerSam(
            root.root,
            parameters,
            sequence,
            allocationSeq,
            registryHead,
            BatchRules.samSubject("CN=Soft Issuer SAM", SAM_ID),
            new X500Name(F9_TEMPLATE));
    byte[] genesis = sam.lock();
    X509Certificate certificate =
        dev.mistial.tools.openfips201.attestation.StrictDer.parseCertificate(sam.certificate);

    BatchMetadata batch = new BatchMetadata();
    batch.producer = PRODUCER;
    batch.name = name;
    batch.created = java.time.Instant.now().toString();
    batch.state = BatchMetadata.STATE_SAM_BOUND;
    batch.opid.iin = IIN;
    batch.opid.batch = batchNumber;
    batch.paramsDigest = HexUtil.format(parameters.paramsDigest());
    batch.registry.allocate = allocateLine;
    batch.registry.bind = bindLine;
    batch.registry.allocationSeq = allocationSeq;
    batch.registry.head = HexUtil.format(registryHead);
    batch.quota.initial = quota;
    batch.quota.authorizedTotal = quota;
    batch.quota.initialTs = initialTs;
    batch.quota.lastTopUpTs = initialTs;
    batch.f9.validityDays = BatchRules.DEFAULT_F9_VALIDITY_DAYS;
    batch.sam = new BatchMetadata.Sam();
    batch.sam.samId = SAM_ID;
    batch.sam.kdd = SAM_ID;
    batch.sam.certificate = "sam.pem";
    batch.sam.certificateSha256 = HexUtil.format(IssuanceCrypto.sha256(sam.certificate));
    batch.sam.ski = HexUtil.format(KeyIdentifiers.ski(sam.publicKey()));
    batch.sam.subject = certificate.getSubjectX500Principal().getName();
    String stockKey = BatchRules.newStockKey(batch, null);
    batch.writeNew();
    StringWriter text = new StringWriter();
    try (JcaPEMWriter writer = new JcaPEMWriter(text)) {
      writer.writeObject(certificate);
    }
    SecureFiles.writeNew(
        batch.directory().resolve("sam.pem"), text.toString().getBytes(StandardCharsets.US_ASCII));
    new IssuanceLedger(batch.directory().resolve(batch.ledger))
        .appendGenesis(SamLedgerEntry.Signed.parse(genesis));
    return new SoftBatch(batch, sam, stockKey, sequence, root);
  }

  /** Root-station custody of this batch (root key, FF1 key, registry head). */
  IssuanceTestKeys.LocalRoot root() {
    return root;
  }

  /** Production-station custody of this batch (public root, station key, card deriver). */
  IssuanceTestKeys.LocalCustody custody() {
    return custody;
  }

  /** Test oracle: the OPID of issuance {@code seq}, computed from the root-side LCG and FF1 key. */
  Opid expected(long seq) {
    return sequence.opidAt(seq);
  }

  /** The root-side OPID sequence (test oracle for the root ledger audit). */
  OpidSequence sequence() {
    return sequence;
  }

  IssuanceLedger ledger() {
    return new IssuanceLedger(batch.directory().resolve(batch.ledger));
  }

  CardIssuanceOrchestrator.Inputs inputs() {
    CardIssuanceOrchestrator.Inputs inputs = new CardIssuanceOrchestrator.Inputs();
    inputs.batch = batch;
    inputs.root = custody.rootCertificate();
    inputs.samCertificate = sam.certificate.clone();
    Map<String, String> properties = new LinkedHashMap<String, String>();
    properties.put("attestation.enabled", "true");
    inputs.cap = new CapInfo(Paths.get("test.cap"), "00", "00", properties);
    inputs.keyDeriver = custody.keyDeriver();
    inputs.target = "zmq:card";
    inputs.samTarget = "zmq:sam";
    inputs.custody = "test";
    return inputs;
  }
}
