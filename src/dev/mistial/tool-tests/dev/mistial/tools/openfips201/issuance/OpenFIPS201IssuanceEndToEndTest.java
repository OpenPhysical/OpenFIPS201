/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.OpenFips201Tool;
import dev.mistial.tools.openfips201.attestation.OpenPhysicalExtensions;
import dev.mistial.tools.openfips201.common.CardTransport;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.common.SecureFiles;
import dev.mistial.tools.openfips201.gp.DerivedScpKeys;
import dev.mistial.tools.openfips201.opid.Lcg;
import dev.mistial.tools.openfips201.opid.Opid;
import dev.mistial.tools.openfips201.opid.OpidSequence;
import dev.mistial.tools.openfips201.pkcs11.SoftHsmFixture;
import dev.mistial.tools.openfips201.producer.BatchMetadata;
import dev.mistial.tools.openfips201.producer.ProducerPaths;
import dev.mistial.tools.openfips201.producer.ProducerSetupService;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;
import pro.javacard.gp.keys.PlaintextKeys;

/**
 * The full issuer workflow on jCardEngine with two stations on SoftHSM2 tokens of their own, each
 * in its own {@code openfips201.home}: the root station (root CA, IIN FF1 key, registry)
 * personalizes an Issuer SAM on one ZeroMQ reader; the production station (card master key, station
 * handoff key, public root.pem only) receives it and produces stock cards on another.
 */
@Tag("issuance-e2e")
@Tag("softhsm")
@Timeout(value = 300, unit = TimeUnit.SECONDS)
class OpenFIPS201IssuanceEndToEndTest {
  private static final AtomicInteger BATCH_NUMBERS =
      new AtomicInteger(1000 + new java.util.Random().nextInt(7000));

  @TempDir Path temp;
  private String producer;
  private Path rootHome;
  private Path productionHome;
  private EmulatorBed bed;

  @BeforeEach
  void setUpStations() throws Exception {
    EmulatorBed.requireAttestationCap();
    rootHome = SoftHsmFixture.requireSoftHsm();
    producer = SoftHsmFixture.uniqueLabel("e2e-");
    ProducerSetupService.Request root = new ProducerSetupService.Request();
    root.name = producer;
    root.station = ProducerSetupService.STATION_ROOT;
    root.module = SoftHsmFixture.module();
    root.tokenLabel = producer + "-root";
    root.rootSubject = "CN=" + producer + " Root,O=OpenPhysical Test";
    root.f9Subject = "CN=" + producer + " F9,O=OpenPhysical Test";
    root.devSoftHsm = true;
    root.soPinOut = temp.resolve("so-root.pin");
    new ProducerSetupService().setup(root);
    Path rootPem = ProducerPaths.producer(producer).resolve("root.pem");

    // One SoftHSM2 configuration per process: the production home names the same token store.
    productionHome = temp.resolve("production");
    Files.createDirectories(productionHome.resolve("softhsm"));
    Files.copy(
        rootHome.resolve("softhsm/softhsm2.conf"), productionHome.resolve("softhsm/softhsm2.conf"));
    System.setProperty("openfips201.home", productionHome.toString());
    ProducerSetupService.Request production = new ProducerSetupService.Request();
    production.name = producer;
    production.station = ProducerSetupService.STATION_PRODUCTION;
    production.module = SoftHsmFixture.module();
    production.tokenLabel = producer + "-prod";
    production.rootPem = rootPem;
    production.devSoftHsm = true;
    production.soPinOut = temp.resolve("so-production.pin");
    new ProducerSetupService().setup(production);
  }

  @AfterEach
  void stop() throws Exception {
    if (bed != null) {
      bed.close();
    }
  }

  private EmulatorBed bed(long quota) throws Exception {
    bed =
        EmulatorBed.start(
            producer, rootHome, productionHome, BATCH_NUMBERS.incrementAndGet(), quota);
    return bed;
  }

  /** The production station's batch record (the production home is current). */
  private BatchMetadata batch() throws Exception {
    return BatchMetadata.read(producer, bed.batch);
  }

  private CardIssuanceOrchestrator.Result produce() throws Exception {
    return new IssuanceService().produce(bed.produceRequest());
  }

  private static String failure(CardIssuanceOrchestrator.Result result) {
    return result.record.failure == null ? "" : result.record.failure.redactedMessage;
  }

  private int cli(String... args) {
    CommandLine commandLine = new CommandLine(new OpenFips201Tool());
    ByteArrayOutputStream err = new ByteArrayOutputStream();
    commandLine.setErr(new PrintWriter(err, true));
    commandLine.setExecutionExceptionHandler(
        (exception, parsed, result) -> {
          parsed.getErr().println("Error: " + exception);
          return 1;
        });
    int exit = commandLine.execute(args);
    lastError = new String(err.toByteArray(), StandardCharsets.UTF_8);
    return exit;
  }

  private String lastError = "";

  private Path secret(String name, String value) throws Exception {
    return SecureFiles.writeNew(
        temp.resolve(name), (value + "\n").getBytes(StandardCharsets.UTF_8));
  }

  /** The production station's handoff key, read at the production home. */
  private byte[] stationPoint() throws Exception {
    bed.useProduction();
    try (ProductionContext context = ProductionContext.load(producer)) {
      return context.stationPoint();
    }
  }

  /** {@code sam personalize} at the root station with {@code request}. */
  private void personalize(IssuanceService.PersonalizeRequest request) throws Exception {
    byte[] point = stationPoint();
    bed.useRoot();
    try (RootContext root = RootContext.load(producer)) {
      bed.personalize(root, point, root.profile.attestation.issuerSubject, request);
    }
  }

  /** Root station personalizes the SAM, then the production station receives it. */
  private void personalize() throws Exception {
    personalize(bed.personalizeRequest());
    bed.receive(null);
    assertEquals(BatchMetadata.STATE_SAM_BOUND, batch().state);
  }

  /** {@code ledger verify --sam} at the production station, with DECIPHER spot checks. */
  private IssuanceLedger.Report verifyLedger() throws Exception {
    try (ProductionContext context = ProductionContext.load(producer)) {
      return new LedgerService()
          .verify(
              batch(),
              context.rootCertificate(),
              bed.sam.target(),
              context,
              EmulatorBed.OPERATOR_PIN,
              LedgerService.DEFAULT_DECIPHER_SAMPLE);
    }
  }

  @Test
  void fullProduce() throws Exception {
    bed(5);
    personalize();
    CardIssuanceOrchestrator.Result first = produce();
    assertEquals(0, first.exitCode, failure(first));
    List<String> expected = bed.rootOpids(null, 2);
    assertEquals(expected.get(0), first.record.sam.opid);
    assertEquals(IssuanceReceipt.STATUS_COMPLETED, first.record.status);
    assertEquals("softhsm-dev", first.record.custody);
    assertMeasurementsBound(first);

    // The card now answers only to keys derived from its KDD under the production master key.
    try (ProductionContext context = ProductionContext.load(producer);
        CardTransport transport = bed.card.target().openTransport()) {
      DerivedScpKeys keys = context.keyDeriver().derive(HexUtil.parse(first.record.card.kddFinal));
      try (GlobalPlatformSession ignored =
          transport.openGlobalPlatformSession(GlobalPlatformSession.ISD_AID, keys.config)) {
        // Opening the channel is the check.
      }
    }
    assertProofPinRefused(bed);

    // The second card through the CLI, with secrets from owner-only files.
    bed.newCard();
    Path stock = secret("stock.key", bed.stockKey);
    Path pin =
        secret("operator.pin", new String(EmulatorBed.OPERATOR_PIN, StandardCharsets.US_ASCII));
    String sam = "zmq:" + bed.sam.endpoint();
    assertEquals(
        0,
        cli(
            "card",
            "produce",
            "--producer",
            producer,
            "--batch",
            bed.batch,
            "--target",
            "zmq:" + bed.card.endpoint(),
            "--sam",
            sam,
            "--cap",
            bed.cap.toString(),
            "--stock-scp-key-file",
            stock.toString(),
            "--operator-pin-file",
            pin.toString()),
        lastError);
    assertEquals(
        0,
        cli(
            "ledger",
            "verify",
            "--producer",
            producer,
            "--batch",
            bed.batch,
            "--sam",
            sam,
            "--operator-pin-file",
            pin.toString()),
        lastError);
    assertEquals(
        0,
        cli("sam", "status", "--producer", producer, "--batch", bed.batch, "--sam", sam, "--json"),
        lastError);

    // The root station replays the exported production ledger against its LCG and FF1 key.
    Path exported = temp.resolve("ledger-export.jsonl");
    Files.copy(batch().directory().resolve(batch().ledger), exported);
    bed.useRoot();
    assertEquals(
        0,
        cli(
            "root",
            "audit-ledger",
            "--producer",
            producer,
            "--ledger",
            exported.toString(),
            "--batch",
            bed.batch),
        lastError);
    bed.useProduction();
  }

  /**
   * The CAP, CPLC and build hashes flow from the produce run into the receipt, the SAM-signed ISSUE
   * entry, the F9 issuance extension and the attestation leaf, and {@code attestation verify
   * --receipt} checks them; a different expected CAP hash fails.
   */
  private void assertMeasurementsBound(CardIssuanceOrchestrator.Result result) throws Exception {
    IssuanceReceipt record = result.record;
    byte[] capSha256 = HexUtil.parse(record.cap.sha256);
    assertArrayEquals(
        IssuanceCrypto.sha256(Files.readAllBytes(bed.cap)), capSha256, "receipt CAP SHA-256");
    byte[] cplcSha256 = IssuanceCrypto.sha256(HexUtil.parse(record.card.cplc));
    assertEquals(HexUtil.format(cplcSha256), record.card.cplcSha256, "receipt CPLC SHA-256");
    java.util.Properties properties = new java.util.Properties();
    try (java.io.InputStream in = Files.newInputStream(Paths.get(bed.cap + ".properties"))) {
      properties.load(in);
    }
    byte[] buildSha256 = HexUtil.parse(properties.getProperty("build.sha256"));

    SamLedgerEntry entry =
        IssueResponse.parse(HexUtil.parse(record.sam.issueResponse)).signedEntry.entry;
    assertArrayEquals(capSha256, entry.capSha256(), "SAM entry capSha256");
    assertArrayEquals(cplcSha256, entry.cplcSha256(), "SAM entry cplcSha256");
    SamLedgerEntry logged =
        new IssuanceLedger(batch().directory().resolve(batch().ledger))
            .issueLine(entry.issuanceSeq)
            .samEntry()
            .entry;
    assertArrayEquals(entry.encoded(), logged.encoded(), "ledger issue line carries the entry");

    byte[] f9 = java.util.Base64.getDecoder().decode(record.f9.certificateBase64);
    OpenPhysicalExtensions.F9Issuance issuance =
        OpenPhysicalExtensions.parseF9Issuance(
            OpenPhysicalExtensions.requireNonCritical(
                org.bouncycastle.asn1.x509.Certificate.getInstance(f9)
                    .getTBSCertificate()
                    .getExtensions(),
                OpenPhysicalExtensions.F9_ISSUANCE));
    assertArrayEquals(capSha256, issuance.capSha256(), "F9 capSha256");
    assertArrayEquals(cplcSha256, issuance.cplcSha256(), "F9 cplcSha256");
    byte[] leaf = java.util.Base64.getDecoder().decode(record.proof.leafBase64);
    OpenPhysicalExtensions.PivLeaf pivLeaf =
        OpenPhysicalExtensions.parsePivLeaf(
            OpenPhysicalExtensions.requireNonCritical(
                org.bouncycastle.asn1.x509.Certificate.getInstance(leaf)
                    .getTBSCertificate()
                    .getExtensions(),
                OpenPhysicalExtensions.PIV_LEAF));
    assertArrayEquals(buildSha256, pivLeaf.buildSha256(), "leaf buildSha256 = CAP build.sha256");

    Path samPem = pem("sam.pem", IssuanceService.samCertificate(batch()));
    Path f9Pem = pem("f9.pem", f9);
    Path leafPem = pem("leaf.pem", leaf);
    String[] verify = {
      "attestation",
      "verify",
      "--producer",
      producer,
      "--chain",
      samPem.toString(),
      "--chain",
      f9Pem.toString(),
      "--leaf",
      leafPem.toString(),
      "--receipt",
      result.receipt.toString()
    };
    assertEquals(
        dev.mistial.tools.openfips201.attestation.AttestationCommand.EXIT_VALID,
        cli(verify),
        lastError);
    byte[] otherCap = capSha256.clone();
    otherCap[0] ^= 1;
    String[] mismatched = java.util.Arrays.copyOf(verify, verify.length);
    mismatched[verify.length - 2] = "--expect-cap";
    mismatched[verify.length - 1] = HexUtil.format(otherCap);
    assertEquals(
        dev.mistial.tools.openfips201.attestation.AttestationCommand.EXIT_INVALID,
        cli(mismatched),
        lastError);
    assertTrue(lastError.isEmpty(), lastError);
  }

  private Path pem(String name, byte[] der) throws Exception {
    String body = java.util.Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der);
    String text = "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n";
    return Files.write(temp.resolve(name), text.getBytes(StandardCharsets.US_ASCII));
  }

  @Test
  void samDecipherReversesIssuedOpids() throws Exception {
    bed(5);
    personalize();
    CardIssuanceOrchestrator.Result first = produce();
    assertEquals(0, first.exitCode, failure(first));
    IssuanceService service = new IssuanceService();
    byte[] pin = EmulatorBed.OPERATOR_PIN;
    int iin = batch().opid.iin;
    int batchNumber = batch().opid.batch;

    DecipherResult issued =
        service.decipher(producer, bed.batch, bed.sam.target(), pin, first.record.sam.opid);
    assertTrue(issued.sameBatch);
    assertEquals(batchNumber, issued.batch);
    assertEquals(1, issued.count);
    assertTrue(issued.issued);

    // The next OPID of the sequence (root-side oracle) deciphers to issuance 2, not yet issued.
    DecipherResult next =
        service.decipher(producer, bed.batch, bed.sam.target(), pin, bed.rootOpids(null, 2).get(1));
    assertEquals(2, next.count);
    assertTrue(!next.issued);

    // A different batch under the same IIN key deciphers to that batch only.
    final int foreignBatch = (batchNumber + 1) % 10_000;
    String foreignOpid;
    bed.useRoot();
    try (RootContext root = RootContext.load(producer)) {
      foreignOpid =
          OpidSequence.of(iin, foreignBatch, Lcg.of(21, 7, 0), root.iinCipher(iin))
              .opidAt(1)
              .toPrinted();
    } finally {
      bed.useProduction();
    }
    DecipherResult other =
        service.decipher(producer, bed.batch, bed.sam.target(), pin, foreignOpid);
    assertTrue(!other.sameBatch);
    assertEquals(foreignBatch, other.batch);

    // Another IIN is refused by the SAM; a bad check digit is refused by the host parser.
    SamApduException otherIin =
        assertThrows(
            SamApduException.class,
            () ->
                service.decipher(
                    producer,
                    bed.batch,
                    bed.sam.target(),
                    pin,
                    Opid.of((iin + 1) % 10_000, 123456789012L).toPrinted()));
    assertEquals(0x6A88, otherIin.sw);
    String printed = first.record.sam.opid;
    char last = printed.charAt(16);
    String badLuhn = printed.substring(0, 16) + (char) ('0' + (last - '0' + 1) % 10);
    assertThrows(
        IllegalArgumentException.class,
        () -> service.decipher(producer, bed.batch, bed.sam.target(), pin, badLuhn));

    Path pinFile =
        secret("decipher.pin", new String(EmulatorBed.OPERATOR_PIN, StandardCharsets.US_ASCII));
    assertEquals(
        0,
        cli(
            "sam",
            "decipher",
            "--producer",
            producer,
            "--batch",
            bed.batch,
            "--sam",
            "zmq:" + bed.sam.endpoint(),
            "--opid",
            first.record.sam.opid,
            "--operator-pin-file",
            pinFile.toString()),
        lastError);
  }

  @Test
  void abortAfterIssue() throws Exception {
    bed(5);
    personalize();
    IssuanceService.ProduceRequest request = bed.produceRequest();
    request.hooks = failAt(IssuanceStage.F9_LOADED);
    CardIssuanceOrchestrator.Result aborted = new IssuanceService().produce(request);
    assertEquals(CardIssuanceOrchestrator.EXIT_BURNED, aborted.exitCode);
    assertTrue(aborted.record.burned);

    bed.newCard();
    CardIssuanceOrchestrator.Result next = produce();
    assertEquals(0, next.exitCode, failure(next));
    assertEquals(bed.rootOpids(null, 2).get(1), next.record.sam.opid);
    IssuanceLedger.Report report = verifyLedger();
    assertTrue(report.valid(), report.problems.toString());
  }

  @Test
  void lostIssueResponseAndReconcile() throws Exception {
    bed(5);
    personalize();
    IssuanceService.ProduceRequest request = bed.produceRequest();
    request.hooks = failAt(IssuanceStage.ISSUED);
    assertEquals(
        CardIssuanceOrchestrator.EXIT_BURNED, new IssuanceService().produce(request).exitCode);

    bed.newCard();
    IllegalStateException refused = assertThrows(IllegalStateException.class, this::produce);
    assertTrue(refused.getMessage().contains("ledger reconcile"), refused.getMessage());
    assertFalse(verifyLedger().valid());

    assertEquals(
        0,
        cli(
            "ledger",
            "reconcile",
            "--producer",
            producer,
            "--batch",
            bed.batch,
            "--sam",
            "zmq:" + bed.sam.endpoint()),
        lastError);
    IssuanceLedger.Report report = verifyLedger();
    assertTrue(report.valid(), report.problems.toString());
    CardIssuanceOrchestrator.Result next = produce();
    assertEquals(0, next.exitCode, failure(next));
    assertEquals(bed.rootOpids(null, 2).get(1), next.record.sam.opid);
  }

  @Test
  void wrongStockKeySendsNoApdu() throws Exception {
    bed(5);
    personalize();
    IssuanceService.ProduceRequest request = bed.produceRequest();
    request.stockScpKey = HexUtil.parse("000102030405060708090A0B0C0D0E0F");
    IllegalArgumentException refused =
        assertThrows(IllegalArgumentException.class, () -> new IssuanceService().produce(request));
    assertTrue(refused.getMessage().contains("before any card I/O"), refused.getMessage());
    // Neither reader was used: the SAM issued nothing and the same stock card still produces.
    assertEquals(0, new IssuanceLedger(batch().directory().resolve("ledger.jsonl")).lastIssueSeq());
    CardIssuanceOrchestrator.Result result = produce();
    assertEquals(0, result.exitCode, failure(result));
    assertEquals(bed.rootOpids(null, 1).get(0), result.record.sam.opid);
  }

  @Test
  void kddMismatchStopsBeforeKeyRotation() throws Exception {
    bed(5);
    personalize();
    IssuanceService.ProduceRequest request = bed.produceRequest();
    request.cardDecorator = card -> new SwappedCard(card);
    CardIssuanceOrchestrator.Result result = new IssuanceService().produce(request);
    assertEquals(CardIssuanceOrchestrator.EXIT_BURNED, result.exitCode);
    assertEquals(IssuanceStage.KEYS_ROTATED.name(), result.record.failure.stage);
    // The card keeps its stock keys.
    try (CardTransport transport = bed.card.target().openTransport();
        GlobalPlatformSession ignored =
            transport.openGlobalPlatformSession(
                GlobalPlatformSession.ISD_AID,
                ScpConfig.fromMaster(
                    ScpConfig.Mode.SCP03,
                    ScpConfig.KEY_VERSION_AUTO,
                    HexUtil.parse(bed.stockKey)))) {
      // Opening the channel with the stock key is the check.
    }
  }

  @Test
  void interruptedPersonalizationBindsNothingAndAFreshInstanceCompletes() throws Exception {
    bed(5);
    IssuanceService.PersonalizeRequest interrupted = bed.personalizeRequest();
    interrupted.hooks =
        step -> {
          if ("load".equals(step)) {
            throw new IllegalStateException("SAM removed before LOAD SAM CERTIFICATE");
          }
        };
    assertThrows(IllegalStateException.class, () -> personalize(interrupted));
    assertFalse(Files.exists(bed.bundle), "no handoff bundle without a locked SAM");
    bed.useRoot();
    try (RootContext root = RootContext.load(producer)) {
      assertNull(
          AllocationRegistry.open(producer, root).binding(EmulatorBed.IIN, bed.batchNumber),
          "the allocation stays unbound");
    }
    try (CardTransport transport = bed.sam.target().openTransport()) {
      assertEquals(
          SamStatus.LC_KEY_GENERATED, ApduSamClient.selectPlain(transport).status().lifecycle);
      // The half-personalized instance is deleted under the stock keys.
      try (GlobalPlatformSession isd =
          transport.openGlobalPlatformSession(
              GlobalPlatformSession.ISD_AID,
              ScpConfig.fromMaster(
                  ScpConfig.Mode.SCP03, ScpConfig.KEY_VERSION_AUTO, PlaintextKeys.DEFAULT_KEY()))) {
        isd.gp().deleteAID(new pro.javacard.capfile.AID(ApduSamClient.SAM_AID), false);
      }
    }

    // Personalization of a fresh instance completes the allocation.
    personalize();
    CardIssuanceOrchestrator.Result result = produce();
    assertEquals(0, result.exitCode, failure(result));
  }

  @Test
  void quotaExhaustedThenTopUpThenReplayRejected() throws Exception {
    bed(1);
    personalize();
    assertEquals(0, produce().exitCode);
    bed.newCard();
    IllegalStateException exhausted = assertThrows(IllegalStateException.class, this::produce);
    assertTrue(exhausted.getMessage().contains("quota exhausted"), exhausted.getMessage());

    Path request = temp.resolve("topup-request.json");
    Path authorization = temp.resolve("topup-authorization.json");
    String sam = "zmq:" + bed.sam.endpoint();
    assertEquals(
        0,
        cli(
            "sam",
            "top-up",
            "--producer",
            producer,
            "--batch",
            bed.batch,
            "--sam",
            sam,
            "--add",
            "2",
            "--request-out",
            request.toString()),
        lastError);
    bed.useRoot();
    assertEquals(
        0,
        cli(
            "root",
            "sign-top-up",
            "--producer",
            producer,
            "--request",
            request.toString(),
            "--out",
            authorization.toString()),
        lastError);
    bed.useProduction();
    assertEquals(
        0,
        cli(
            "sam",
            "top-up",
            "--producer",
            producer,
            "--batch",
            bed.batch,
            "--sam",
            sam,
            "--authorization-in",
            authorization.toString()),
        lastError);
    assertEquals(3, batch().quota.authorizedTotal);
    CardIssuanceOrchestrator.Result next = produce();
    assertEquals(0, next.exitCode, failure(next));
    assertEquals(bed.rootOpids(null, 2).get(1), next.record.sam.opid);

    assertNotEquals(
        0,
        cli(
            "sam",
            "top-up",
            "--producer",
            producer,
            "--batch",
            bed.batch,
            "--sam",
            sam,
            "--authorization-in",
            authorization.toString()));
    assertTrue(lastError.contains("replay"), lastError);
    // The root refuses to sign the same request twice.
    bed.useRoot();
    assertNotEquals(
        0,
        cli(
            "root",
            "sign-top-up",
            "--producer",
            producer,
            "--request",
            request.toString(),
            "--out",
            temp.resolve("again.json").toString()));
    bed.useProduction();
    IssuanceLedger.Report report = verifyLedger();
    assertTrue(report.valid(), report.problems.toString());
  }

  @Test
  void cliCloseStopsTheSamAndTerminateFollows() throws Exception {
    bed(5);
    personalize();
    assertEquals(0, produce().exitCode);
    String sam = "zmq:" + bed.sam.endpoint();
    Path pin = secret("close.pin", new String(EmulatorBed.OPERATOR_PIN, StandardCharsets.US_ASCII));
    String[] close = {
      "batch",
      "close",
      "--producer",
      producer,
      "--batch",
      bed.batch,
      "--sam",
      sam,
      "--operator-pin-file",
      pin.toString(),
      "--yes"
    };
    assertEquals(0, cli(close), lastError);
    assertEquals(BatchMetadata.STATE_CLOSED, batch().state);
    assertEquals(0, cli(close), lastError);

    // The SAM itself refuses BEGIN ISSUANCE once closed.
    try (ProductionContext context = ProductionContext.load(producer);
        CardTransport transport = bed.sam.target().openTransport();
        GlobalPlatformSession session = IssuanceService.openSam(transport, batch(), context)) {
      SamClient client = ApduSamClient.secure(session);
      client.verifyPin(EmulatorBed.OPERATOR_PIN);
      SamApduException refused = assertThrows(SamApduException.class, client::beginIssuance);
      assertEquals(0x6985, refused.sw);
    }
    bed.newCard();
    IllegalStateException produceRefused = assertThrows(IllegalStateException.class, this::produce);
    assertTrue(produceRefused.getMessage().contains("CLOSED"), produceRefused.getMessage());

    assertEquals(
        0,
        cli(
            "sam",
            "terminate",
            "--producer",
            producer,
            "--batch",
            bed.batch,
            "--sam",
            sam,
            "--operator-pin-file",
            pin.toString(),
            "--yes"),
        lastError);
    assertEquals(BatchMetadata.STATE_TERMINATED, batch().state);
    assertEquals(
        0,
        cli("ledger", "verify", "--producer", producer, "--batch", bed.batch, "--sam", sam),
        lastError);
    IssuanceLedger.Report report = verifyLedger();
    assertTrue(report.valid(), report.problems.toString());
    assertTrue(report.closed && report.terminated);
  }

  /** The produced card no longer accepts the proof PIN 123456: its PIN is random and unrecorded. */
  static void assertProofPinRefused(EmulatorBed bed) throws Exception {
    try (CardTransport transport = bed.card.target().openTransport()) {
      apdu4j.core.BIBO bibo = transport.bibo();
      dev.mistial.tools.openfips201.common.ApduSupport.selectApplication(
          bibo, GlobalPlatformSession.PIV_AID, "SELECT PIV");
      int sw =
          bibo.transmit(
                  new apdu4j.core.CommandAPDU(
                      0x00, 0x20, 0x00, 0x80, HexUtil.parse(IssuanceService.PROOF_PIN)))
              .getSW();
      assertEquals(0x63C0, sw & 0xFFF0, "VERIFY with the proof PIN must fail");
    }
  }

  private static CardIssuanceOrchestrator.StageHooks failAt(final IssuanceStage target) {
    return stage -> {
      if (stage == target) {
        throw new IllegalStateException("injected fault at " + stage);
      }
    };
  }

  /** The card reports a different KDD on its second identity read: a card swap. */
  private static final class SwappedCard implements PivIssuanceClient {
    private final PivIssuanceClient card;
    private int reads;

    SwappedCard(PivIssuanceClient card) {
      this.card = card;
    }

    @Override
    public CardIdentity readIdentity() throws Exception {
      CardIdentity identity = card.readIdentity();
      if (++reads == 1) {
        return identity;
      }
      byte[] kdd = identity.kdd();
      kdd[kdd.length - 1] ^= 0x01;
      return new CardIdentity(identity.cplc, identity.cplcFields, kdd);
    }

    @Override
    public void installApplet() throws Exception {
      card.installApplet();
    }

    @Override
    public byte[] generateF9() throws Exception {
      return card.generateF9();
    }

    @Override
    public byte[] proveF9(byte[] nonce) throws Exception {
      return card.proveF9(nonce);
    }

    @Override
    public void loadF9Certificate(byte[] certificate) throws Exception {
      card.loadF9Certificate(certificate);
    }

    @Override
    public byte[] readF9Certificate() throws Exception {
      return card.readF9Certificate();
    }

    @Override
    public ProofResult attestProofKey() throws Exception {
      return card.attestProofKey();
    }

    @Override
    public byte[] getVersion() throws Exception {
      return card.getVersion();
    }

    @Override
    public byte[] getStatus() throws Exception {
      return card.getStatus();
    }

    @Override
    public void rotateKeys(DerivedScpKeys keys) throws Exception {
      card.rotateKeys(keys);
    }

    @Override
    public boolean pivInstancePresent() throws Exception {
      return card.pivInstancePresent();
    }

    @Override
    public void deleteInstance(ScpConfig keys) throws Exception {
      card.deleteInstance(keys);
    }

    @Override
    public void restoreStockKeys(ScpConfig current, int version) throws Exception {
      card.restoreStockKeys(current, version);
    }
  }
}
