/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.SecureFiles;
import dev.mistial.tools.openfips201.emulator.EmulatedApplet;
import dev.mistial.tools.openfips201.emulator.ZmqEmulatorFixture;
import dev.mistial.tools.openfips201.producer.BatchRules;
import dev.mistial.tools.openfips201.producer.ProducerPaths;
import dev.mistial.tools.openfips201.producer.ProducerSetupService;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.junit.jupiter.api.Assumptions;
import pro.javacard.gp.keys.PlaintextKeys;

/**
 * The two-station topology on jCardEngine readers over ZeroMQ. Each station has its own {@code
 * openfips201.home}: the root station (root CA, IIN FF1 key, allocation registry) personalizes a
 * stock Issuer SAM and emits a handoff bundle; the production station receives that SAM and then
 * produces cards on a second reader holding a stock card with the OpenFIPS201 package. The SAM and
 * the card are in separate engines; selecting PIV on the SAM's engine would deselect the SAM.
 *
 * <p>{@link #useRoot()} and {@link #useProduction()} switch {@code openfips201.home}; every station
 * operation runs under its own home.
 */
final class EmulatorBed implements AutoCloseable {
  static final byte[] OPERATOR_PIN = "13572468".getBytes(StandardCharsets.US_ASCII);
  static final int IIN = 4321;
  static final String STATION = "line-1";

  final String producer;
  final Path rootHome;
  final Path productionHome;
  final int batchNumber;
  final long quota;
  final String batch;
  final Path cap;
  final Path bundle;
  final ZmqEmulatorFixture sam;
  String stockKey;
  ZmqEmulatorFixture card;

  private EmulatorBed(
      String producer,
      Path rootHome,
      Path productionHome,
      int batchNumber,
      long quota,
      Path cap,
      ZmqEmulatorFixture sam) {
    this.producer = producer;
    this.rootHome = rootHome;
    this.productionHome = productionHome;
    this.batchNumber = batchNumber;
    this.quota = quota;
    this.batch = BatchRules.batchName(IIN, batchNumber);
    this.cap = cap;
    this.bundle = rootHome.resolve("sam-handoff-" + batch + ".json");
    this.sam = sam;
  }

  /** The CAP under test; skips unless the build carries attestation. */
  static Path requireAttestationCap() {
    Assumptions.assumeTrue(
        !"false".equalsIgnoreCase(System.getProperty("attestation.enabled", "true")),
        "issuance requires an attestation build");
    String capPath = System.getProperty("cap.path");
    Assumptions.assumeTrue(capPath != null, "cap.path is not set");
    Path cap = Paths.get(capPath);
    Assumptions.assumeTrue(Files.isRegularFile(cap), "CAP not built: " + cap);
    return cap;
  }

  /** Starts the stock SAM reader; the card reader starts once the SAM is received. */
  static EmulatorBed start(
      String producer, Path rootHome, Path productionHome, int batchNumber, long quota)
      throws Exception {
    Path cap = requireAttestationCap();
    ZmqEmulatorFixture sam =
        ZmqEmulatorFixture.start(PlaintextKeys.DEFAULT_KEY(), EmulatedApplet.SAM);
    return new EmulatorBed(producer, rootHome, productionHome, batchNumber, quota, cap, sam);
  }

  void useRoot() {
    System.setProperty("openfips201.home", rootHome.toString());
  }

  void useProduction() {
    System.setProperty("openfips201.home", productionHome.toString());
  }

  /**
   * Writes schema-3 profiles for software custody: a root station and a production station holding
   * only the public {@code root.pem}.
   */
  void writeLocalProfiles(X509Certificate root, String f9Subject) throws Exception {
    writeProfile(rootHome, ProducerSetupService.STATION_ROOT, root, f9Subject);
    writeProfile(productionHome, ProducerSetupService.STATION_PRODUCTION, root, f9Subject);
  }

  private void writeProfile(Path home, String station, X509Certificate root, String f9Subject)
      throws Exception {
    System.setProperty("openfips201.home", home.toString());
    Path directory = ProducerPaths.producer(producer);
    ProducerPaths.createDirectories(directory);
    Files.write(
        directory.resolve("producer.json"),
        ("{\"schema\":\""
                + ProducerSetupService.SCHEMA
                + "\",\"station\":\""
                + station
                + "\",\"name\":\""
                + producer
                + "\",\"custody\":\"test\",\"attestation\":{\"issuerSubject\":\""
                + f9Subject
                + "\"}}")
            .getBytes(StandardCharsets.UTF_8));
    SecureFiles.writeNew(directory.resolve("root.pem"), pem(root));
  }

  static byte[] pem(X509Certificate certificate) throws Exception {
    StringWriter text = new StringWriter();
    try (JcaPEMWriter writer = new JcaPEMWriter(text)) {
      writer.writeObject(certificate);
    }
    return text.toString().getBytes(StandardCharsets.US_ASCII);
  }

  /**
   * Root station: {@code root init} (once), {@code station import} of {@code stationPoint}, {@code
   * root allocate} and {@code sam personalize}, which writes the handoff bundle.
   */
  SamPersonalizationService.Result personalize(RootKeys keys, byte[] stationPoint, String f9Subject)
      throws Exception {
    return personalize(keys, stationPoint, f9Subject, personalizeRequest());
  }

  /** As {@link #personalize(RootKeys, byte[], String)}, with {@code request}. */
  SamPersonalizationService.Result personalize(
      RootKeys keys,
      byte[] stationPoint,
      String f9Subject,
      IssuanceService.PersonalizeRequest request)
      throws Exception {
    useRoot();
    if (!Files.exists(AllocationRegistry.file(producer))) {
      new RootStationService().init(producer, keys);
    }
    if (!Files.exists(StationKeys.stationFile(producer, STATION))) {
      Path pem =
          StationKeys.writeStationPem(
              ProducerPaths.producer(producer).resolve("station-" + STATION + ".pem"),
              stationPoint);
      StationKeys.importStation(producer, STATION, pem);
    }
    if (AllocationRegistry.open(producer, keys).allocation(IIN, batchNumber) == null) {
      new RootStationService().allocate(producer, keys, IIN, batchNumber, quota);
    }
    return new IssuanceService().personalize(request, keys, f9Subject);
  }

  /**
   * Both stations under software custody: profiles, personalization at the root station and receipt
   * at the production station, which is left as the current home.
   */
  void bringUp(IssuanceTestKeys.LocalRoot root, IssuanceTestKeys.LocalCustody custody)
      throws Exception {
    writeLocalProfiles(root.rootCertificate(), SoftBatch.F9_TEMPLATE);
    personalize(root, custody.stationPoint(), SoftBatch.F9_TEMPLATE);
    receive(custody);
  }

  IssuanceService.PersonalizeRequest personalizeRequest() {
    IssuanceService.PersonalizeRequest request = new IssuanceService.PersonalizeRequest();
    request.producer = producer;
    request.iin = IIN;
    request.batch = batchNumber;
    request.station = STATION;
    request.sam = sam.target();
    request.samStockKey = PlaintextKeys.DEFAULT_KEY();
    request.install = true;
    request.bundleOut = bundle;
    return request;
  }

  /**
   * Production station: {@code sam receive} under {@code custody} (null: the station's PKCS#11
   * custody), then a stock card under the batch's new stock key in the card reader.
   */
  SamReceiveService.Result receive(Custody custody) throws Exception {
    useProduction();
    SamReceiveService.Result received =
        custody == null
            ? new IssuanceService()
                .receive(producer, sam.target(), bundle, OPERATOR_PIN.clone(), null)
            : new IssuanceService()
                .receive(producer, sam.target(), bundle, OPERATOR_PIN.clone(), null, custody);
    stockKey = received.stockKey;
    card = ZmqEmulatorFixture.start(HexUtil.parse(stockKey));
    return received;
  }

  /**
   * Root-side oracle: OPIDs 1..{@code count} of this batch, replayed from the root LCG record and
   * the IIN FF1 key under {@code keys} (null: the root station's PKCS#11 custody). The current home
   * is restored afterwards.
   */
  List<String> rootOpids(RootKeys keys, int count) throws Exception {
    String previous = System.getProperty("openfips201.home");
    useRoot();
    try {
      if (keys == null) {
        try (RootContext context = RootContext.load(producer)) {
          return replay(context, count);
        }
      }
      return replay(keys, count);
    } finally {
      System.setProperty("openfips201.home", previous);
    }
  }

  private List<String> replay(RootKeys keys, int count) throws Exception {
    RootBatchRecord.SamFile bound = RootBatchRecord.readSam(producer, IIN, batchNumber);
    BatchLcgAuditor auditor =
        BatchLcgAuditor.of(
            RootBatchRecord.readLcg(producer, IIN, batchNumber, bound.samId), keys.iinCipher(IIN));
    List<String> opids = new ArrayList<String>();
    for (int seq = 1; seq <= count; seq++) {
      opids.add(auditor.expected(seq).toPrinted());
    }
    return opids;
  }

  IssuanceService.ProduceRequest produceRequest() {
    IssuanceService.ProduceRequest request = new IssuanceService.ProduceRequest();
    request.producer = producer;
    request.batch = batch;
    request.target = card.target();
    request.sam = sam.target();
    request.stockScpKey = HexUtil.parse(stockKey);
    request.operatorPin = OPERATOR_PIN.clone();
    request.cap = cap;
    return request;
  }

  /** Replaces the card in the card reader with a new stock card. */
  void newCard() throws Exception {
    card.close();
    card = ZmqEmulatorFixture.start(HexUtil.parse(stockKey));
  }

  @Override
  public void close() throws Exception {
    try {
      if (card != null) {
        card.close();
      }
    } finally {
      sam.close();
    }
  }
}
