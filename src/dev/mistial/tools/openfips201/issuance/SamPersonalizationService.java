/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import com.google.gson.JsonObject;
import dev.mistial.tools.openfips201.attestation.StrictDer;
import dev.mistial.tools.openfips201.common.CardTransport;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.crypto.KeyIdentifiers;
import dev.mistial.tools.openfips201.crypto.SigningKey;
import dev.mistial.tools.openfips201.gp.CardDiversificationDataService;
import dev.mistial.tools.openfips201.gp.CardKeyRotationService;
import dev.mistial.tools.openfips201.gp.DerivedScpKeys;
import dev.mistial.tools.openfips201.opid.Lcg;
import dev.mistial.tools.openfips201.producer.BatchRules;
import dev.mistial.tools.openfips201.producer.StationGuard;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.EnumSet;
import org.bouncycastle.asn1.x500.X500Name;
import pro.javacard.capfile.AID;
import pro.javacard.capfile.CAPFile;
import pro.javacard.gp.GPCommands;
import pro.javacard.gp.GPData;
import pro.javacard.gp.GPRegistryEntry;

/**
 * {@code sam personalize} at the root station: one online step with the root custody and the SAM,
 * never a card.
 *
 * <ol>
 *   <li>the (IIN, batch) allocation exists in the registry and is unbound; the reader does not hold
 *       a PIV card; the SAM is freshly installed;
 *   <li>the LCG is drawn and stored only in the root's owner-only {@code
 *       root/batches/IIII-NNNN-<samId>.lcg.json};
 *   <li>over the SAM's stock channel: GENERATE TRANSPORT KEY, PUT PARAMETERS v5 (the LCG and the
 *       IIN FF1 key wrapped on the root token to the transport key), SET PIN (a random operator
 *       PIN), GENERATE;
 *   <li>the root issues the SAM certificate with batch extension v3 (allocationSeq and the registry
 *       head after the bind line), verifies it and loads it;
 *   <li>the SAM's GlobalPlatform keys are rotated to random handoff keys ({@link
 *       #HANDOFF_KEY_VERSION}); LOCK; the genesis entry must commit to the certificate,
 *       paramsDigest and quota;
 *   <li>the bind line is appended to the registry and {@code sam-handoff.json} written:
 *       root-signed, the handoff keys and operator PIN wrapped to the production station;
 *   <li>the handoff secrets are wiped.
 * </ol>
 *
 * <p>An interrupted personalization is not resumed: the SAM is reinstalled (or another SAM used)
 * and the command repeated. The handoff keys exist only in memory and in the bundle, so a SAM whose
 * bundle was never written cannot be operated by anyone.
 */
public final class SamPersonalizationService {
  /** GlobalPlatform key version of the handoff keys; distinct from stock and production keys. */
  public static final int HANDOFF_KEY_VERSION = 0x7E;

  private static final char[] PIN_ALPHABET =
      "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789".toCharArray();

  /** Fault-injection points: invoked before each named step. */
  interface Hooks {
    void before(String step) throws Exception;
  }

  private static final Hooks NO_HOOKS =
      new Hooks() {
        @Override
        public void before(String step) {}
      };

  /** Input to {@link #personalize}. */
  public static final class Request {
    public String producer;
    public int iin;
    public int batch;
    public String station;
    public RootKeys keys;
    public CardTransport sam;
    public ScpConfig samStockScp;
    public String f9SubjectTemplate;
    public String samSubjectTemplate;
    public int samValidityDays = BatchRules.DEFAULT_SAM_VALIDITY_DAYS;
    public int f9ValidityDays = BatchRules.DEFAULT_F9_VALIDITY_DAYS;

    /** Installs the SAM instance (from the already-loaded package unless {@link #samCap}). */
    public boolean install;

    public Path samCap;
    public Path bundleOut;
    public SecureRandom random = new SecureRandom();
  }

  /** Outcome of {@link #personalize}. */
  public static final class Result {
    public final Path bundle;
    public final String samId;
    public final byte[] samCertificate;
    public final SamLedgerEntry genesis;

    Result(Path bundle, String samId, byte[] samCertificate, SamLedgerEntry genesis) {
      this.bundle = bundle;
      this.samId = samId;
      this.samCertificate = samCertificate.clone();
      this.genesis = genesis;
    }
  }

  private final Hooks hooks;

  public SamPersonalizationService() {
    this(NO_HOOKS);
  }

  SamPersonalizationService(Hooks hooks) {
    this.hooks = hooks;
  }

  public Result personalize(Request request) throws Exception {
    if (request.bundleOut == null) {
      throw new IllegalArgumentException("the handoff bundle path is required");
    }
    if (java.nio.file.Files.exists(request.bundleOut)) {
      throw new IllegalArgumentException(request.bundleOut + " already exists");
    }
    if (request.f9ValidityDays < 1) {
      throw new IllegalArgumentException("F9 validity must be at least one day");
    }
    BatchRules.requireF9SubjectFits(request.f9SubjectTemplate, request.iin);
    BatchRules.requireSamSubjectFits(request.samSubjectTemplate);
    RootKeys keys = request.keys;
    AllocationRegistry registry = AllocationRegistry.open(request.producer, keys);
    JsonObject allocation = registry.allocation(request.iin, request.batch);
    if (allocation == null) {
      throw new IllegalArgumentException(
          String.format(
              "IIN %04d batch %04d is not allocated; run 'root allocate'",
              request.iin, request.batch));
    }
    if (registry.binding(request.iin, request.batch) != null) {
      throw new IllegalStateException(
          String.format(
              "IIN %04d batch %04d is already bound to a SAM", request.iin, request.batch));
    }
    byte[] stationPoint = StationKeys.importedPoint(request.producer, request.station);
    byte[] stationSki = StationKeys.ski(stationPoint);
    long quota = allocation.get("quota").getAsLong();
    long allocationSeq = allocation.get("seq").getAsLong();

    CardTransport transport = request.sam;
    hooks.before("preflight");
    StationGuard.requireNotPivCard(transport);
    byte[] kdd = new CardDiversificationDataService().readKdd(transport).kdd;
    String samId = HexUtil.format(kdd);
    if (request.install) {
      install(transport, request.samStockScp, request.samCap);
    }
    SamStatus before = ApduSamClient.selectPlain(transport).status();
    if (before.lifecycle != SamStatus.LC_INSTALLED) {
      throw new IllegalStateException(
          "SAM is "
              + SamStatus.lifecycleName(before.lifecycle)
              + "; personalization needs a freshly installed SAM");
    }

    hooks.before("lcg");
    String fpeKcv = keys.ensureIinKey(request.iin);
    RootBatchRecord.LcgFile lcgRecord =
        RootBatchRecord.readLcg(request.producer, request.iin, request.batch, samId);
    SamParameters parameters;
    if (lcgRecord == null) {
      Lcg lcg = Lcg.generate(request.random);
      long initialTs = System.currentTimeMillis();
      parameters =
          new SamParameters(
              request.iin, request.batch, quota, initialTs, lcg, keys.iinCipher(request.iin));
      lcgRecord = new RootBatchRecord.LcgFile();
      lcgRecord.iin = request.iin;
      lcgRecord.batch = request.batch;
      lcgRecord.samId = samId;
      lcgRecord.a = lcg.a;
      lcgRecord.c = lcg.c;
      lcgRecord.x0 = lcg.x0;
      lcgRecord.quota = quota;
      lcgRecord.initialTs = initialTs;
      lcgRecord.fpeKcv = fpeKcv;
      lcgRecord.paramsDigest = HexUtil.format(parameters.paramsDigest());
      RootBatchRecord.writeLcg(request.producer, lcgRecord);
    } else {
      if (lcgRecord.quota != quota || !fpeKcv.equals(lcgRecord.fpeKcv)) {
        throw new IllegalStateException(
            "The recorded LCG of this SAM was drawn for another quota or IIN key");
      }
      parameters =
          new SamParameters(
              request.iin,
              request.batch,
              quota,
              lcgRecord.initialTs,
              lcgRecord.lcg(),
              keys.iinCipher(request.iin));
    }

    SigningKey root = keys.rootSigner();
    X509Certificate rootCertificate = keys.rootCertificate();
    X500Name samSubject = BatchRules.samSubject(request.samSubjectTemplate, samId);
    byte[] operatorPin = randomPin(request.random);
    byte[] enc = new byte[16];
    byte[] mac = new byte[16];
    byte[] dek = new byte[16];
    request.random.nextBytes(enc);
    request.random.nextBytes(mac);
    request.random.nextBytes(dek);
    SamHandoff.Secret secret = new SamHandoff.Secret(enc, mac, dek, operatorPin);
    Arrays.fill(enc, (byte) 0);
    Arrays.fill(mac, (byte) 0);
    Arrays.fill(dek, (byte) 0);
    byte[] encodedSecret = null;
    try {
      byte[] samCertificate;
      String bindLine;
      try (GlobalPlatformSession session =
          transport.openGlobalPlatformSession(ApduSamClient.SAM_AID, request.samStockScp)) {
        SamClient sam = ApduSamClient.secure(session);
        hooks.before("transport");
        byte[] transportPoint = sam.generateTransportKey();
        RootKeys.WrappedKey wrappedFpe = keys.wrapIinKeyForSam(request.iin, transportPoint);
        hooks.before("params");
        sam.putParameters(
            parameters.encodePacket(
                new X500Name(request.f9SubjectTemplate),
                samSubject,
                IssuanceCrypto.point(rootCertificate.getPublicKey()),
                wrappedFpe));
        if (!Arrays.equals(
            ApduSamClient.paramsDigest(sam.parameters()), parameters.paramsDigest())) {
          throw new IllegalStateException(
              "The SAM reports a paramsDigest other than the one the root computed");
        }
        hooks.before("pin");
        sam.setOperatorPin(operatorPin);
        hooks.before("generate");
        byte[] point = sam.generateKey();
        PublicKey samKey = IssuanceCrypto.publicKey(point);
        hooks.before("load");
        bindLine = registry.prepareBind(request.iin, request.batch, samId);
        samCertificate =
            SamCertificateFactory.issue(
                root,
                point,
                samSubject,
                parameters.encodeBatchExtension(
                    allocationSeq, AllocationRegistry.headAfter(bindLine)),
                request.samValidityDays,
                new Date());
        byte[] reported = sam.loadCertificate(samCertificate);
        if (!Arrays.equals(reported, KeyIdentifiers.ski(samKey))) {
          throw new IllegalStateException("The SAM reports a different key identifier");
        }
      }

      hooks.before("rotate");
      ScpConfig handoff = secret.scp(HANDOFF_KEY_VERSION);
      new CardKeyRotationService()
          .rotate(transport, request.samStockScp, DerivedScpKeys.fromConfig(handoff), false);

      hooks.before("lock");
      SamLedgerEntry.Signed genesis;
      try (GlobalPlatformSession session =
          transport.openGlobalPlatformSession(ApduSamClient.SAM_AID, handoff)) {
        genesis = SamLedgerEntry.Signed.parse(ApduSamClient.secure(session).lock());
      }
      X509Certificate samX509 = StrictDer.parseCertificate(samCertificate);
      requireGenesis(genesis, samX509, samCertificate, parameters);

      hooks.before("bind");
      registry.commit(bindLine);
      RootBatchRecord.SamFile samRecord = new RootBatchRecord.SamFile();
      samRecord.iin = request.iin;
      samRecord.batch = request.batch;
      samRecord.samId = samId;
      samRecord.samSki = HexUtil.format(KeyIdentifiers.ski(samX509.getPublicKey()));
      samRecord.certificate = Base64.getEncoder().encodeToString(samCertificate);
      samRecord.certificateSha256 = HexUtil.format(IssuanceCrypto.sha256(samCertificate));
      samRecord.allocationSeq = allocationSeq;
      samRecord.registryHead = AllocationRegistry.headHex(bindLine);
      RootBatchRecord.writeSam(request.producer, samRecord);

      hooks.before("bundle");
      SamHandoff.Fields fields = new SamHandoff.Fields();
      fields.producer = request.producer;
      fields.iin = request.iin;
      fields.batch = request.batch;
      fields.samId = samId;
      fields.quota = quota;
      fields.initialTs = parameters.initialTimestamp;
      fields.paramsDigest = parameters.paramsDigest();
      fields.f9ValidityDays = request.f9ValidityDays;
      fields.samCertificate = samCertificate;
      fields.rootCertificate = rootCertificate;
      fields.allocateLine = registry.line(allocationSeq);
      fields.bindLine = bindLine;
      fields.genesis = genesis;
      fields.station = request.station;
      fields.stationSki = stationSki;
      fields.scpKeyVersion = HANDOFF_KEY_VERSION;
      encodedSecret = secret.encode();
      RootKeys.WrappedKey wrapped =
          keys.wrapSecret(encodedSecret, stationPoint, SamHandoff.sharedInfo(samId, stationSki));
      SamHandoff bundle = SamHandoff.sign(fields, wrapped, root);
      bundle.writeNew(request.bundleOut);
      return new Result(request.bundleOut, samId, samCertificate, genesis.entry);
    } finally {
      secret.wipe();
      Arrays.fill(operatorPin, (byte) 0);
      if (encodedSecret != null) {
        Arrays.fill(encodedSecret, (byte) 0);
      }
    }
  }

  /** The genesis entry commits to this SAM certificate, the batch paramsDigest and quota. */
  static void requireGenesis(
      SamLedgerEntry.Signed genesis,
      X509Certificate samX509,
      byte[] samCertificate,
      SamParameters parameters) {
    requireGenesis(
        genesis,
        samX509,
        samCertificate,
        parameters.paramsDigest(),
        parameters.initialQuota,
        parameters.initialTimestamp);
  }

  static void requireGenesis(
      SamLedgerEntry.Signed genesis,
      X509Certificate samX509,
      byte[] samCertificate,
      byte[] paramsDigest,
      long quota,
      long initialTimestamp) {
    SamLedgerEntry entry = genesis.entry;
    if (!genesis.verify(samX509.getPublicKey())) {
      throw new IllegalStateException("The genesis entry signature does not verify");
    }
    if (entry.type != SamLedgerEntry.TYPE_GENESIS
        || entry.eventSeq != 1
        || !Arrays.equals(entry.prevHead(), new byte[32])
        || !Arrays.equals(entry.samSki(), KeyIdentifiers.ski(samX509.getPublicKey()))) {
      throw new IllegalStateException("LOCK did not return the SAM's genesis entry");
    }
    if (!Arrays.equals(entry.samCertificateSha256(), IssuanceCrypto.sha256(samCertificate))) {
      throw new IllegalStateException("The genesis entry commits to a different SAM certificate");
    }
    if (!Arrays.equals(entry.paramsDigest(), paramsDigest)
        || entry.quota != quota
        || entry.timestamp != initialTimestamp) {
      throw new IllegalStateException("The genesis entry commits to different batch parameters");
    }
  }

  /** Sixteen random characters from an unambiguous alphanumeric alphabet. */
  static byte[] randomPin(SecureRandom random) {
    byte[] pin = new byte[16];
    for (int i = 0; i < pin.length; i++) {
      pin[i] = (byte) PIN_ALPHABET[random.nextInt(PIN_ALPHABET.length)];
    }
    return pin;
  }

  private static void install(CardTransport transport, ScpConfig keys, Path cap) throws Exception {
    try (GlobalPlatformSession isd =
        transport.openGlobalPlatformSession(GlobalPlatformSession.ISD_AID, keys)) {
      if (cap != null) {
        GPCommands.load(isd.gp(), CAPFile.fromFile(cap), null, null, GPData.LFDBH.SHA256);
      }
      isd.gp()
          .installAndMakeSelectable(
              new AID(ApduSamClient.SAM_PACKAGE_AID),
              new AID(ApduSamClient.SAM_AID),
              new AID(ApduSamClient.SAM_AID),
              EnumSet.noneOf(GPRegistryEntry.Privilege.class),
              new byte[0]);
    }
  }
}
