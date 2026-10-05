/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.producer;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.SecureFiles;
import dev.mistial.tools.openfips201.crypto.KeyIdentifiers;
import dev.mistial.tools.openfips201.crypto.SecretSource;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11AdminService;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11Config;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11Session;
import dev.mistial.tools.openfips201.profiles.IssuerProfile;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Map;
import java.util.function.Consumer;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

/**
 * Producer setup, root certificate reissue and destruction.
 *
 * <p>Custody contract:
 *
 * <ul>
 *   <li>{@code pkcs11}: a hardware token selected by {@code --pkcs11-module} and label. The token
 *       must already be initialized; the user PIN is read from an environment variable, an
 *       owner-only file or the console, and only its source is recorded in {@code producer.json}.
 *   <li>{@code softhsm-dev} (requires {@code --dev-softhsm}): a SoftHSM2 token below {@code
 *       ~/.openfips201/softhsm}. An existing token with the producer's label is reused with the
 *       existing {@code pkcs11.pin}; a token without that file is refused. Otherwise the token is
 *       initialized through PKCS#11 ({@code C_InitToken}/{@code C_InitPIN}) with distinct random
 *       16-byte hex SO and user PINs; no PIN reaches a command line. Only after initialization
 *       succeeds is {@code pkcs11.pin} created (0600, never overwritten). The SO PIN is shown once
 *       ({@link Request#soPinDisplay}) or written to {@code --so-pin-out} (0600, never
 *       overwritten), and never stored below the OpenFIPS201 home.
 * </ul>
 *
 * <p>Setup is idempotent: keys that exist are reused ({@link
 * Pkcs11AdminService#ensureRootSigner(Pkcs11Session, String, String, int)}). Every run exports
 * {@code producers/<name>/root.pem} and rewrites {@code producer.json} (schema {@value #SCHEMA})
 * atomically with {@code rootCa.certificateSha256} and {@code rootCa.ski}.
 */
public final class ProducerSetupService {
  public static final String SCHEMA = "openfips201.producer/3";
  public static final String STATION_ROOT = "root";
  public static final String STATION_PRODUCTION = "production";
  public static final String CUSTODY_PKCS11 = "pkcs11";
  public static final String CUSTODY_SOFTHSM_DEV = "softhsm-dev";

  private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
  private static final int PIN_BYTES = 16;
  private static final char[] HEX = "0123456789ABCDEF".toCharArray();

  private final SecureRandom random = new SecureRandom();

  /** Producer setup options. */
  public static final class Request {
    public String name;
    public String module;
    public String tokenLabel;
    public String rootSubject;
    public String f9Subject;
    public boolean devSoftHsm;
    public String pinEnv;
    public String pinFile;
    public Path soPinOut;
    /**
     * Shows a newly initialized token's SO PIN once when {@link #soPinOut} is unset. It is called
     * immediately after initialization, before any key is generated; the array is wiped after it
     * returns.
     */
    public Consumer<char[]> soPinDisplay;

    public int rootValidityDays = Pkcs11AdminService.DEFAULT_ROOT_VALIDITY_DAYS;

    /** {@link #STATION_ROOT} or {@link #STATION_PRODUCTION}. */
    public String station = STATION_ROOT;

    /** Production station: the root station's public {@code root.pem}. */
    public Path rootPem;
  }

  public Result setup(Request request) throws Exception {
    Path producer = ProducerPaths.producer(request.name);
    Path profilePath = ProducerPaths.producerProfile(request.name);
    IssuerProfile existing = Files.exists(profilePath) ? readProfile(profilePath) : null;
    String existingCustody = Files.exists(profilePath) ? readCustody(profilePath) : null;
    String custody = request.devSoftHsm ? CUSTODY_SOFTHSM_DEV : CUSTODY_PKCS11;
    if (existingCustody != null && !existingCustody.equals(custody)) {
      throw new IllegalArgumentException(
          "Producer " + request.name + " uses custody " + existingCustody + ", not " + custody);
    }
    if (existing != null) {
      StationGuard.requireSchema(request.name);
    }
    String station = request.station;
    if (!STATION_ROOT.equals(station) && !STATION_PRODUCTION.equals(station)) {
      throw new IllegalArgumentException("--station must be root or production");
    }
    if (existing != null && !station.equals(StationGuard.station(request.name))) {
      throw new IllegalArgumentException(
          "Producer " + request.name + " is a " + StationGuard.station(request.name) + " station");
    }
    if (STATION_PRODUCTION.equals(station) && request.rootPem == null) {
      throw new IllegalArgumentException("a production station needs --root-pem");
    }
    if (STATION_ROOT.equals(station) && request.rootPem != null) {
      throw new IllegalArgumentException("--root-pem applies only to a production station");
    }
    String tokenLabel =
        firstNonEmpty(
            request.tokenLabel, existing == null ? null : existing.pkcs11.tokenLabel, request.name);
    if (Pkcs11AdminService.DESTROYED_TOKEN_LABEL.equals(tokenLabel)) {
      throw new IllegalArgumentException("PKCS#11 token label is reserved: " + tokenLabel);
    }
    String rootSubject =
        firstNonEmpty(
            request.rootSubject, existing == null ? null : existing.attestation.rootSubject, null);
    String f9Subject =
        firstNonEmpty(
            request.f9Subject, existing == null ? null : existing.attestation.issuerSubject, null);
    if (rootSubject == null && STATION_ROOT.equals(station)) {
      throw new IllegalArgumentException("Root CA subject is required");
    }
    ProducerPaths.createDirectories(producer);

    Pkcs11Config pkcs11 = new Pkcs11Config();
    pkcs11.tokenLabel = tokenLabel;
    Path softhsmConf = null;
    Path soPinPath = null;
    boolean initialized = false;
    if (request.devSoftHsm) {
      if (request.pinEnv != null || request.pinFile != null) {
        throw new IllegalArgumentException(
            "--dev-softhsm manages its own PIN file; --pkcs11-pin-env/--pkcs11-pin-file do not"
                + " apply");
      }
      requireSoPinDestination(request);
      softhsmConf = ensureSoftHsmConfig();
      pkcs11.module =
          firstNonEmpty(
              request.module,
              existing == null ? null : existing.pkcs11.module,
              defaultSoftHsmModule());
      pkcs11.softhsmConfig = softhsmConf.toString();
      Path pinFile = producer.resolve("pkcs11.pin");
      pkcs11.pinFile = pinFile.toString();
      if (Pkcs11AdminService.tokenExists(pkcs11)) {
        if (!Files.exists(pinFile)) {
          throw new IllegalStateException(
              "SoftHSM token "
                  + tokenLabel
                  + " exists but "
                  + pinFile
                  + " is missing; restore the PIN file or run 'openfips201 producer destroy'");
        }
      } else {
        if (Files.exists(pinFile)) {
          throw new IllegalStateException(
              pinFile + " exists but SoftHSM token " + tokenLabel + " was not found");
        }
        if (request.soPinOut == null && request.soPinDisplay == null) {
          throw new IllegalArgumentException(
              "--so-pin-out or a console is required for the new token's SO PIN");
        }
        char[] soPin = initializeSoftHsmToken(pkcs11, pinFile);
        initialized = true;
        try {
          soPinPath = deliverSoPin(request, soPin);
        } finally {
          Arrays.fill(soPin, '\0');
        }
      }
    } else {
      if (request.soPinOut != null) {
        throw new IllegalArgumentException("--so-pin-out applies only with --dev-softhsm");
      }
      pkcs11.module =
          firstNonEmpty(request.module, existing == null ? null : existing.pkcs11.module, null);
      if (pkcs11.module == null) {
        throw new IllegalArgumentException(
            "--pkcs11-module is required; use --dev-softhsm for a development SoftHSM token");
      }
      selectPinSource(pkcs11, request, existing);
      if (!Pkcs11AdminService.tokenExists(pkcs11)) {
        throw new IllegalArgumentException(
            "PKCS#11 token "
                + tokenLabel
                + " was not found; initialize it with the HSM vendor tools first");
      }
      if (!Pkcs11AdminService.userPinInitialized(pkcs11)) {
        throw new IllegalArgumentException("PKCS#11 token " + tokenLabel + " has no user PIN");
      }
    }

    String rootLabel = request.name + "-root-ca";
    String aesLabel = request.name + "-card-master";
    Pkcs11AdminService admin = new Pkcs11AdminService();
    IssuerProfile profile = existing != null ? existing : new IssuerProfile();
    profile.name = request.name;
    profile.pkcs11 = pkcs11.copy();
    Pkcs11AdminService.RootSigner root = null;
    X509Certificate rootCertificate;
    if (STATION_ROOT.equals(station)) {
      // The root station holds the root CA (and, later, the IIN FF1 keys); never card keys.
      try (Pkcs11Session session = Pkcs11Session.open(pkcs11)) {
        root = admin.ensureRootSigner(session, rootLabel, rootSubject, request.rootValidityDays);
      }
      rootCertificate = root.certificate;
      profile.pkcs11.keyAlias = rootLabel;
      profile.pkcs11.keyId = HexUtil.format(root.keyId());
      profile.attestation.rootSubject = rootSubject;
      if (f9Subject != null) {
        profile.attestation.issuerSubject = f9Subject;
      }
      profile.cardKeys.masterKeyAlias = null;
      profile.cardKeys.masterKeyId = null;
      profile.cardKeys.pkcs11 = null;
    } else {
      // The production station holds the card-master key and only the public root certificate.
      rootCertificate = StationGuard.readRootPem(request.rootPem);
      byte[] aesId;
      try (Pkcs11Session session = Pkcs11Session.open(pkcs11)) {
        aesId = admin.ensureAes256Key(session, aesLabel);
      }
      profile.pkcs11.keyAlias = null;
      profile.pkcs11.keyId = null;
      profile.attestation.rootSubject =
          rootCertificate
              .getSubjectX500Principal()
              .getName(javax.security.auth.x500.X500Principal.RFC2253);
      profile.cardKeys.masterKeyAlias = aesLabel;
      profile.cardKeys.masterKeyId = HexUtil.format(aesId);
      profile.cardKeys.pkcs11 = pkcs11.copy();
      profile.cardKeys.pkcs11.keyAlias = aesLabel;
      profile.cardKeys.pkcs11.keyId = HexUtil.format(aesId);
    }
    if (existing == null) {
      profile.receipts.directory = producer.resolve("receipts").toString();
    }
    Path rootPem =
        writeRootArtifacts(producer, profilePath, profile, custody, station, rootCertificate);
    return new Result(
        profilePath,
        softhsmConf,
        pkcs11.module,
        tokenLabel,
        custody,
        initialized,
        root,
        rootPem,
        soPinPath);
  }

  /** Writes the SO PIN to {@code --so-pin-out}, or shows it once; returns the file or null. */
  private static Path deliverSoPin(Request request, char[] soPin) throws IOException {
    if (request.soPinOut == null) {
      request.soPinDisplay.accept(soPin);
      return null;
    }
    byte[] encoded = ascii(soPin, true);
    try {
      return SecureFiles.writeNew(request.soPinOut, encoded);
    } finally {
      Arrays.fill(encoded, (byte) 0);
    }
  }

  /**
   * Issues a new root certificate for the producer's existing root key (same key, root profile with
   * SKI), replaces it on the token, re-exports {@code root.pem} and rewrites {@code producer.json}.
   */
  public Result reissueRootCertificate(String name, int validityDays) throws Exception {
    Path producer = ProducerPaths.producer(name);
    Path profilePath = ProducerPaths.producerProfile(name);
    IssuerProfile profile = requireProfile(name, profilePath);
    StationGuard.requireStation(name, STATION_ROOT);
    String custody = custodyOf(producer, profilePath, profile);
    Pkcs11AdminService.RootSigner root;
    try (Pkcs11Session session = Pkcs11Session.open(profile.pkcs11)) {
      root =
          new Pkcs11AdminService()
              .reissueRootCertificate(session, profile.pkcs11.keyAlias, null, validityDays);
    }
    profile.pkcs11.keyId = HexUtil.format(root.keyId());
    Path rootPem =
        writeRootArtifacts(producer, profilePath, profile, custody, STATION_ROOT, root.certificate);
    return new Result(
        profilePath,
        profile.pkcs11.softhsmConfig == null ? null : Paths.get(profile.pkcs11.softhsmConfig),
        profile.pkcs11.module,
        profile.pkcs11.tokenLabel,
        custody,
        false,
        root,
        rootPem,
        null);
  }

  /**
   * Destroys the producer's token and state. {@code confirmTokenLabel} must equal the token label
   * recorded in {@code producer.json}. The token is erased with {@link
   * Pkcs11AdminService#destroyToken(Pkcs11Config, byte[])} using the SO PIN from {@code soPin};
   * then {@code pkcs11.pin}, {@code root.pem} and {@code producer.json} are deleted. Batches and
   * receipts are kept.
   */
  public Path destroy(String name, String confirmTokenLabel, SecretSource soPin) throws Exception {
    Path producer = ProducerPaths.producer(name);
    Path profilePath = ProducerPaths.producerProfile(name);
    IssuerProfile profile = requireProfile(name, profilePath);
    String tokenLabel = profile.pkcs11.tokenLabel;
    if (tokenLabel == null || !tokenLabel.equals(confirmTokenLabel)) {
      throw new IllegalArgumentException(
          "--confirm-token-label does not match the producer's token label");
    }
    char[] pinChars = soPin.charsOrPrompt("PKCS#11 SO PIN for token " + tokenLabel);
    byte[] pin = null;
    try {
      pin = ascii(pinChars, false);
      Pkcs11AdminService.destroyToken(profile.pkcs11, pin);
    } finally {
      Arrays.fill(pinChars, '\0');
      if (pin != null) {
        Arrays.fill(pin, (byte) 0);
      }
    }
    Files.deleteIfExists(producer.resolve("pkcs11.pin"));
    Files.deleteIfExists(producer.resolve("root.pem"));
    Files.deleteIfExists(profilePath);
    return producer;
  }

  /**
   * Generates distinct SO and user PINs, initializes the token, then creates {@code pinFile} with
   * the user PIN. Returns the SO PIN, owned by the caller.
   */
  private char[] initializeSoftHsmToken(Pkcs11Config pkcs11, Path pinFile) throws IOException {
    char[] userPin = randomHexPin();
    char[] soPin = randomHexPin();
    while (Arrays.equals(userPin, soPin)) {
      Arrays.fill(soPin, '\0');
      soPin = randomHexPin();
    }
    byte[] userBytes = ascii(userPin, false);
    byte[] soBytes = ascii(soPin, false);
    byte[] fileBytes = ascii(userPin, true);
    boolean done = false;
    try {
      Pkcs11AdminService.initializeToken(pkcs11, soBytes, userBytes);
      SecureFiles.writeNew(pinFile, fileBytes);
      done = true;
      return soPin;
    } finally {
      Arrays.fill(userPin, '\0');
      Arrays.fill(userBytes, (byte) 0);
      Arrays.fill(soBytes, (byte) 0);
      Arrays.fill(fileBytes, (byte) 0);
      if (!done) {
        Arrays.fill(soPin, '\0');
      }
    }
  }

  private static void selectPinSource(
      Pkcs11Config pkcs11, Request request, IssuerProfile existing) {
    if (request.pinEnv != null && request.pinFile != null) {
      throw new IllegalArgumentException("Use only one of --pkcs11-pin-env or --pkcs11-pin-file");
    }
    if (request.pinEnv != null) {
      pkcs11.pinEnv = request.pinEnv;
    } else if (request.pinFile != null) {
      pkcs11.pinFile = Paths.get(request.pinFile).toAbsolutePath().toString();
    } else if (existing != null
        && (existing.pkcs11.pinEnv != null
            || existing.pkcs11.pinFile != null
            || existing.pkcs11.pinPrompt)) {
      pkcs11.pinEnv = existing.pkcs11.pinEnv;
      pkcs11.pinFile = existing.pkcs11.pinFile;
      pkcs11.pinPrompt = existing.pkcs11.pinPrompt;
    } else {
      pkcs11.pinPrompt = true;
    }
  }

  /** Validates {@code --so-pin-out}, when given, before any token is touched. */
  private static void requireSoPinDestination(Request request) {
    Path soPinOut = request.soPinOut;
    if (soPinOut == null) {
      return;
    }
    Path home = ProducerPaths.home().toAbsolutePath().normalize();
    if (soPinOut.toAbsolutePath().normalize().startsWith(home)) {
      throw new IllegalArgumentException("--so-pin-out must be outside " + home);
    }
    if (Files.exists(soPinOut)) {
      throw new IllegalArgumentException("--so-pin-out already exists: " + soPinOut);
    }
    Path parent = soPinOut.toAbsolutePath().getParent();
    if (parent == null || !Files.isDirectory(parent)) {
      throw new IllegalArgumentException("--so-pin-out directory does not exist: " + parent);
    }
  }

  private static Path writeRootArtifacts(
      Path producer,
      Path profilePath,
      IssuerProfile profile,
      String custody,
      String station,
      X509Certificate certificate)
      throws Exception {
    Path rootPem = producer.resolve("root.pem");
    StringWriter pem = new StringWriter();
    try (JcaPEMWriter writer = new JcaPEMWriter(pem)) {
      writer.writeObject(certificate);
    }
    SecureFiles.replaceAtomically(rootPem, pem.toString().getBytes(StandardCharsets.US_ASCII));

    JsonObject document = new JsonObject();
    document.addProperty("schema", SCHEMA);
    document.addProperty("station", station);
    document.addProperty("custody", custody);
    for (Map.Entry<String, JsonElement> entry :
        GSON.toJsonTree(profile).getAsJsonObject().entrySet()) {
      document.add(entry.getKey(), entry.getValue());
    }
    JsonObject rootCa = new JsonObject();
    rootCa.addProperty("certificate", rootPem.getFileName().toString());
    rootCa.addProperty(
        "certificateSha256",
        HexUtil.format(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded())));
    rootCa.addProperty("ski", HexUtil.format(KeyIdentifiers.ski(certificate.getPublicKey())));
    document.add("rootCa", rootCa);
    SecureFiles.replaceAtomically(
        profilePath, GSON.toJson(document).getBytes(StandardCharsets.UTF_8));
    return rootPem;
  }

  private static Path ensureSoftHsmConfig() throws IOException {
    Path softhsm = ProducerPaths.home().resolve("softhsm");
    Path tokens = ProducerPaths.createDirectories(softhsm.resolve("tokens"));
    Path conf = softhsm.resolve("softhsm2.conf");
    if (!Files.exists(conf)) {
      String body =
          "directories.tokendir = "
              + tokens.toAbsolutePath()
              + "\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n";
      SecureFiles.writeNew(conf, body.getBytes(StandardCharsets.UTF_8));
    }
    return conf;
  }

  /**
   * Returns the SoftHSM2 module: {@code OPENFIPS201_SOFTHSM_MODULE} when set, else the first of the
   * Homebrew, /usr/local and distribution paths that exists.
   */
  public static String defaultSoftHsmModule() {
    String override = System.getenv("OPENFIPS201_SOFTHSM_MODULE");
    if (override != null && !override.isEmpty()) {
      return override;
    }
    String[] candidates = {
      "/opt/homebrew/lib/softhsm/libsofthsm2.so",
      "/usr/local/lib/softhsm/libsofthsm2.so",
      "/usr/lib/softhsm/libsofthsm2.so",
      "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
      "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
      "/usr/lib64/pkcs11/libsofthsm2.so"
    };
    for (String candidate : candidates) {
      if (Files.exists(Paths.get(candidate))) {
        return candidate;
      }
    }
    return "libsofthsm2.so";
  }

  private static IssuerProfile requireProfile(String name, Path profilePath) throws IOException {
    if (!Files.exists(profilePath)) {
      throw new IllegalArgumentException("Producer does not exist: " + name);
    }
    return readProfile(profilePath);
  }

  private static IssuerProfile readProfile(Path profilePath) throws IOException {
    IssuerProfile profile =
        GSON.fromJson(
            new String(Files.readAllBytes(profilePath), StandardCharsets.UTF_8),
            IssuerProfile.class);
    if (profile == null || profile.pkcs11 == null) {
      throw new IllegalArgumentException("Producer profile is incomplete: " + profilePath);
    }
    return profile;
  }

  private static String readCustody(Path profilePath) throws IOException {
    JsonElement document =
        JsonParser.parseString(new String(Files.readAllBytes(profilePath), StandardCharsets.UTF_8));
    if (document.isJsonObject() && document.getAsJsonObject().has("custody")) {
      return document.getAsJsonObject().get("custody").getAsString();
    }
    return null;
  }

  /**
   * Custody recorded in {@code producer.json}; a schema 1 profile is classified by its PIN file.
   */
  private static String custodyOf(Path producer, Path profilePath, IssuerProfile profile)
      throws IOException {
    String custody = readCustody(profilePath);
    if (custody != null) {
      return custody;
    }
    return producer.resolve("pkcs11.pin").toString().equals(profile.pkcs11.pinFile)
        ? CUSTODY_SOFTHSM_DEV
        : CUSTODY_PKCS11;
  }

  private char[] randomHexPin() {
    byte[] raw = new byte[PIN_BYTES];
    random.nextBytes(raw);
    char[] pin = new char[PIN_BYTES * 2];
    for (int i = 0; i < raw.length; i++) {
      pin[2 * i] = HEX[(raw[i] >> 4) & 0x0F];
      pin[2 * i + 1] = HEX[raw[i] & 0x0F];
    }
    Arrays.fill(raw, (byte) 0);
    return pin;
  }

  /** ASCII bytes of {@code value}, optionally followed by a newline; rejects non-ASCII. */
  private static byte[] ascii(char[] value, boolean newline) {
    byte[] out = new byte[value.length + (newline ? 1 : 0)];
    for (int i = 0; i < value.length; i++) {
      if (value[i] > 0x7E || value[i] < 0x20) {
        Arrays.fill(out, (byte) 0);
        throw new IllegalArgumentException("PIN must be printable ASCII");
      }
      out[i] = (byte) value[i];
    }
    if (newline) {
      out[value.length] = '\n';
    }
    return out;
  }

  private static String firstNonEmpty(String first, String second, String fallback) {
    if (first != null && !first.isEmpty()) {
      return first;
    }
    if (second != null && !second.isEmpty()) {
      return second;
    }
    return fallback;
  }

  public static final class Result {
    public final Path profilePath;
    /** SoftHSM2 configuration, or {@code null} for hardware custody. */
    public final Path softhsmConfig;

    public final String module;
    public final String tokenLabel;
    public final String custody;
    /** Whether this run initialized the token. */
    public final boolean tokenInitialized;

    public final Pkcs11AdminService.RootSigner root;
    public final Path rootCertificate;
    /** File the new token's SO PIN was written to ({@code --so-pin-out}), else {@code null}. */
    public final Path soPinFile;

    Result(
        Path profilePath,
        Path softhsmConfig,
        String module,
        String tokenLabel,
        String custody,
        boolean tokenInitialized,
        Pkcs11AdminService.RootSigner root,
        Path rootCertificate,
        Path soPinFile) {
      this.profilePath = profilePath;
      this.softhsmConfig = softhsmConfig;
      this.module = module;
      this.tokenLabel = tokenLabel;
      this.custody = custody;
      this.tokenInitialized = tokenInitialized;
      this.root = root;
      this.rootCertificate = rootCertificate;
      this.soPinFile = soPinFile;
    }
  }
}
