/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

import com.sun.jna.NativeLong;
import dev.mistial.tools.openfips201.crypto.CryptoProviders;
import dev.mistial.tools.openfips201.crypto.KeyIdentifiers;
import dev.mistial.tools.openfips201.crypto.SigningKey;
import dev.mistial.tools.openfips201.crypto.SigningKeyContentSigner;
import dev.mistial.tools.openfips201.opid.OpidCipher;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Producer key management on a PKCS#11 token.
 *
 * <p>Root CA profile (checked by {@link #checkRootProfile(X509Certificate, PublicKey)}): X.509 v3,
 * self-signed with ecdsa-with-SHA256; basicConstraints critical, cA TRUE, no pathLenConstraint;
 * keyUsage critical, exactly keyCertSign and cRLSign; subjectKeyIdentifier non-critical, equal to
 * RFC 7093 method 1 of the public key ({@link KeyIdentifiers#ski(PublicKey)}); serial number a
 * random positive integer of at most 128 bits.
 */
public final class Pkcs11AdminService {
  public static final int DEFAULT_ROOT_VALIDITY_DAYS = 7300;

  private static final int KEY_ID_LENGTH = 8;
  private static final int SERIAL_BITS = 128;
  private static final long DAY_MILLIS = 24L * 60L * 60L * 1000L;

  /** Label given to a token by {@link #destroyToken(Pkcs11Config, byte[])}. */
  public static final String DESTROYED_TOKEN_LABEL = "openfips201-destroyed";

  private final SecureRandom random = new SecureRandom();

  /**
   * Reports whether the module named by {@code config} has an initialized token labelled {@code
   * config.tokenLabel}; more than one such token fails.
   */
  public static boolean tokenExists(Pkcs11Config config) {
    return Pkcs11Token.findInitializedTokenSlot(Pkcs11Token.load(config), requireLabel(config))
        != null;
  }

  /**
   * Reports whether the initialized token labelled {@code config.tokenLabel} has its user PIN set
   * ({@code CKF_USER_PIN_INITIALIZED}).
   *
   * @throws IllegalArgumentException when no such token exists
   */
  public static boolean userPinInitialized(Pkcs11Config config) {
    CryptokiLibrary library = Pkcs11Token.load(config);
    return (Pkcs11Token.tokenFlags(library, requireTokenSlot(library, config))
            & Pkcs11Constants.CKF_USER_PIN_INITIALIZED)
        != 0;
  }

  /**
   * Initializes a new token labelled {@code config.tokenLabel} in the first slot with an
   * uninitialized token: {@code C_InitToken(soPin)}, then SO login and {@code C_InitPIN(userPin)}.
   * Fails, before any token is changed, when a token with that label is already initialized, when
   * the PINs are equal, or when no uninitialized token is present. Both PIN arrays remain owned by
   * the caller.
   */
  public static void initializeToken(Pkcs11Config config, byte[] soPin, byte[] userPin) {
    String label = requireLabel(config);
    Pkcs11Token.paddedLabel(label);
    if (Arrays.equals(soPin, userPin)) {
      throw new IllegalArgumentException("PKCS#11 SO PIN and user PIN must differ");
    }
    CryptokiLibrary library = Pkcs11Token.load(config);
    if (Pkcs11Token.findInitializedTokenSlot(library, label) != null) {
      throw new IllegalStateException("PKCS#11 token is already initialized: " + label);
    }
    NativeLong free = Pkcs11Token.findUninitializedTokenSlot(library);
    if (free == null) {
      throw new IllegalStateException("PKCS#11 module has no uninitialized token");
    }
    Pkcs11Token.initToken(library, free, soPin, userPin, label);
  }

  /**
   * Erases the initialized token labelled {@code config.tokenLabel}: {@code C_InitToken} with its
   * current SO PIN destroys every object and the user PIN, and relabels the token {@link
   * #DESTROYED_TOKEN_LABEL}. {@code soPin} remains owned by the caller.
   */
  public static void destroyToken(Pkcs11Config config, byte[] soPin) {
    CryptokiLibrary library = Pkcs11Token.load(config);
    Pkcs11Token.reinitializeToken(
        library, requireTokenSlot(library, config), soPin, DESTROYED_TOKEN_LABEL);
  }

  private static NativeLong requireTokenSlot(CryptokiLibrary library, Pkcs11Config config) {
    NativeLong slot = Pkcs11Token.findInitializedTokenSlot(library, requireLabel(config));
    if (slot == null) {
      throw new IllegalArgumentException("PKCS#11 token label was not found: " + config.tokenLabel);
    }
    return slot;
  }

  private static String requireLabel(Pkcs11Config config) {
    if (config.tokenLabel == null || config.tokenLabel.isEmpty()) {
      throw new IllegalArgumentException("PKCS#11 token label is required");
    }
    return config.tokenLabel;
  }

  /**
   * Ensures the token holds one root CA key pair labelled {@code label} with a certificate in the
   * root profile, and returns it.
   *
   * <ul>
   *   <li>Key and certificate exist: the certificate is checked against the root profile, the
   *       token's public key and {@code subjectName} (when given), and returned unchanged.
   *   <li>Key exists, certificate missing: a root certificate is created for the existing key.
   *   <li>Neither exists: a P-256 key pair is generated, then its root certificate.
   *   <li>More than one key, or more than one certificate for the key's CKA_ID: fails.
   * </ul>
   */
  public RootSigner ensureRootSigner(
      Pkcs11Session session, String label, String subjectName, int validityDays) throws Exception {
    Pkcs11Token token = session.token();
    List<Pkcs11Token.KeyHandle> keys = token.findEcPrivateKeys(label);
    if (keys.size() > 1) {
      throw new IllegalStateException("PKCS#11 token holds multiple root keys labelled " + label);
    }
    if (keys.isEmpty()) {
      byte[] id = randomBytes(KEY_ID_LENGTH);
      Pkcs11Token.KeyHandle key = token.generateEcP256KeyPair(label, id);
      PublicKey publicKey = token.publicKey(label, id);
      X509Certificate certificate =
          storeRootCertificate(token, key, publicKey, subjectName, validityDays);
      return new RootSigner(certificate, id, RootSigner.Outcome.KEY_GENERATED);
    }
    Pkcs11Token.KeyHandle key = keys.get(0);
    byte[] id = requireId(key);
    PublicKey publicKey = token.publicKey(label, id);
    List<NativeLong> certificates = token.findCertificates(id);
    if (certificates.size() > 1) {
      throw new IllegalStateException(
          "PKCS#11 token holds multiple certificates for root key " + label);
    }
    if (certificates.isEmpty()) {
      X509Certificate certificate =
          storeRootCertificate(token, key, publicKey, subjectName, validityDays);
      return new RootSigner(certificate, id, RootSigner.Outcome.CERTIFICATE_CREATED);
    }
    X509Certificate certificate = parseCertificate(token.value(certificates.get(0)));
    checkRootProfile(certificate, publicKey);
    if (subjectName != null
        && !X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded())
            .equals(new X500Name(subjectName))) {
      throw new IllegalStateException(
          "Root CA certificate subject on the token is "
              + certificate.getSubjectX500Principal().getName()
              + ", not "
              + subjectName);
    }
    return new RootSigner(certificate, id, RootSigner.Outcome.EXISTING);
  }

  /**
   * Replaces the certificate of the existing root key labelled {@code label} with a new root
   * certificate for the same key. The subject is {@code subjectName}, or the current certificate's
   * subject when {@code subjectName} is null. The new certificate is signed before any token object
   * is changed; the old certificate objects are then destroyed and the new one stored.
   */
  public RootSigner reissueRootCertificate(
      Pkcs11Session session, String label, String subjectName, int validityDays) throws Exception {
    Pkcs11Token token = session.token();
    List<Pkcs11Token.KeyHandle> keys = token.findEcPrivateKeys(label);
    if (keys.size() != 1) {
      throw new IllegalStateException(
          "PKCS#11 token must hold exactly one root key labelled "
              + label
              + "; found "
              + keys.size());
    }
    Pkcs11Token.KeyHandle key = keys.get(0);
    byte[] id = requireId(key);
    PublicKey publicKey = token.publicKey(label, id);
    List<NativeLong> existing = token.findCertificates(id);
    X500Name subject;
    if (subjectName != null) {
      subject = new X500Name(subjectName);
    } else if (existing.size() == 1) {
      subject =
          X500Name.getInstance(
              parseCertificate(token.value(existing.get(0)))
                  .getSubjectX500Principal()
                  .getEncoded());
    } else {
      throw new IllegalArgumentException("Root CA subject is required");
    }
    X509Certificate certificate =
        createRootCertificate(new TokenSigningKey(token, key, publicKey), subject, validityDays);
    for (NativeLong object : existing) {
      token.destroyObject(object);
    }
    storeCertificate(token, key, certificate);
    return new RootSigner(certificate, id, RootSigner.Outcome.CERTIFICATE_REISSUED);
  }

  /** Token label of the FF1 key of {@code iin}: {@code <prefix>-iin-IIII-fpe}. */
  public static String iinFpeKeyLabel(String prefix, int iin) {
    if (iin < 0 || iin > 9999) {
      throw new IllegalArgumentException("IIN must be 0..9999");
    }
    return prefix + String.format(java.util.Locale.ROOT, "-iin-%04d-fpe", iin);
  }

  /**
   * Ensures the (root) token holds the FF1 key of {@code iin} and returns it.
   *
   * <p>The key is CKK_AES, 32 bytes, token-resident, private, sensitive, {@code CKA_EXTRACTABLE}
   * true (it leaves the token only wrapped), {@code CKA_ENCRYPT} true and no other usage; label
   * {@link #iinFpeKeyLabel(String, int)}; CKA_ID = its KCV ({@link OpidCipher#kcv()}, computed
   * through the token). An existing key is reused after its CKA_ID is checked against the KCV
   * recomputed through the token. More than one key with the label fails.
   */
  public IinFpeKey ensureIinFpeKey(Pkcs11Session session, String prefix, int iin) {
    String label = iinFpeKeyLabel(prefix, iin);
    Pkcs11Token token = session.token();
    List<Pkcs11Token.KeyHandle> keys = token.findAesKeys(label);
    if (keys.size() > 1) {
      throw new IllegalStateException("PKCS#11 token holds multiple keys labelled " + label);
    }
    if (keys.size() == 1) {
      byte[] kcv = tokenKcv(session, label);
      if (!Arrays.equals(kcv, keys.get(0).id)) {
        throw new IllegalStateException("FF1 key " + label + " CKA_ID is not its key check value");
      }
      return new IinFpeKey(label, iin, kcv, false);
    }
    Pkcs11Token.KeyHandle key =
        token.generateWrappableAesKey(label, randomBytes(KEY_ID_LENGTH), OpidCipher.KEY_LENGTH);
    byte[] kcv;
    try {
      kcv = tokenKcv(session, label);
      token.setId(key.handle, kcv);
    } catch (RuntimeException e) {
      token.destroyQuietly(key.handle);
      throw e;
    }
    return new IinFpeKey(label, iin, kcv, true);
  }

  /**
   * Imports {@code key} (32 bytes) as the FF1 key of {@code iin} with the attributes of {@link
   * #ensureIinFpeKey(Pkcs11Session, String, int)}. The KCV recomputed through the token must equal
   * both {@code expectedKcv} and the KCV of {@code key}; otherwise the imported object is destroyed
   * and the import fails. Refused when a key with the label exists. {@code key} stays owned by the
   * caller.
   */
  public IinFpeKey importIinFpeKey(
      Pkcs11Session session, String prefix, int iin, byte[] key, byte[] expectedKcv) {
    if (key == null || key.length != OpidCipher.KEY_LENGTH) {
      throw new IllegalArgumentException("FF1 key must be 32 bytes");
    }
    String label = iinFpeKeyLabel(prefix, iin);
    Pkcs11Token token = session.token();
    if (!token.findAesKeys(label).isEmpty()) {
      throw new IllegalStateException("PKCS#11 token already holds " + label);
    }
    OpidCipher software = OpidCipher.of(key);
    byte[] softwareKcv;
    try {
      softwareKcv = software.kcv();
    } finally {
      software.destroy();
    }
    if (expectedKcv == null || !Arrays.equals(softwareKcv, expectedKcv)) {
      throw new IllegalArgumentException("FF1 key does not match its recorded key check value");
    }
    Pkcs11Token.KeyHandle imported = token.importWrappableAesKey(label, softwareKcv, key);
    try {
      if (!Arrays.equals(tokenKcv(session, label), softwareKcv)) {
        throw new IllegalStateException("imported FF1 key fails its key check value on the token");
      }
    } catch (RuntimeException e) {
      token.destroyQuietly(imported.handle);
      throw e;
    }
    return new IinFpeKey(label, iin, softwareKcv, true);
  }

  /** Labels of every AES secret key on the session's token (for station guards). */
  public static List<String> aesKeyLabels(Pkcs11Session session) {
    return session.token().aesKeyLabels();
  }

  /**
   * Whether the session's token holds an EC private key labelled {@code label} (station guards).
   */
  public static boolean hasEcPrivateKey(Pkcs11Session session, String label) {
    return !session.token().findEcPrivateKeys(label).isEmpty();
  }

  /** Points of every EC public key on the session's token (for station guards). */
  public static List<byte[]> ecPublicPoints(Pkcs11Session session) {
    return session.token().ecPublicPoints();
  }

  /** {@link OpidCipher} running FF1 through the token key labelled {@code label}. */
  public static OpidCipher iinCipher(Pkcs11Session session, String label) {
    return OpidCipher.of(session.aesBlock(label));
  }

  /**
   * Ensures the token holds one P-256 ECDH key pair labelled {@code label} (private key sensitive,
   * non-extractable, derive only) and returns its uncompressed public point.
   */
  public byte[] ensureEcdhKey(Pkcs11Session session, String label) {
    Pkcs11Token token = session.token();
    List<Pkcs11Token.KeyHandle> keys = token.findEcPrivateKeys(label);
    if (keys.size() > 1) {
      throw new IllegalStateException("PKCS#11 token holds multiple EC keys labelled " + label);
    }
    if (keys.isEmpty()) {
      token.generateEcP256KeyPair(label, randomBytes(KEY_ID_LENGTH), true);
    }
    List<NativeLong> publicKeys = token.findEcPublicKeys(label);
    if (publicKeys.size() != 1) {
      throw new IllegalStateException(
          "PKCS#11 token must hold one EC public key labelled " + label);
    }
    return token.ecPoint(publicKeys.get(0));
  }

  /**
   * Returns the value of the one CKO_DATA object with {@code label} and {@code application}, or
   * {@code null} when there is none; more than one fails.
   */
  public static byte[] readData(Pkcs11Session session, String label, String application) {
    List<NativeLong> objects = session.token().findData(label, application);
    if (objects.size() > 1) {
      throw new IllegalStateException("PKCS#11 token holds multiple data objects " + label);
    }
    return objects.isEmpty() ? null : session.token().value(objects.get(0));
  }

  /**
   * Creates or replaces the value of the one CKO_DATA object with {@code label} and {@code
   * application} (token-resident, private).
   */
  public static void writeData(
      Pkcs11Session session, String label, String application, byte[] value) {
    Pkcs11Token token = session.token();
    List<NativeLong> objects = token.findData(label, application);
    if (objects.size() > 1) {
      throw new IllegalStateException("PKCS#11 token holds multiple data objects " + label);
    }
    if (objects.isEmpty()) {
      token.createData(label, application, value);
    } else {
      token.updateData(objects.get(0), label, application, value);
    }
  }

  private static byte[] tokenKcv(Pkcs11Session session, String label) {
    return OpidCipher.of(session.aesBlock(label)).kcv();
  }

  /** FF1 key of one IIN on the token. */
  public static final class IinFpeKey {
    public final String label;
    public final int iin;
    /** Whether this call created (generated or imported) the key. */
    public final boolean created;

    private final byte[] kcv;

    IinFpeKey(String label, int iin, byte[] kcv, boolean created) {
      this.label = label;
      this.iin = iin;
      this.kcv = kcv.clone();
      this.created = created;
    }

    /** {@link OpidCipher#kcv()} of the key, 16 bytes; also its CKA_ID. */
    public byte[] kcv() {
      return kcv.clone();
    }
  }

  /**
   * Ensures the token holds one AES-256 key labelled {@code label}, generating it when absent, and
   * returns its CKA_ID. More than one key with the label fails.
   */
  public byte[] ensureAes256Key(Pkcs11Session session, String label) {
    Pkcs11Token token = session.token();
    List<Pkcs11Token.KeyHandle> keys = token.findAesKeys(label);
    if (keys.size() > 1) {
      throw new IllegalStateException("PKCS#11 token holds multiple AES keys labelled " + label);
    }
    if (keys.size() == 1) {
      return requireId(keys.get(0));
    }
    byte[] id = randomBytes(KEY_ID_LENGTH);
    token.generateAesKey(label, id, 32);
    return id;
  }

  /**
   * Fails unless {@code certificate} is in the root profile (see the class contract) for {@code
   * publicKey}.
   */
  public static void checkRootProfile(X509Certificate certificate, PublicKey publicKey)
      throws Exception {
    CryptoProviders.ensureBouncyCastle();
    if (!Arrays.equals(certificate.getPublicKey().getEncoded(), publicKey.getEncoded())) {
      throw rootProfile("its public key is not the token's root key");
    }
    if (certificate.getVersion() != 3
        || !Arrays.equals(
            certificate.getSubjectX500Principal().getEncoded(),
            certificate.getIssuerX500Principal().getEncoded())) {
      throw rootProfile("it is not a self-issued v3 certificate");
    }
    try {
      certificate.verify(publicKey, BouncyCastleProvider.PROVIDER_NAME);
    } catch (java.security.GeneralSecurityException e) {
      throw rootProfile("its self-signature does not verify");
    }
    Set<String> critical = certificate.getCriticalExtensionOIDs();
    if (critical == null
        || !critical.contains(Extension.basicConstraints.getId())
        || certificate.getBasicConstraints() != Integer.MAX_VALUE) {
      throw rootProfile("basicConstraints is not critical cA TRUE without pathLenConstraint");
    }
    boolean[] usage = certificate.getKeyUsage();
    if (!critical.contains(Extension.keyUsage.getId()) || usage == null || !rootKeyUsage(usage)) {
      throw rootProfile("keyUsage is not critical keyCertSign and cRLSign");
    }
    Extension ski =
        new X509CertificateHolder(certificate.getEncoded())
            .getExtension(Extension.subjectKeyIdentifier);
    if (ski == null
        || ski.isCritical()
        || !Arrays.equals(
            SubjectKeyIdentifier.getInstance(ski.getParsedValue()).getKeyIdentifier(),
            KeyIdentifiers.ski(publicKey))) {
      throw rootProfile("subjectKeyIdentifier is missing or is not RFC 7093 method 1");
    }
  }

  /**
   * Builds a root-profile certificate for {@code signer}'s public key, signed by {@code signer}.
   */
  X509Certificate createRootCertificate(SigningKey signer, X500Name subject, int validityDays)
      throws Exception {
    if (validityDays <= 0) {
      throw new IllegalArgumentException("Root CA validity must be at least one day");
    }
    CryptoProviders.ensureBouncyCastle();
    PublicKey publicKey = signer.publicKey();
    Date notBefore = new Date();
    Date notAfter = new Date(notBefore.getTime() + validityDays * DAY_MILLIS);
    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            subject, randomSerial(), notBefore, notAfter, subject, publicKey);
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    builder.addExtension(
        Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
    builder.addExtension(
        Extension.subjectKeyIdentifier, false, KeyIdentifiers.subjectKeyIdentifier(publicKey));
    X509CertificateHolder holder = builder.build(SigningKeyContentSigner.sha256(signer));
    X509Certificate certificate =
        new JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getCertificate(holder);
    checkRootProfile(certificate, publicKey);
    return certificate;
  }

  private X509Certificate storeRootCertificate(
      Pkcs11Token token,
      Pkcs11Token.KeyHandle key,
      PublicKey publicKey,
      String subjectName,
      int validityDays)
      throws Exception {
    if (subjectName == null || subjectName.isEmpty()) {
      throw new IllegalArgumentException("Root CA subject is required");
    }
    X509Certificate certificate =
        createRootCertificate(
            new TokenSigningKey(token, key, publicKey), new X500Name(subjectName), validityDays);
    storeCertificate(token, key, certificate);
    return certificate;
  }

  private static void storeCertificate(
      Pkcs11Token token, Pkcs11Token.KeyHandle key, X509Certificate certificate) throws Exception {
    token.createCertificate(
        key.label,
        key.id,
        certificate.getSubjectX500Principal().getEncoded(),
        certificate.getIssuerX500Principal().getEncoded(),
        new ASN1Integer(certificate.getSerialNumber()).getEncoded(),
        certificate.getEncoded());
  }

  private BigInteger randomSerial() {
    BigInteger serial;
    do {
      serial = new BigInteger(SERIAL_BITS, random);
    } while (serial.signum() <= 0);
    return serial;
  }

  private byte[] randomBytes(int length) {
    byte[] value = new byte[length];
    random.nextBytes(value);
    return value;
  }

  private static boolean rootKeyUsage(boolean[] usage) {
    for (int bit = 0; bit < usage.length; bit++) {
      boolean expected = bit == 5 || bit == 6;
      if (usage[bit] != expected) {
        return false;
      }
    }
    return usage.length > 6;
  }

  private static byte[] requireId(Pkcs11Token.KeyHandle key) {
    if (key.id == null || key.id.length == 0) {
      throw new IllegalStateException("PKCS#11 key " + key.label + " has no CKA_ID");
    }
    return key.id.clone();
  }

  private static IllegalStateException rootProfile(String reason) {
    return new IllegalStateException(
        "Root CA certificate does not match the root profile: "
            + reason
            + "; run 'openfips201 producer root reissue-certificate'");
  }

  public static X509Certificate parseCertificate(byte[] der) throws Exception {
    return (X509Certificate)
        CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
  }

  /** Root CA key and certificate on the token. */
  public static final class RootSigner {
    public enum Outcome {
      EXISTING,
      CERTIFICATE_CREATED,
      KEY_GENERATED,
      CERTIFICATE_REISSUED
    }

    public final X509Certificate certificate;
    public final Outcome outcome;
    private final byte[] keyId;

    RootSigner(X509Certificate certificate, byte[] keyId, Outcome outcome) {
      this.certificate = certificate;
      this.keyId = keyId.clone();
      this.outcome = outcome;
    }

    /** CKA_ID shared by the root key pair and its certificate. */
    public byte[] keyId() {
      return keyId.clone();
    }
  }

  /** The root private key, signing on the caller's session. */
  private static final class TokenSigningKey implements SigningKey {
    private final Pkcs11Token token;
    private final Pkcs11Token.KeyHandle key;
    private final PublicKey publicKey;

    TokenSigningKey(Pkcs11Token token, Pkcs11Token.KeyHandle key, PublicKey publicKey) {
      this.token = token;
      this.key = key;
      this.publicKey = publicKey;
    }

    @Override
    public PublicKey publicKey() {
      return publicKey;
    }

    @Override
    public byte[] sign(String jcaAlgorithm, byte[] message) throws Exception {
      if (!"SHA256withECDSA".equals(jcaAlgorithm)) {
        throw new IllegalArgumentException("Root CA key signs with SHA256withECDSA only");
      }
      byte[] raw =
          token.sign(
              Pkcs11Constants.CKM_ECDSA, key, MessageDigest.getInstance("SHA-256").digest(message));
      return Pkcs11SigningKey.derEncodeEcdsa(raw, 32);
    }

    @Override
    public String description() {
      return "pkcs11:" + key.label;
    }
  }
}
