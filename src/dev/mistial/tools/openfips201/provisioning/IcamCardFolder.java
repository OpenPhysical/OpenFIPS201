/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ******************************************************************************/

package dev.mistial.tools.openfips201.provisioning;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Loads a GSA ICAM card-builder card folder natively into a {@link ConformancePackage}.
 *
 * <p>Accepts directories such as {@code .../ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV/} without an
 * intermediate package conversion step. File naming follows the ICAM card-builder convention
 * (numbered prefixes for data objects and cert/p12 pairs for key slots), matching the mapping used
 * by OpenPhysical's VirtualPiv ICAM loader.
 *
 * <p>PKCS#12 files in the published ICAM corpus use an empty password; pass a non-empty password
 * via {@link #load(Path, char[])} when consuming custom folders.
 */
public final class IcamCardFolder {

  // Access-mode bits matching PIVObject / SP 800-73 Table 2 defaults used for golden cards.
  public static final byte ACCESS_NEVER = (byte) 0x00;
  public static final byte ACCESS_PIN = (byte) 0x01;
  public static final byte ACCESS_PIN_ALWAYS = (byte) 0x02;
  public static final byte ACCESS_VCI = (byte) 0x08;
  public static final byte ACCESS_ALWAYS = (byte) 0x7F;

  public static final byte ROLE_AUTHENTICATE = (byte) 0x01;
  public static final byte ROLE_KEY_ESTABLISH = (byte) 0x02;
  public static final byte ROLE_SIGN = (byte) 0x04;
  public static final byte ATTR_IMPORTABLE = (byte) 0x10;

  public static final byte ALG_RSA_1024 = (byte) 0x06;
  public static final byte ALG_RSA_2048 = (byte) 0x07;
  public static final byte ALG_ECC_P256 = (byte) 0x11;
  public static final byte ALG_ECC_P384 = (byte) 0x14;

  public static final byte SLOT_PIV_AUTH = (byte) 0x9A;
  public static final byte SLOT_DIGITAL_SIGNATURE = (byte) 0x9C;
  public static final byte SLOT_KEY_MANAGEMENT = (byte) 0x9D;
  public static final byte SLOT_CARD_AUTH = (byte) 0x9E;

  private static final byte[] ID_DISCOVERY = {(byte) 0x7E};
  private static final byte[] ID_CARD_AUTH_CERT = {(byte) 0x5F, (byte) 0xC1, 0x01};
  private static final byte[] ID_CHUID = {(byte) 0x5F, (byte) 0xC1, 0x02};
  private static final byte[] ID_FINGERPRINTS = {(byte) 0x5F, (byte) 0xC1, 0x03};
  private static final byte[] ID_PIV_AUTH_CERT = {(byte) 0x5F, (byte) 0xC1, 0x05};
  private static final byte[] ID_SECURITY_OBJECT = {(byte) 0x5F, (byte) 0xC1, 0x06};
  private static final byte[] ID_CCC = {(byte) 0x5F, (byte) 0xC1, 0x07};
  private static final byte[] ID_FACE = {(byte) 0x5F, (byte) 0xC1, 0x08};
  private static final byte[] ID_PRINTED = {(byte) 0x5F, (byte) 0xC1, 0x09};
  private static final byte[] ID_DIG_SIG_CERT = {(byte) 0x5F, (byte) 0xC1, 0x0A};
  private static final byte[] ID_KEY_MGMT_CERT = {(byte) 0x5F, (byte) 0xC1, 0x0B};

  /** Empty password used by the published GSA ICAM PKCS#12 corpus. */
  public static final char[] DEFAULT_P12_PASSWORD = new char[0];

  private IcamCardFolder() {}

  /** Loads an ICAM card folder with the default empty PKCS#12 password. */
  public static ConformancePackage load(Path directory) throws Exception {
    return load(directory, DEFAULT_P12_PASSWORD);
  }

  /**
   * Loads an ICAM card folder.
   *
   * @param directory path to a single card directory (e.g. {@code 46_Golden_FIPS_201-2_PIV})
   * @param p12Password PKCS#12 password (empty for the published ICAM corpus)
   */
  public static ConformancePackage load(Path directory, char[] p12Password) throws Exception {
    if (directory == null) {
      throw new IllegalArgumentException("ICAM directory is required");
    }
    Path root = directory.toAbsolutePath().normalize();
    if (!Files.isDirectory(root)) {
      throw new IllegalArgumentException("ICAM path is not a directory: " + root);
    }
    ensureProvider();

    List<ConformancePackage.DataObject> objects = new ArrayList<ConformancePackage.DataObject>();
    List<ConformancePackage.KeyMaterial> keys = new ArrayList<ConformancePackage.KeyMaterial>();

    // Data objects (binary containers). Certificates are loaded from the key/cert pairs so the
    // on-card payload is always the SP 800-73 X.509 Certificate container (tags 70/71).
    addRawObject(
        objects,
        root,
        "1 - Discovery Object",
        ID_DISCOVERY,
        "Discovery Object",
        ACCESS_ALWAYS,
        ACCESS_ALWAYS,
        ConformancePackage.PutForm.DISCOVERY,
        null,
        "");
    addRawObject(
        objects,
        root,
        "2 - Security Object",
        ID_SECURITY_OBJECT,
        "Security Object",
        ACCESS_ALWAYS,
        ACCESS_VCI,
        ConformancePackage.PutForm.TAG_LIST,
        null,
        "");
    addRawObject(
        objects,
        root,
        "7 - CCC",
        ID_CCC,
        "Card Capability Container",
        ACCESS_ALWAYS,
        ACCESS_VCI,
        ConformancePackage.PutForm.TAG_LIST,
        null,
        "");
    addRawObject(
        objects,
        root,
        "8 - CHUID Object",
        ID_CHUID,
        "Cardholder Unique Identifier",
        ACCESS_ALWAYS,
        ACCESS_ALWAYS,
        ConformancePackage.PutForm.TAG_LIST,
        null,
        "");
    addRawObject(
        objects,
        root,
        "9 - Fingerprints",
        ID_FINGERPRINTS,
        "Cardholder Fingerprints",
        ACCESS_PIN,
        (byte) (ACCESS_VCI | ACCESS_PIN),
        ConformancePackage.PutForm.TAG_LIST,
        null,
        "");
    addRawObject(
        objects,
        root,
        "10 - Face Object",
        ID_FACE,
        "Cardholder Facial Image",
        ACCESS_PIN,
        (byte) (ACCESS_VCI | ACCESS_PIN),
        ConformancePackage.PutForm.TAG_LIST,
        null,
        "");
    addRawObject(
        objects,
        root,
        "11 - Printed Information",
        ID_PRINTED,
        "Printed Information",
        ACCESS_PIN,
        (byte) (ACCESS_VCI | ACCESS_PIN),
        ConformancePackage.PutForm.TAG_LIST,
        null,
        "");

    // Key slots + matching certificate containers.
    addKeyAndCert(
        objects,
        keys,
        root,
        "3 - ICAM_PIV_Auth",
        SLOT_PIV_AUTH,
        "PIV Authentication",
        ROLE_SIGN,
        ACCESS_PIN,
        (byte) (ACCESS_VCI | ACCESS_PIN),
        ID_PIV_AUTH_CERT,
        "PIV Authentication Certificate",
        p12Password);
    addKeyAndCert(
        objects,
        keys,
        root,
        "4 - ICAM_PIV_Dig_Sig",
        SLOT_DIGITAL_SIGNATURE,
        "Digital Signature",
        ROLE_SIGN,
        ACCESS_PIN_ALWAYS,
        (byte) (ACCESS_VCI | ACCESS_PIN_ALWAYS),
        ID_DIG_SIG_CERT,
        "Digital Signature Certificate",
        p12Password);
    addKeyAndCert(
        objects,
        keys,
        root,
        "5 - ICAM_PIV_Key_Mgmt",
        SLOT_KEY_MANAGEMENT,
        "Key Management",
        ROLE_KEY_ESTABLISH,
        ACCESS_PIN,
        (byte) (ACCESS_VCI | ACCESS_PIN),
        ID_KEY_MGMT_CERT,
        "Key Management Certificate",
        p12Password);
    addKeyAndCert(
        objects,
        keys,
        root,
        "6 - ICAM_PIV_Card_Auth",
        SLOT_CARD_AUTH,
        "Card Authentication",
        ROLE_SIGN,
        ACCESS_ALWAYS,
        ACCESS_ALWAYS,
        ID_CARD_AUTH_CERT,
        "Card Authentication Certificate",
        p12Password);

    if (objects.isEmpty() && keys.isEmpty()) {
      throw new IllegalArgumentException(
          "No ICAM data objects or keys found under " + root + " (expected numbered ICAM files)");
    }

    String credentialId = root.getFileName().toString();
    ConformancePackage result = new ConformancePackage(
        credentialId,
        root,
        StandardCardProfile.PIN,
        StandardCardProfile.PUK,
        StandardCardProfile.ADMIN_KEY_ALG,
        StandardCardProfile.ADMIN_KEY,
        objects,
        keys);

    // The Security Object signs hashes of the exact container bytes written to the card.
    // Reject any reconstruction mismatch before provisioning mutates a card.
    java.util.Map<String, ConformancePackage.DataObject> byId =
        new java.util.HashMap<String, ConformancePackage.DataObject>();
    for (ConformancePackage.DataObject object : objects) {
      byId.put(toHex(object.id), object);
    }
    CertificationProfileValidator.validateSecurityObject(byId);
    return result;
  }

  private static String toHex(byte[] value) {
    StringBuilder result = new StringBuilder(value.length * 2);
    for (byte element : value) result.append(String.format("%02X", element & 0xFF));
    return result.toString();
  }

  private static void addRawObject(
      List<ConformancePackage.DataObject> objects,
      Path root,
      String filePrefix,
      byte[] id,
      String label,
      byte modeContact,
      byte modeContactless,
      ConformancePackage.PutForm putForm,
      String[] preferredTokens,
      String extensionFilter)
      throws IOException {
    Path file = findFile(root, filePrefix, preferredTokens, extensionFilter);
    if (file == null) {
      throw new IllegalArgumentException("Missing required ICAM object: " + filePrefix);
    }
    byte[] payload = Files.readAllBytes(file);
    if (payload.length == 0) {
      throw new IllegalArgumentException("Empty required ICAM object: " + file);
    }
    objects.add(new ConformancePackage.DataObject(id, label, modeContact, modeContactless, putForm, payload));
  }

  private static void addKeyAndCert(
      List<ConformancePackage.DataObject> objects,
      List<ConformancePackage.KeyMaterial> keys,
      Path root,
      String filePrefix,
      byte slot,
      String keyLabel,
      byte role,
      byte modeContact,
      byte modeContactless,
      byte[] certObjectId,
      String certLabel,
      char[] p12Password)
      throws Exception {
    // Prefer the ICAM_Test_Card-named assets when both exist (same preference as VirtualPiv).
    String[] preferred = new String[] {"ICAM_Test_Card"};
    Path p12 = findFile(root, filePrefix, preferred, ".p12");
    Path crt = findFile(root, filePrefix, preferred, ".crt");
    if (p12 == null && crt == null) {
      return;
    }
    if (p12 == null) {
      throw new IllegalArgumentException(
          "Certificate exists without importable key material for " + keyLabel);
    }

    PrivateKey privateKey = null;
    X509Certificate certificate = null;
    if (p12 != null) {
      Pkcs12Entry entry = loadPkcs12(p12, p12Password);
      privateKey = entry.privateKey;
      certificate = entry.certificate;
    }
    if (certificate == null && crt != null) {
      certificate = loadCertificate(crt);
    }
    if (certificate == null) {
      throw new IllegalStateException("No certificate for key slot " + keyLabel + " under " + root);
    }

    // Certificate container payload per SP 800-73 Table 15 / 85B atoms:
    //   70 <X.509 DER>  71 01 00 (uncompressed)  FE 00 (empty error-detection code).
    byte[] certContainer =
        AdminTlv.concat(
            AdminTlv.tlv(0x70, certificate.getEncoded()),
            AdminTlv.tlv(0x71, new byte[] {0x00}),
            AdminTlv.tlv(0xFE, new byte[0]));
    objects.add(
        new ConformancePackage.DataObject(
            certObjectId,
            certLabel,
            ACCESS_ALWAYS,
            slot == SLOT_CARD_AUTH ? ACCESS_ALWAYS : ACCESS_VCI,
            ConformancePackage.PutForm.TAG_LIST,
            certContainer));

    if (privateKey != null) {
      byte algorithm = detectAlgorithm(privateKey);
      keys.add(
          new ConformancePackage.KeyMaterial(
              slot,
              keyLabel,
              algorithm,
              role,
              ATTR_IMPORTABLE,
              modeContact,
              modeContactless,
              privateKey,
              certificate));
    }
  }

  static byte detectAlgorithm(PrivateKey privateKey) {
    if (privateKey instanceof RSAPrivateKey) {
      int bits = ((RSAPrivateKey) privateKey).getModulus().bitLength();
      if (bits <= 1024) {
        return ALG_RSA_1024;
      }
      if (bits <= 2048) {
        return ALG_RSA_2048;
      }
      throw new IllegalArgumentException("Unsupported RSA size for OpenFIPS201 import: " + bits);
    }
    if (privateKey instanceof ECPrivateKey) {
      int fieldBits = ((ECPrivateKey) privateKey).getParams().getCurve().getField().getFieldSize();
      if (fieldBits == 256) {
        return ALG_ECC_P256;
      }
      if (fieldBits == 384) {
        return ALG_ECC_P384;
      }
      throw new IllegalArgumentException("Unsupported ECC field size for OpenFIPS201 import: " + fieldBits);
    }
    throw new IllegalArgumentException(
        "Unsupported private key type: " + privateKey.getClass().getName());
  }

  /**
   * Locates a file whose name starts with {@code filePrefix}, optionally preferring names that
   * contain one of {@code preferredTokens}, and optionally requiring {@code extensionFilter}.
   */
  static Path findFile(
      Path directory, String filePrefix, String[] preferredTokens, String extensionFilter)
      throws IOException {
    List<Path> matches = new ArrayList<Path>();
    try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory)) {
      for (Path entry : stream) {
        if (!Files.isRegularFile(entry)) {
          continue;
        }
        String name = entry.getFileName().toString();
        if (!name.regionMatches(true, 0, filePrefix, 0, filePrefix.length())) {
          continue;
        }
        if (extensionFilter != null
            && !extensionFilter.isEmpty()
            && !name.toLowerCase(Locale.ROOT).endsWith(extensionFilter.toLowerCase(Locale.ROOT))) {
          continue;
        }
        matches.add(entry);
      }
    }
    if (matches.isEmpty()) {
      return null;
    }
    Collections.sort(
        matches,
        new Comparator<Path>() {
          @Override
          public int compare(Path left, Path right) {
            return left.getFileName().toString().compareToIgnoreCase(right.getFileName().toString());
          }
        });
    if (preferredTokens != null) {
      for (String token : preferredTokens) {
        for (Path candidate : matches) {
          if (candidate.getFileName().toString().toLowerCase(Locale.ROOT).contains(token.toLowerCase(Locale.ROOT))) {
            return candidate;
          }
        }
      }
    }
    return matches.get(0);
  }

  static X509Certificate loadCertificate(Path path) throws Exception {
    byte[] bytes = Files.readAllBytes(path);
    // Tolerate PEM (ICAM .crt files) or raw DER.
    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    try {
      return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(bytes));
    } catch (Exception first) {
      // Some PKCS#12 dumps store multiple PEM blocks; extract the first CERTIFICATE.
      String text = new String(bytes, StandardCharsets.US_ASCII);
      int begin = text.indexOf("-----BEGIN CERTIFICATE-----");
      int end = text.indexOf("-----END CERTIFICATE-----");
      if (begin >= 0 && end > begin) {
        String pem = text.substring(begin, end + "-----END CERTIFICATE-----".length());
        return (X509Certificate)
            factory.generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
      }
      throw first;
    }
  }

  static Pkcs12Entry loadPkcs12(Path path, char[] password) throws Exception {
    KeyStore store = KeyStore.getInstance("PKCS12");
    try (InputStream in = Files.newInputStream(path)) {
      store.load(in, password == null ? new char[0] : password);
    }
    Enumeration<String> aliases = store.aliases();
    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement();
      if (!store.isKeyEntry(alias)) {
        continue;
      }
      PrivateKey privateKey = (PrivateKey) store.getKey(alias, password == null ? new char[0] : password);
      java.security.cert.Certificate cert = store.getCertificate(alias);
      if (privateKey != null && cert instanceof X509Certificate) {
        return new Pkcs12Entry(privateKey, (X509Certificate) cert);
      }
    }
    throw new IllegalStateException("PKCS#12 file contains no private key entry: " + path);
  }

  static void ensureProvider() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  static final class Pkcs12Entry {
    final PrivateKey privateKey;
    final X509Certificate certificate;

    Pkcs12Entry(PrivateKey privateKey, X509Certificate certificate) {
      this.privateKey = privateKey;
      this.certificate = certificate;
    }
  }

  /** Exposed for tests: confirms RSA CRT keys are recognised as RSA. */
  static boolean isRsaCrt(PrivateKey key) {
    return key instanceof RSAPrivateCrtKey;
  }
}
