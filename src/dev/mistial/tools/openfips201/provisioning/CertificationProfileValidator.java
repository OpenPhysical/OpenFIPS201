/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.provisioning;

import dev.mistial.tools.openfips201.common.HexUtil;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.icao.DataGroupHash;
import org.bouncycastle.asn1.icao.LDSSecurityObject;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;

/** Preflight checks for the frozen SP 800-73-5 Part 1 certification profile. */
public final class CertificationProfileValidator {
  private static final byte ACCESS_PIN = (byte) 0x01;
  private static final byte ACCESS_PIN_ALWAYS = (byte) 0x02;
  private static final byte ACCESS_VCI = (byte) 0x08;
  private static final byte ACCESS_ALWAYS = (byte) 0x7F;
  // SP 800-73-5 Part 1 Section 3.3.2, first byte of the PIN Usage Policy: bit 6 Global PIN, bit 5
  // OCC, bit 4 VCI, and bit 3 "set to one if a VCI is established without a pairing code".
  private static final int PIN_POLICY_GLOBAL_PIN = 0x20;
  private static final int PIN_POLICY_OCC = 0x10;
  private static final int PIN_POLICY_VCI = 0x08;
  private static final int PIN_POLICY_VCI_WITHOUT_PAIRING = 0x04;
  // "Table 1 lists the acceptable values for the first byte of the PIN Usage Policy".
  private static final int[] TABLE_1_FIRST_BYTES = {
    0x40, 0x48, 0x4C, 0x50, 0x58, 0x5C, 0x60, 0x68, 0x6C, 0x70, 0x78, 0x7C
  };
  private static final String[] MANDATORY = {
    "5FC107", "5FC102", "5FC105", "5FC101", "5FC103", "5FC108", "5FC106"
  };
  private static final ASN1ObjectIdentifier ID_PIV_CHUID_SECURITY_OBJECT =
      new ASN1ObjectIdentifier("2.16.840.1.101.3.6.1");
  private static final ASN1ObjectIdentifier ID_PIV_SIGNER_DN =
      new ASN1ObjectIdentifier("2.16.840.1.101.3.6.5");
  private static final ASN1ObjectIdentifier ID_ICAO_LDS_SECURITY_OBJECT =
      new ASN1ObjectIdentifier("1.3.27.1.1.1");

  /** Frozen issuer claims that affect which Part 1 objects are required. */
  public static final class Claims {
    public final boolean governmentEmail;
    public final boolean vci;
    public final boolean pairingRequired;
    public final boolean globalPin;

    /** Claims for a card whose Global PIN is not enabled. */
    public Claims(boolean governmentEmail, boolean vci, boolean pairingRequired) {
      this(governmentEmail, vci, pairingRequired, false);
    }

    /**
     * @param globalPin whether the applet configuration enables the Global PIN, which Discovery may
     *     then advertise
     */
    public Claims(
        boolean governmentEmail, boolean vci, boolean pairingRequired, boolean globalPin) {
      this.governmentEmail = governmentEmail;
      this.vci = vci;
      this.pairingRequired = pairingRequired;
      this.globalPin = globalPin;
    }
  }

  private CertificationProfileValidator() {}

  /** Returns the fixed card allocation required by SP 800-73-5 Part 1 Table 8. */
  static int requiredCapacity(byte[] objectId, int payloadLength) {
    String id = hex(objectId);
    int minimum;
    if (id.equals("5FC107")) minimum = 170;
    else if (id.equals("5FC102")) minimum = 2881;
    else if (id.equals("5FC105")
        || id.equals("5FC101")
        || id.equals("5FC10A")
        || id.equals("5FC10B")) minimum = 1857;
    else if (id.equals("5FC103")) minimum = 4006;
    else if (id.equals("5FC106")) minimum = 1336;
    else if (id.equals("5FC108")) minimum = 12710;
    else if (id.equals("5FC109")) minimum = 245;
    else if (id.equals("5FC10C")) minimum = 128;
    else if (id.length() == 6
        && Integer.parseInt(id.substring(4), 16) >= 0x0D
        && Integer.parseInt(id.substring(4), 16) <= 0x20) minimum = 1895;
    else if (id.equals("5FC121")) minimum = 7106;
    else if (id.equals("7F61")) minimum = 65;
    else if (id.equals("5FC122")) minimum = 2471;
    else if (id.equals("7E")) minimum = 19;
    else if (id.equals("5FC123")) minimum = 12;
    else minimum = payloadLength;
    int storedLength =
        isRawPutObject(id) ? payloadLength : payloadLength + berHeaderLength(payloadLength);
    return Math.max(minimum, storedLength);
  }

  private static boolean isRawPutObject(String id) {
    return id.equals("7E") || id.equals("7F61");
  }

  private static int berHeaderLength(int payloadLength) {
    if (payloadLength < 0x80) return 2; // tag 53 + one-byte length
    if (payloadLength <= 0xFF) return 3; // tag 53 + 81 LL
    return 4; // tag 53 + 82 LL LL
  }

  /**
   * Validates issuer inputs before the irreversible personalization transition.
   *
   * <p>This validates both CMS signatures using the single content-signing certificate carried in
   * the CHUID, plus the Security Object mapping and LDS hashes. The applet does not verify issuer
   * signatures at runtime; this host preflight does so before personalization.
   */
  public static void validate(ConformancePackage pkg, Claims claims) throws Exception {
    if (pkg == null || claims == null)
      throw new IllegalArgumentException("package and claims are required");
    Map<String, ConformancePackage.DataObject> objects = index(pkg);
    for (String id : MANDATORY) require(objects, id);
    if (claims.governmentEmail) {
      require(objects, "5FC10A");
      require(objects, "5FC10B");
    }
    validateDiscovery(objects, claims);
    validateKeys(pkg, claims);
    validateKeyBindings(pkg, objects);
    validateAccessModes(pkg);
    for (Map.Entry<String, ConformancePackage.DataObject> entry : objects.entrySet()) {
      validateContainer(entry.getKey(), entry.getValue().payload);
    }
    validateSecurityObject(objects, true);
    if (objects.containsKey("5FC122")) {
      validateSmSignerUsage(objects.get("5FC122").payload, objects.get("5FC102").payload);
    }
  }

  /** Rejects issuer packages whose ACRs contradict Part 1 Tables 2 and 5. */
  static void validateAccessModes(ConformancePackage pkg) {
    for (ConformancePackage.DataObject object : pkg.dataObjects) {
      String id = hex(object.id);
      byte contact = ACCESS_ALWAYS;
      byte contactless = ACCESS_VCI;
      if (id.equals("5FC102")
          || id.equals("5FC101")
          || id.equals("7E")
          || id.equals("7F61")
          || id.equals("5FC122")) {
        contactless = ACCESS_ALWAYS;
      } else if (id.equals("5FC103")
          || id.equals("5FC108")
          || id.equals("5FC109")
          || id.equals("5FC121")
          || id.equals("5FC123")) {
        contact = ACCESS_PIN;
        contactless = (byte) (ACCESS_VCI | ACCESS_PIN);
      }
      requireAccess(id, object.modeContact, object.modeContactless, contact, contactless);
    }
    for (ConformancePackage.KeyMaterial key : pkg.keys) {
      byte contact;
      byte contactless;
      if ((key.slot & 0xFF) == 0x9E) {
        contact = ACCESS_ALWAYS;
        contactless = ACCESS_ALWAYS;
      } else if ((key.slot & 0xFF) == 0x9C) {
        contact = ACCESS_PIN_ALWAYS;
        contactless = (byte) (ACCESS_VCI | ACCESS_PIN_ALWAYS);
      } else {
        contact = ACCESS_PIN;
        contactless = (byte) (ACCESS_VCI | ACCESS_PIN);
      }
      requireAccess(
          String.format("key %02X", key.slot & 0xFF),
          key.modeContact,
          key.modeContactless,
          contact,
          contactless);
    }
  }

  private static void requireAccess(
      String label, byte actualContact, byte actualContactless, byte contact, byte contactless) {
    if (actualContact != contact || actualContactless != contactless) {
      throw new IllegalArgumentException(
          label + " access modes contradict SP 800-73-5 Part 1 Tables 2/5");
    }
  }

  private static Map<String, ConformancePackage.DataObject> index(ConformancePackage pkg) {
    Map<String, ConformancePackage.DataObject> result =
        new HashMap<String, ConformancePackage.DataObject>();
    for (ConformancePackage.DataObject object : pkg.dataObjects) {
      String id = hex(object.id);
      if (result.put(id, object) != null)
        throw new IllegalArgumentException("duplicate object " + id);
    }
    return result;
  }

  private static void validateKeys(ConformancePackage pkg, Claims claims) {
    Set<Integer> slots = new HashSet<Integer>();
    for (ConformancePackage.KeyMaterial key : pkg.keys) slots.add(key.slot & 0xFF);
    if (!slots.contains(0x9A) || !slots.contains(0x9E)) {
      throw new IllegalArgumentException("Part 1 mandatory 9A and 9E keys are required");
    }
    if (claims.governmentEmail && (!slots.contains(0x9C) || !slots.contains(0x9D))) {
      throw new IllegalArgumentException("government-email profile requires 9C and 9D keys");
    }
  }

  /** Proves that each imported cardholder key, certificate object, and X.509 public key agree. */
  static void validateKeyBindings(
      ConformancePackage pkg, Map<String, ConformancePackage.DataObject> objects) throws Exception {
    for (ConformancePackage.KeyMaterial key : pkg.keys) {
      String containerId = certificateContainerFor(key.slot & 0xFF);
      if (containerId == null) continue;
      if (key.privateKey == null || key.certificate == null) {
        throw new IllegalArgumentException(
            String.format(
                "key %02X requires private key and certificate material", key.slot & 0xFF));
      }
      ConformancePackage.DataObject object = objects.get(containerId);
      if (object == null) {
        throw new IllegalArgumentException(
            String.format(
                "key %02X requires certificate container %s", key.slot & 0xFF, containerId));
      }
      byte[] encodedCertificate = certificateValue(object.payload, containerId);
      if (!Arrays.equals(key.certificate.getEncoded(), encodedCertificate)) {
        throw new IllegalArgumentException(
            String.format(
                "key %02X certificate does not match container %s", key.slot & 0xFF, containerId));
      }

      X509CertificateHolder certificateHolder =
          new X509CertificateHolder(key.certificate.getEncoded());
      Extension subjectKeyIdentifier =
          certificateHolder.getExtension(Extension.subjectKeyIdentifier);
      if (subjectKeyIdentifier != null) {
        byte[] declaredIdentifier =
            SubjectKeyIdentifier.getInstance(subjectKeyIdentifier.getParsedValue())
                .getKeyIdentifier();
        byte[] computedIdentifier =
            MessageDigest.getInstance("SHA-1")
                .digest(certificateHolder.getSubjectPublicKeyInfo().getPublicKeyData().getBytes());
        if (!Arrays.equals(declaredIdentifier, computedIdentifier)) {
          throw new IllegalArgumentException(
              String.format(
                  "key %02X certificate subject key identifier is invalid", key.slot & 0xFF));
        }
      }

      String publicAlgorithm = key.certificate.getPublicKey().getAlgorithm();
      String signatureAlgorithm;
      if ("RSA".equalsIgnoreCase(publicAlgorithm)) signatureAlgorithm = "SHA256withRSA";
      else if ("EC".equalsIgnoreCase(publicAlgorithm)) signatureAlgorithm = "SHA256withECDSA";
      else {
        throw new IllegalArgumentException(
            String.format(
                "key %02X uses unsupported certificate algorithm %s",
                key.slot & 0xFF, publicAlgorithm));
      }
      try {
        Signature proof = Signature.getInstance(signatureAlgorithm);
        proof.initSign(key.privateKey);
        proof.update(new byte[] {(byte) 0x4F, (byte) 0x46, key.slot});
        byte[] signature = proof.sign();
        proof.initVerify(key.certificate.getPublicKey());
        proof.update(new byte[] {(byte) 0x4F, (byte) 0x46, key.slot});
        if (!proof.verify(signature)) {
          throw new IllegalArgumentException(
              String.format(
                  "key %02X private key does not match its certificate", key.slot & 0xFF));
        }
      } catch (IllegalArgumentException e) {
        throw e;
      } catch (Exception e) {
        throw new IllegalArgumentException(
            String.format("key %02X private key does not match its certificate", key.slot & 0xFF),
            e);
      }
    }
  }

  private static String certificateContainerFor(int slot) {
    if (slot == 0x9A) return "5FC105";
    if (slot == 0x9C) return "5FC10A";
    if (slot == 0x9D) return "5FC10B";
    if (slot == 0x9E) return "5FC101";
    if (slot >= 0x82 && slot <= 0x95) return String.format("5FC1%02X", slot - 0x75);
    return null;
  }

  private static byte[] certificateValue(byte[] payload, String id) throws Exception {
    Tlv certificate = element(payload, 0, 0x70, 1, Integer.MAX_VALUE, id);
    Tlv info = element(payload, certificate.end, 0x71, 1, 1, id);
    byte[] encoded = Arrays.copyOfRange(payload, certificate.value, certificate.end);
    if ((payload[info.value] & 0x01) == 0) return encoded;

    GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(encoded));
    ByteArrayOutputStream uncompressed = new ByteArrayOutputStream();
    byte[] buffer = new byte[1024];
    int count;
    while ((count = gzip.read(buffer)) >= 0) {
      if (count > 0) uncompressed.write(buffer, 0, count);
    }
    gzip.close();
    return uncompressed.toByteArray();
  }

  private static void validateDiscovery(
      Map<String, ConformancePackage.DataObject> objects, Claims claims) {
    ConformancePackage.DataObject discovery = objects.get("7E");
    if (claims.vci && discovery == null) {
      throw new IllegalArgumentException("Part 1 Section 3.3.2 requires Discovery for VCI");
    }
    if (discovery == null) return;
    byte[] value = tlvValue(discovery.payload, 0x7E);
    Tlv aid = read(value, 0);
    Tlv policy = read(value, aid.end);
    byte[] expectedAid = hexBytes("A000000308000010000100");
    if (aid.tag != 0x4F
        || !Arrays.equals(expectedAid, Arrays.copyOfRange(value, aid.value, aid.end))
        || policy.tag != 0x5F2F
        || policy.length != 2
        || policy.end != value.length) {
      throw new IllegalArgumentException(
          "Discovery must be the Part 1 Section 3.3.2 4F/5F2F template");
    }
    int first = value[policy.value] & 0xFF;
    int second = value[policy.value + 1] & 0xFF;
    if (!isTable1PinUsagePolicy(first, second)) {
      throw new IllegalArgumentException(
          String.format("invalid Part 1 PIN Usage Policy %02X%02X", first, second));
    }
    // Section 3.3.2: bit 5 "indicates whether the optional OCC satisfies the PIV ACRs" and bit 6
    // "whether the optional Global PIN satisfies the PIV ACRs". The applet implements no OCC and
    // rejects a Discovery Object that advertises a Global PIN its configuration does not enable.
    if ((first & PIN_POLICY_OCC) != 0) {
      throw new IllegalArgumentException("Discovery advertises OCC, which the applet lacks");
    }
    if ((first & PIN_POLICY_GLOBAL_PIN) != 0 && !claims.globalPin) {
      throw new IllegalArgumentException("Discovery advertises a Global PIN that is not claimed");
    }
    if (((first & PIN_POLICY_VCI) != 0) != claims.vci
        || (claims.vci
            && (((first & PIN_POLICY_VCI_WITHOUT_PAIRING) == 0) != claims.pairingRequired))) {
      throw new IllegalArgumentException("Discovery VCI/pairing bits contradict frozen claims");
    }
    if (claims.vci) require(objects, "5FC122");
    if (claims.pairingRequired) require(objects, "5FC123");
  }

  /**
   * Returns whether {@code first} is a SP 800-73-5 Part 1 Table 1 value and {@code second} obeys
   * Section 3.3.2: "0x10 indicates that the PIV Card Application PIN is the primary PIN", "0x20
   * indicates that the Global PIN is the primary PIN", and "If Bit 6 of the first byte of the PIN
   * Usage Policy is set to zero, then the second byte is RFU and SHALL be set to 0x00."
   */
  static boolean isTable1PinUsagePolicy(int first, int second) {
    boolean listed = false;
    for (int value : TABLE_1_FIRST_BYTES) listed |= value == first;
    if (!listed) return false;
    if ((first & PIN_POLICY_GLOBAL_PIN) == 0) return second == 0x00;
    return second == 0x10 || second == 0x20;
  }

  static void validateContainer(String id, byte[] payload) {
    if (id.equals("7E")) return;
    if (id.equals("5FC107")) validateCcc(id, payload);
    else if (id.equals("5FC102")) validateChuid(id, payload);
    else if (isCertificateContainer(id)) validateCertificate(id, payload, isRetiredCertificate(id));
    else if (id.equals("5FC103") || id.equals("5FC108") || id.equals("5FC121")) {
      validateBiometric(id, payload);
    } else if (id.equals("5FC106")) {
      // The CMS, BA mapping, and LDS hashes are validated by validateSecurityObject.
      validateSecurityObjectEnvelope(id, payload);
    } else if (id.equals("5FC109")) validatePrintedInformation(id, payload);
    else if (id.equals("5FC10C")) validateKeyHistory(id, payload);
    else if (id.equals("7F61")) validateBitGroup(id, payload);
    else if (id.equals("5FC122")) validateSmSigner(id, payload);
    else if (id.equals("5FC123")) validatePairingCode(id, payload);
    else validateCompleteBer(id, payload);
  }

  private static void validateCcc(String id, byte[] payload) {
    int offset = 0;
    Tlv cardId = element(payload, offset, 0xF0, 0, 21, id);
    if (cardId.length != 0 && cardId.length != 21) invalid(id);
    offset = cardId.end;
    offset = fixedOrEmpty(payload, offset, 0xF1, 1, id).end;
    offset = fixedOrEmpty(payload, offset, 0xF2, 1, id).end;
    offset = element(payload, offset, 0xF3, 0, 128, id).end;
    offset = fixedOrEmpty(payload, offset, 0xF4, 1, id).end;
    Tlv dataModel = element(payload, offset, 0xF5, 1, 1, id);
    // SP 800-73-5 Part 1 Section 3.1.1 assigns data model number 0x10.
    if ((payload[dataModel.value] & 0xFF) != 0x10) invalid(id);
    offset = dataModel.end;
    offset = fixedOrEmpty(payload, offset, 0xF6, 17, id).end;
    for (int tag : new int[] {0xF7, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE}) {
      offset = element(payload, offset, tag, 0, 0, id).end;
    }
    requireEnd(payload, offset, id);
  }

  private static void validateChuid(String id, byte[] payload) {
    int offset = element(payload, 0, 0x30, 25, 25, id).end;
    offset = element(payload, offset, 0x34, 16, 16, id).end;
    Tlv expiration = element(payload, offset, 0x35, 8, 8, id);
    requireAsciiDigits(payload, expiration, id);
    requireCalendarDate(payload, expiration, false, id);
    offset = expiration.end;
    if (hasTag(payload, offset, 0x36)) offset = element(payload, offset, 0x36, 16, 16, id).end;
    offset = element(payload, offset, 0x3E, 1, 2816, id).end;
    offset = element(payload, offset, 0xFE, 0, 0, id).end;
    requireEnd(payload, offset, id);
  }

  private static void validateCertificate(String id, byte[] payload, boolean retired) {
    int offset = element(payload, 0, 0x70, 1, Integer.MAX_VALUE, id).end;
    Tlv info = element(payload, offset, 0x71, 1, 1, id);
    if ((payload[info.value] & 0xFF) > 1) invalid(id);
    offset = info.end;
    if (retired && hasTag(payload, offset, 0x72)) {
      offset = element(payload, offset, 0x72, 1, 38, id).end;
    }
    offset = element(payload, offset, 0xFE, 0, 0, id).end;
    requireEnd(payload, offset, id);
  }

  private static void validateBiometric(String id, byte[] payload) {
    int offset = element(payload, 0, 0xBC, 1, Integer.MAX_VALUE, id).end;
    offset = element(payload, offset, 0xFE, 0, 0, id).end;
    requireEnd(payload, offset, id);
  }

  private static void validateSecurityObjectEnvelope(String id, byte[] payload) {
    int offset = element(payload, 0, 0xBA, 3, Integer.MAX_VALUE, id).end;
    offset = element(payload, offset, 0xBB, 1, Integer.MAX_VALUE, id).end;
    offset = element(payload, offset, 0xFE, 0, 0, id).end;
    requireEnd(payload, offset, id);
  }

  private static void validatePrintedInformation(String id, byte[] payload) {
    Tlv name = element(payload, 0, 0x01, 1, 125, id);
    requireAscii(payload, name, id);
    Tlv affiliation = element(payload, name.end, 0x02, 1, 20, id);
    requireAscii(payload, affiliation, id);
    Tlv expiration = element(payload, affiliation.end, 0x04, 9, 9, id);
    requirePrintedDate(payload, expiration, id);
    Tlv serial = element(payload, expiration.end, 0x05, 1, 20, id);
    requireAscii(payload, serial, id);
    Tlv issuer = element(payload, serial.end, 0x06, 15, 15, id);
    requireAscii(payload, issuer, id);
    int offset = issuer.end;
    if (hasTag(payload, offset, 0x07)) {
      Tlv line = element(payload, offset, 0x07, 1, 20, id);
      requireAscii(payload, line, id);
      offset = line.end;
    }
    if (hasTag(payload, offset, 0x08)) {
      Tlv line = element(payload, offset, 0x08, 1, 20, id);
      requireAscii(payload, line, id);
      offset = line.end;
    }
    offset = element(payload, offset, 0xFE, 0, 0, id).end;
    requireEnd(payload, offset, id);
  }

  private static void validateKeyHistory(String id, byte[] payload) {
    Tlv onCard = element(payload, 0, 0xC1, 1, 1, id);
    Tlv offCard = element(payload, onCard.end, 0xC2, 1, 1, id);
    int offset = offCard.end;
    boolean hasUrl = hasTag(payload, offset, 0xF3);
    if (hasUrl) offset = element(payload, offset, 0xF3, 1, 118, id).end;
    int onCardCount = payload[onCard.value] & 0xFF;
    int offCardCount = payload[offCard.value] & 0xFF;
    if (onCardCount > 20 || offCardCount > 20 || onCardCount + offCardCount > 20) invalid(id);
    if (offCardCount > 0 && !hasUrl) invalid(id);
    if (onCardCount == 0 && offCardCount == 0 && hasUrl) {
      invalid(id);
    }
    offset = element(payload, offset, 0xFE, 0, 0, id).end;
    requireEnd(payload, offset, id);
  }

  private static void validateBitGroup(String id, byte[] payload) {
    Tlv count = element(payload, 0, 0x02, 1, 1, id);
    int fingers = payload[count.value] & 0xFF;
    int offset = count.end;
    int actual = 0;
    while (hasTag(payload, offset, 0x7F60)) {
      offset = element(payload, offset, 0x7F60, 1, 28, id).end;
      actual++;
    }
    if (fingers != actual || actual > 2) invalid(id);
    requireEnd(payload, offset, id);
  }

  private static void validateSmSigner(String id, byte[] payload) {
    int offset = element(payload, 0, 0x70, 1, Integer.MAX_VALUE, id).end;
    Tlv info = element(payload, offset, 0x71, 1, 1, id);
    if ((payload[info.value] & 0xFF) > 1) invalid(id);
    offset = info.end;
    if (hasTag(payload, offset, 0x7F21)) {
      offset = element(payload, offset, 0x7F21, 1, 601, id).end;
    }
    offset = element(payload, offset, 0xFE, 0, 0, id).end;
    requireEnd(payload, offset, id);
  }

  /**
   * SP 800-73-5 Part 1 Section 3.3.7: "The X.509 Certificate for Content Signing SHALL also include
   * an extended key usage (extKeyUsage) extension asserting id-PIV-content-signing", or the PIV-I
   * purpose for a PIV-I card ({@link ContentSigningProfile}).
   *
   * @param chuid the card's CHUID value, which determines the card type
   */
  static void validateSmSignerUsage(byte[] payload, byte[] chuid) {
    X509CertificateHolder certificate;
    try {
      certificate = new X509CertificateHolder(certificateValue(payload, "5FC122"));
    } catch (Exception e) {
      throw new IllegalArgumentException("5FC122 does not carry an X.509 certificate", e);
    }
    ContentSigningProfile.requireUsage(certificate, chuid, "5FC122");
  }

  private static void validatePairingCode(String id, byte[] payload) {
    Tlv code = element(payload, 0, 0x99, 8, 8, id);
    requireAsciiDigits(payload, code, id);
    int offset = element(payload, code.end, 0xFE, 0, 0, id).end;
    requireEnd(payload, offset, id);
  }

  private static void validateCompleteBer(String id, byte[] payload) {
    int offset = 0;
    while (offset < payload.length) offset = read(payload, offset).end;
    requireEnd(payload, offset, id);
  }

  private static boolean isCertificateContainer(String id) {
    return id.equals("5FC105")
        || id.equals("5FC101")
        || id.equals("5FC10A")
        || id.equals("5FC10B")
        || isRetiredCertificate(id);
  }

  private static boolean isRetiredCertificate(String id) {
    if (id.length() != 6 || !id.startsWith("5FC1")) return false;
    int suffix = Integer.parseInt(id.substring(4), 16);
    return suffix >= 0x0D && suffix <= 0x20;
  }

  private static Tlv fixedOrEmpty(byte[] payload, int offset, int tag, int size, String id) {
    Tlv value = element(payload, offset, tag, 0, size, id);
    if (value.length != 0 && value.length != size) invalid(id);
    return value;
  }

  private static Tlv element(
      byte[] payload, int offset, int tag, int minimum, int maximum, String id) {
    Tlv value = read(payload, offset);
    if (value.tag != tag || value.length < minimum || value.length > maximum) invalid(id);
    return value;
  }

  private static boolean hasTag(byte[] payload, int offset, int tag) {
    return offset < payload.length && read(payload, offset).tag == tag;
  }

  private static void requireAsciiDigits(byte[] payload, Tlv value, String id) {
    for (int offset = value.value; offset < value.end; offset++) {
      if (payload[offset] < '0' || payload[offset] > '9') invalid(id);
    }
  }

  private static void requireAscii(byte[] payload, Tlv value, String id) {
    for (int offset = value.value; offset < value.end; offset++) {
      int character = payload[offset] & 0xFF;
      if (character < 0x20 || character > 0x7E) invalid(id);
    }
  }

  private static void requirePrintedDate(byte[] payload, Tlv value, String id) {
    for (int index = 0; index < value.length; index++) {
      int character = payload[value.value + index] & 0xFF;
      boolean month = index >= 4 && index <= 6;
      if (month ? character < 'A' || character > 'Z' : character < '0' || character > '9') {
        invalid(id);
      }
    }
    requireCalendarDate(payload, value, true, id);
  }

  private static void requireCalendarDate(
      byte[] payload, Tlv value, boolean abbreviatedMonth, String id) {
    int year = decimal(payload, value.value, 4);
    int month;
    int dayOffset;
    if (abbreviatedMonth) {
      String[] months = {
        "JAN", "FEB", "MAR", "APR", "MAY", "JUN",
        "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"
      };
      month = 0;
      for (int candidate = 0; candidate < months.length; candidate++) {
        String name = months[candidate];
        if (payload[value.value + 4] == (byte) name.charAt(0)
            && payload[value.value + 5] == (byte) name.charAt(1)
            && payload[value.value + 6] == (byte) name.charAt(2)) {
          month = candidate + 1;
          break;
        }
      }
      dayOffset = value.value + 7;
    } else {
      month = decimal(payload, value.value + 4, 2);
      dayOffset = value.value + 6;
    }
    int day = decimal(payload, dayOffset, 2);
    int[] monthLengths = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    boolean leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    if (month == 0
        || month > 12
        || day == 0
        || day > monthLengths[month - 1] + (month == 2 && leap ? 1 : 0)) {
      invalid(id);
    }
  }

  private static int decimal(byte[] payload, int offset, int length) {
    int value = 0;
    for (int index = 0; index < length; index++) {
      value = value * 10 + (payload[offset + index] - '0');
    }
    return value;
  }

  private static void requireEnd(byte[] payload, int offset, String id) {
    if (offset != payload.length) invalid(id);
  }

  private static void invalid(String id) {
    throw new IllegalArgumentException(
        id + " does not match its SP 800-73-5 Part 1 container schema");
  }

  static void validateSecurityObject(Map<String, ConformancePackage.DataObject> objects)
      throws Exception {
    validateSecurityObject(objects, false);
  }

  private static void validateSecurityObject(
      Map<String, ConformancePackage.DataObject> objects, boolean requireProfileCoverage)
      throws Exception {
    byte[] payload = objects.get("5FC106").payload;
    Tlv mapping = read(payload, 0);
    Tlv signed = read(payload, mapping.end);
    Tlv error = read(payload, signed.end);
    if (mapping.tag != 0xBA
        || mapping.length == 0
        || mapping.length % 3 != 0
        || signed.tag != 0xBB
        || error.tag != 0xFE
        || error.length != 0
        || error.end != payload.length) {
      throw new IllegalArgumentException("Security Object must contain BA mapping and BB CMS data");
    }
    Map<Integer, ConformancePackage.DataObject> byDg =
        new HashMap<Integer, ConformancePackage.DataObject>();
    Map<Integer, String> containerByDg = new HashMap<Integer, String>();
    Set<ConformancePackage.DataObject> mappedObjects = new HashSet<ConformancePackage.DataObject>();
    for (int offset = mapping.value; offset < mapping.end; offset += 3) {
      int dg = payload[offset] & 0xFF;
      String container =
          String.format("%04X", ((payload[offset + 1] & 0xFF) << 8) | (payload[offset + 2] & 0xFF));
      ConformancePackage.DataObject object = objectForContainer(objects, container);
      addSecurityObjectMapping(byDg, mappedObjects, dg, object);
      containerByDg.put(dg, container);
    }
    if (requireProfileCoverage) validateRequiredSecurityObjectCoverage(objects, byDg);

    byte[] cmsBytes = Arrays.copyOfRange(payload, signed.value, signed.end);
    CMSSignedData cms = new CMSSignedData(cmsBytes);
    if (cms.getSignedContent() == null || cms.getSignerInfos().size() == 0) {
      throw new IllegalArgumentException("Security Object BB lacks signed LDS content");
    }
    // SP 800-73-5 Part 1 Section 3.1.7 requires the BB signature to omit the issuer
    // content-signing certificate because that certificate is carried by the CHUID.
    if (!cms.getCertificates().getMatches(null).isEmpty()) {
      throw new IllegalArgumentException("Security Object BB must omit signer certificates");
    }
    X509CertificateHolder contentSigner = validateChuidSignature(objects.get("5FC102").payload);
    verifyCmsSigner(cms, contentSigner, "Security Object");
    // SP 800-85B AS06.04.06: "The eContentType of the encapContentInfo shall be
    // id-icao-ldsSecurityObject (OID = 1.3.27.1.1.1)."
    if (!ID_ICAO_LDS_SECURITY_OBJECT.getId().equals(cms.getSignedContentTypeOID())) {
      throw new IllegalArgumentException(
          "Security Object eContentType must be id-icao-ldsSecurityObject, not "
              + cms.getSignedContentTypeOID());
    }
    SignerInformation securityObjectSigner = singleSigner(cms, "Security Object");
    requireTable2Digest(securityObjectSigner, contentSigner, "Security Object");
    byte[] ldsBytes = (byte[]) cms.getSignedContent().getContent();
    LDSSecurityObject lds = LDSSecurityObject.getInstance(ASN1Primitive.fromByteArray(ldsBytes));
    // SP 800-78-5 Section 3.2.3: "This specification requires that the message digests of digital
    // information be computed using the same hash algorithm used to generate the digital signature
    // on the Security Object."
    if (!lds.getDigestAlgorithmIdentifier()
        .getAlgorithm()
        .getId()
        .equals(securityObjectSigner.getDigestAlgOID())) {
      throw new IllegalArgumentException(
          "Security Object LDS hash algorithm differs from its signature hash algorithm");
    }
    MessageDigest digest =
        MessageDigest.getInstance(lds.getDigestAlgorithmIdentifier().getAlgorithm().getId(), "BC");
    Set<Integer> seen = new HashSet<Integer>();
    for (DataGroupHash hash : lds.getDatagroupHash()) {
      int dg = hash.getDataGroupNumber();
      ConformancePackage.DataObject object = byDg.get(dg);
      if (object == null
          || !seen.add(dg)
          || !Arrays.equals(
              hash.getDataGroupHashValue().getOctets(),
              digest.digest(securityObjectHashInput(object)))) {
        throw new IllegalArgumentException(
            "Security Object DG hash does not match BA mapping/input: DG "
                + dg
                + ", container "
                + containerByDg.get(dg));
      }
    }
    if (seen.size() != byDg.size()) {
      throw new IllegalArgumentException("Security Object BA and LDS hash sets differ");
    }
  }

  private static byte[] securityObjectHashInput(ConformancePackage.DataObject object) {
    // Table 19 defines the Discovery Object data as its 4F and 5F2F elements. The outer 7E
    // application template is the GET/PUT representation and is not part of the LDS data group.
    return hex(object.id).equals("7E") ? tlvValue(object.payload, 0x7E) : object.payload;
  }

  @SuppressWarnings("unchecked")
  private static X509CertificateHolder validateChuidSignature(byte[] payload) throws Exception {
    int offset = 0;
    int signedContentLength = -1;
    Tlv signature = null;
    while (offset < payload.length) {
      int elementStart = offset;
      Tlv element = read(payload, offset);
      if (element.tag == 0x3E) {
        signedContentLength = elementStart;
        signature = element;
        break;
      }
      offset = element.end;
    }
    if (signature == null) {
      throw new IllegalArgumentException("CHUID asymmetric signature field is missing");
    }
    byte[] cmsBytes = Arrays.copyOfRange(payload, signature.value, signature.end);
    byte[] signedContent =
        AdminTlv.concat(
            Arrays.copyOf(payload, signedContentLength),
            Arrays.copyOfRange(payload, signature.end, payload.length));
    CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(signedContent), cmsBytes);
    if (cms.getSignerInfos().size() != 1 || cms.getCertificates().getMatches(null).size() != 1) {
      throw new IllegalArgumentException(
          "CHUID signature must contain one signer and one content-signing certificate");
    }
    SignerInformation signer = singleSigner(cms, "CHUID");
    Collection<?> matches = cms.getCertificates().getMatches(signer.getSID());
    if (matches.size() != 1) {
      throw new IllegalArgumentException("CHUID signer does not match its certificate");
    }
    Object matched = matches.iterator().next();
    if (!(matched instanceof X509CertificateHolder)) {
      throw new IllegalArgumentException("CHUID signer certificate has an unsupported form");
    }
    X509CertificateHolder certificate = (X509CertificateHolder) matched;
    verifyCmsSigner(cms, certificate, "CHUID");
    // SP 800-73-5 Part 1 Section 3.1.2.1: "The encapContentInfo SHALL: Specify an eContentType of
    // id-PIV-CHUIDSecurityObject".
    if (!ID_PIV_CHUID_SECURITY_OBJECT.getId().equals(cms.getSignedContentTypeOID())) {
      throw new IllegalArgumentException(
          "CHUID eContentType must be id-PIV-CHUIDSecurityObject, not "
              + cms.getSignedContentTypeOID());
    }
    requirePivSignerDn(signer, certificate);
    requireTable2Digest(signer, certificate, "CHUID");
    // SP 800-73-5 Part 1 Section 3.1.2.1: "The content signing certificate SHALL also include an
    // extended key usage (extKeyUsage) extension asserting id-PIV-content-signing"; a PIV-I card's
    // content signer asserts id-fpki-pivi-content-signing instead. The same certificate verifies
    // the Security Object signature (Section 3.1.7).
    ContentSigningProfile.requireUsage(certificate, payload, "CHUID");
    return certificate;
  }

  /**
   * SP 800-73-5 Part 1 Section 3.1.2.1: the CHUID SignerInfo SHALL "Include, at a minimum, the
   * following signed attributes: ... A pivSigner-DN attribute containing the subject name that
   * appears in the PKI certificate for the entity that signed the CHUID".
   */
  private static void requirePivSignerDn(
      SignerInformation signer, X509CertificateHolder certificate) {
    AttributeTable attributes = signer.getSignedAttributes();
    ASN1EncodableVector values =
        attributes == null ? new ASN1EncodableVector() : attributes.getAll(ID_PIV_SIGNER_DN);
    if (values.size() != 1) {
      throw new IllegalArgumentException("CHUID signer must carry exactly one pivSigner-DN");
    }
    ASN1Set attributeValues = ((Attribute) values.get(0)).getAttrValues();
    if (attributeValues.size() != 1
        || !certificate
            .getSubject()
            .equals(X500Name.getInstance(attributeValues.getObjectAt(0).toASN1Primitive()))) {
      throw new IllegalArgumentException(
          "CHUID pivSigner-DN does not match the content signing certificate subject");
    }
  }

  /**
   * Enforces SP 800-78-5 Section 3.2.1 Table 2: "ECDSA (Curve P-256) | SHA-256", "ECDSA (Curve
   * P-384) | SHA-384", and RSA with "SHA-256 or SHA-384".
   */
  private static void requireTable2Digest(
      SignerInformation signer, X509CertificateHolder certificate, String label) {
    AlgorithmIdentifier keyAlgorithm = certificate.getSubjectPublicKeyInfo().getAlgorithm();
    String digest = signer.getDigestAlgOID();
    boolean conforming;
    if (X9ObjectIdentifiers.id_ecPublicKey.equals(keyAlgorithm.getAlgorithm())) {
      ASN1Encodable curve = keyAlgorithm.getParameters();
      String signature = signer.getEncryptionAlgOID();
      if (SECObjectIdentifiers.secp256r1.equals(curve)) {
        conforming =
            NISTObjectIdentifiers.id_sha256.getId().equals(digest)
                && X9ObjectIdentifiers.ecdsa_with_SHA256.getId().equals(signature);
      } else if (SECObjectIdentifiers.secp384r1.equals(curve)) {
        conforming =
            NISTObjectIdentifiers.id_sha384.getId().equals(digest)
                && X9ObjectIdentifiers.ecdsa_with_SHA384.getId().equals(signature);
      } else {
        conforming = false;
      }
    } else if (PKCSObjectIdentifiers.rsaEncryption.equals(keyAlgorithm.getAlgorithm())) {
      conforming =
          NISTObjectIdentifiers.id_sha256.getId().equals(digest)
              || NISTObjectIdentifiers.id_sha384.getId().equals(digest);
    } else {
      conforming = false;
    }
    if (!conforming) {
      throw new IllegalArgumentException(
          label
              + " signature algorithm and hash do not match SP 800-78-5 Table 2 for the signer key"
              + " (digest "
              + digest
              + ", signature "
              + signer.getEncryptionAlgOID()
              + ")");
    }
  }

  private static void verifyCmsSigner(
      CMSSignedData cms, X509CertificateHolder certificate, String label) throws Exception {
    SignerInformation signer = singleSigner(cms, label);
    try {
      if (!signer.getSID().match(certificate)
          || !signer.verify(
              new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certificate))) {
        throw new IllegalArgumentException(label + " CMS signature verification failed");
      }
    } catch (IllegalArgumentException e) {
      throw e;
    } catch (Exception e) {
      throw new IllegalArgumentException(label + " CMS signature verification failed", e);
    }
  }

  private static SignerInformation singleSigner(CMSSignedData cms, String label) {
    if (cms.getSignerInfos().size() != 1) {
      throw new IllegalArgumentException(label + " must contain exactly one signer");
    }
    Object value = cms.getSignerInfos().getSigners().iterator().next();
    if (!(value instanceof SignerInformation)) {
      throw new IllegalArgumentException(label + " signer has an unsupported form");
    }
    return (SignerInformation) value;
  }

  static void addSecurityObjectMapping(
      Map<Integer, ConformancePackage.DataObject> byDg,
      Set<ConformancePackage.DataObject> mappedObjects,
      int dg,
      ConformancePackage.DataObject object) {
    if (dg < 1
        || dg > 16
        || object == null
        || byDg.containsKey(dg)
        || mappedObjects.contains(object)) {
      throw new IllegalArgumentException(
          "Security Object BA contains an invalid or duplicate mapping");
    }
    byDg.put(dg, object);
    mappedObjects.add(object);
  }

  static void validateRequiredSecurityObjectCoverage(
      Map<String, ConformancePackage.DataObject> objects,
      Map<Integer, ConformancePackage.DataObject> mapped) {
    for (Map.Entry<String, ConformancePackage.DataObject> entry : objects.entrySet()) {
      if (requiresSecurityObjectCoverage(entry.getKey())
          && !mapped.containsValue(entry.getValue())) {
        throw new IllegalArgumentException(
            "Security Object omits required unsigned container " + entry.getKey());
      }
    }
  }

  static boolean requiresSecurityObjectCoverage(String id) {
    // SP 800-73-5 Part 1 Sections 3.1.1, 3.1.7, 3.3.2, 3.3.3, 3.3.6, and 3.3.8.
    return id.equals("5FC107")
        || id.equals("5FC109")
        || id.equals("7E")
        || id.equals("5FC10C")
        || id.equals("7F61")
        || id.equals("5FC123");
  }

  private static ConformancePackage.DataObject objectForContainer(
      Map<String, ConformancePackage.DataObject> objects, String container) {
    String[][] mapping = {
      {"DB00", "5FC107"}, {"3000", "5FC102"}, {"0101", "5FC105"},
      {"6010", "5FC103"}, {"6030", "5FC108"}, {"0500", "5FC101"},
      {"0100", "5FC10A"}, {"0102", "5FC10B"}, {"3001", "5FC109"},
      {"6050", "7E"}, {"6060", "5FC10C"}
    };
    for (String[] entry : mapping) if (entry[0].equals(container)) return objects.get(entry[1]);
    int value = Integer.parseInt(container, 16);
    if (value >= 0x1001 && value <= 0x1014) {
      return objects.get(String.format("5FC1%02X", value - 0x1001 + 0x0D));
    }
    if (value >= 0x1015 && value <= 0x1018) {
      String[] optional = {"5FC121", "7F61", "5FC122", "5FC123"};
      return objects.get(optional[value - 0x1015]);
    }
    return null;
  }

  private static void require(Map<String, ConformancePackage.DataObject> objects, String id) {
    if (!objects.containsKey(id))
      throw new IllegalArgumentException("missing mandatory object " + id);
  }

  private static byte[] tlvValue(byte[] encoded, int expectedTag) {
    Tlv tlv = read(encoded, 0);
    if (tlv.tag != expectedTag || tlv.end != encoded.length)
      throw new IllegalArgumentException("invalid TLV");
    return Arrays.copyOfRange(encoded, tlv.value, tlv.end);
  }

  private static Tlv read(byte[] data, int offset) {
    if (offset >= data.length) throw new IllegalArgumentException("missing TLV");
    int tag = data[offset++] & 0xFF;
    if ((tag & 0x1F) == 0x1F) {
      if (offset >= data.length) throw new IllegalArgumentException("truncated tag");
      tag = (tag << 8) | (data[offset++] & 0xFF);
    }
    if (offset >= data.length) throw new IllegalArgumentException("missing length");
    int first = data[offset++] & 0xFF;
    int length = first;
    if ((first & 0x80) != 0) {
      int count = first & 0x7F;
      if (count == 0 || count > 2 || offset + count > data.length)
        throw new IllegalArgumentException("invalid length");
      length = 0;
      while (count-- > 0) length = (length << 8) | (data[offset++] & 0xFF);
    }
    if (offset + length > data.length) throw new IllegalArgumentException("truncated TLV");
    return new Tlv(tag, offset, length);
  }

  private static final class Tlv {
    final int tag;
    final int value;
    final int length;
    final int end;

    Tlv(int tag, int value, int length) {
      this.tag = tag;
      this.value = value;
      this.length = length;
      this.end = value + length;
    }
  }

  private static String hex(byte[] value) {
    return HexUtil.format(value);
  }

  private static byte[] hexBytes(String value) {
    return HexUtil.parse(value);
  }
}
