/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.provisioning;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.icao.DataGroupHash;
import org.bouncycastle.asn1.icao.LDSSecurityObject;
import org.bouncycastle.cms.CMSSignedData;

/** Preflight checks for the frozen SP 800-73-5 Part 1 certification profile. */
public final class CertificationProfileValidator {
  private static final String[] MANDATORY = {
    "5FC107", "5FC102", "5FC105", "5FC101", "5FC103", "5FC108", "5FC106"
  };

  /** Frozen issuer claims that affect which Part 1 objects are required. */
  public static final class Claims {
    public final boolean governmentEmail;
    public final boolean vci;
    public final boolean pairingRequired;

    public Claims(boolean governmentEmail, boolean vci, boolean pairingRequired) {
      this.governmentEmail = governmentEmail;
      this.vci = vci;
      this.pairingRequired = pairingRequired;
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
    return Math.max(minimum, payloadLength);
  }

  /**
   * Validates issuer inputs before the irreversible personalization transition.
   *
   * <p>This validates the Security Object's mapping and signed LDS hash input. Signature trust is
   * an issuer ceremony concern; SP 800-73-5 Part 1 does not require the applet to verify its own
   * issuer signature.
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
    for (Map.Entry<String, ConformancePackage.DataObject> entry : objects.entrySet()) {
      validateContainer(entry.getKey(), entry.getValue().payload);
    }
    validateSecurityObject(objects);
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
    if ((first & 0xC3) != 0x40 || ((first & 0x20) == 0 && second != 0)) {
      throw new IllegalArgumentException("invalid Part 1 PIN Usage Policy");
    }
    if (((first & 0x08) != 0) != claims.vci
        || (claims.vci && (((first & 0x04) == 0) != claims.pairingRequired))) {
      throw new IllegalArgumentException("Discovery VCI/pairing bits contradict frozen claims");
    }
    if (claims.vci) require(objects, "5FC122");
    if (claims.pairingRequired) require(objects, "5FC123");
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
    offset = element(payload, offset, 0xF5, 1, 1, id).end;
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
    if (hasTag(payload, offset, 0xFE)) offset = element(payload, offset, 0xFE, 0, 0, id).end;
    requireEnd(payload, offset, id);
  }

  private static void validatePrintedInformation(String id, byte[] payload) {
    int offset = element(payload, 0, 0x01, 1, 125, id).end;
    offset = element(payload, offset, 0x02, 1, 20, id).end;
    offset = element(payload, offset, 0x04, 9, 9, id).end;
    offset = element(payload, offset, 0x05, 1, 20, id).end;
    offset = element(payload, offset, 0x06, 15, 15, id).end;
    if (hasTag(payload, offset, 0x07)) offset = element(payload, offset, 0x07, 1, 20, id).end;
    if (hasTag(payload, offset, 0x08)) offset = element(payload, offset, 0x08, 1, 20, id).end;
    offset = element(payload, offset, 0xFE, 0, 0, id).end;
    requireEnd(payload, offset, id);
  }

  private static void validateKeyHistory(String id, byte[] payload) {
    Tlv onCard = element(payload, 0, 0xC1, 1, 1, id);
    Tlv offCard = element(payload, onCard.end, 0xC2, 1, 1, id);
    int offset = offCard.end;
    boolean hasUrl = hasTag(payload, offset, 0xF3);
    if (hasUrl) offset = element(payload, offset, 0xF3, 1, 118, id).end;
    if ((payload[offCard.value] & 0xFF) > 0 && !hasUrl) invalid(id);
    if ((payload[onCard.value] & 0xFF) == 0 && (payload[offCard.value] & 0xFF) == 0 && hasUrl) {
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

  private static void requireEnd(byte[] payload, int offset, String id) {
    if (offset != payload.length) invalid(id);
  }

  private static void invalid(String id) {
    throw new IllegalArgumentException(
        id + " does not match its SP 800-73-5 Part 1 container schema");
  }

  static void validateSecurityObject(Map<String, ConformancePackage.DataObject> objects)
      throws Exception {
    byte[] payload = objects.get("5FC106").payload;
    Tlv mapping = read(payload, 0);
    Tlv signed = read(payload, mapping.end);
    Tlv error = signed.end < payload.length ? read(payload, signed.end) : null;
    if (mapping.tag != 0xBA
        || mapping.length == 0
        || mapping.length % 3 != 0
        || signed.tag != 0xBB
        || (error != null
            && (error.tag != 0xFE || error.length != 0 || error.end != payload.length))
        || (error == null && signed.end != payload.length)) {
      throw new IllegalArgumentException("Security Object must contain BA mapping and BB CMS data");
    }
    Map<Integer, ConformancePackage.DataObject> byDg =
        new HashMap<Integer, ConformancePackage.DataObject>();
    for (int offset = mapping.value; offset < mapping.end; offset += 3) {
      int dg = payload[offset] & 0xFF;
      String container =
          String.format("%04X", ((payload[offset + 1] & 0xFF) << 8) | (payload[offset + 2] & 0xFF));
      ConformancePackage.DataObject object = objectForContainer(objects, container);
      if (object == null || byDg.put(dg, object) != null) {
        throw new IllegalArgumentException(
            "Security Object BA contains an unknown or duplicate mapping");
      }
    }

    byte[] cmsBytes = Arrays.copyOfRange(payload, signed.value, signed.end);
    CMSSignedData cms = new CMSSignedData(cmsBytes);
    if (cms.getSignedContent() == null || cms.getSignerInfos().size() == 0) {
      throw new IllegalArgumentException("Security Object BB lacks signed LDS content");
    }
    byte[] ldsBytes = (byte[]) cms.getSignedContent().getContent();
    LDSSecurityObject lds = LDSSecurityObject.getInstance(ASN1Primitive.fromByteArray(ldsBytes));
    MessageDigest digest =
        MessageDigest.getInstance(lds.getDigestAlgorithmIdentifier().getAlgorithm().getId(), "BC");
    Set<Integer> seen = new HashSet<Integer>();
    for (DataGroupHash hash : lds.getDatagroupHash()) {
      int dg = hash.getDataGroupNumber();
      ConformancePackage.DataObject object = byDg.get(dg);
      if (object == null
          || !seen.add(dg)
          || !Arrays.equals(
              hash.getDataGroupHashValue().getOctets(), digest.digest(object.payload))) {
        throw new IllegalArgumentException(
            "Security Object DG hash does not match BA mapping/input");
      }
    }
    if (seen.size() != byDg.size()) {
      throw new IllegalArgumentException("Security Object BA and LDS hash sets differ");
    }
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
    StringBuilder out = new StringBuilder();
    for (byte item : value) out.append(String.format("%02X", item & 0xFF));
    return out.toString();
  }

  private static byte[] hexBytes(String value) {
    byte[] result = new byte[value.length() / 2];
    for (int i = 0; i < value.length(); i += 2)
      result[i / 2] = (byte) Integer.parseInt(value.substring(i, i + 2), 16);
    return result;
  }
}
