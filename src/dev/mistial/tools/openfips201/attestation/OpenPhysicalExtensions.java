/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.attestation;

import java.math.BigInteger;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;

/**
 * OpenPhysical private certificate extensions under {@code 1.3.6.1.4.1.57923}, with strict typed
 * parsers.
 *
 * <p>Every parser takes the extnValue contents (the octets inside the extension OCTET STRING),
 * requires them to be strict DER (see {@link StrictDer#parse}), requires the exact element count
 * and types listed on each class, and requires the version listed there; no other version is
 * accepted.
 */
public final class OpenPhysicalExtensions {
  /** Private enterprise arc {@code 1.3.6.1.4.1.57923}. */
  public static final ASN1ObjectIdentifier ARC = new ASN1ObjectIdentifier("1.3.6.1.4.1.57923");

  /** SAM parameters packet (v2), {@code 1.3.6.1.4.1.57923.20.10.10.1}. */
  public static final ASN1ObjectIdentifier SAM_PARAMETERS = ARC.branch("20.10.10.1");

  /** F9 issuance extension, {@code 1.3.6.1.4.1.57923.20.10.10.2}, non-critical. */
  public static final ASN1ObjectIdentifier F9_ISSUANCE = ARC.branch("20.10.10.2");

  /** SAM batch extension, {@code 1.3.6.1.4.1.57923.20.10.10.3}, non-critical. */
  public static final ASN1ObjectIdentifier SAM_BATCH = ARC.branch("20.10.10.3");

  /** PIV leaf attestation extension, {@code 1.3.6.1.4.1.57923.20.10.20.1}, non-critical. */
  public static final ASN1ObjectIdentifier PIV_LEAF = ARC.branch("20.10.20.1");

  /** Version of the F9 issuance extension (v2: adds capSha256 and cplcSha256). */
  public static final int F9_ISSUANCE_VERSION = 2;

  /** Version of the PIV leaf extension (v2: adds buildSha256). */
  public static final int PIV_LEAF_VERSION = 2;

  /** Length of the measurement hashes capSha256, cplcSha256 and buildSha256. */
  public static final int MEASUREMENT_LENGTH = 32;

  /** Version of the SAM batch extension (v2: no OPID format or CIN width). */
  public static final int SAM_BATCH_VERSION = 3;

  public static final int CHAIN_HEAD_LENGTH = 32;
  public static final int TIMESTAMP_LENGTH = 8;
  public static final int PARAMS_DIGEST_LENGTH = 32;
  public static final int APPLET_VERSION_LENGTH = 4;

  /** PIV leaf {@code buildFlags} bit 0: FIPS build. */
  public static final int BUILD_FLAG_FIPS = 0x01;

  /** PIV leaf {@code buildFlags} bit 1: attestation build. */
  public static final int BUILD_FLAG_ATTESTATION = 0x02;

  /** PIV leaf {@code origin} value for an on-card generated key ({@code ORIGIN_GENERATED}). */
  public static final int ORIGIN_GENERATED = 2;

  private OpenPhysicalExtensions() {}

  /**
   * F9 issuance extension: {@code SEQUENCE{version INTEGER 2, issuanceSeq INTEGER, eventSeq
   * INTEGER, prevChainHead OCTET STRING(32), capSha256 OCTET STRING(32), cplcSha256 OCTET
   * STRING(32)}}. capSha256 and cplcSha256 are the issuance host's measurements of the installed
   * PIV CAP file and of the card's CPLC data, as the SAM received them in ISSUE.
   */
  public static final class F9Issuance {
    public final long issuanceSeq;
    public final long eventSeq;
    private final byte[] prevChainHead;
    private final byte[] capSha256;
    private final byte[] cplcSha256;

    F9Issuance(
        long issuanceSeq,
        long eventSeq,
        byte[] prevChainHead,
        byte[] capSha256,
        byte[] cplcSha256) {
      this.issuanceSeq = issuanceSeq;
      this.eventSeq = eventSeq;
      this.prevChainHead = prevChainHead.clone();
      this.capSha256 = capSha256.clone();
      this.cplcSha256 = cplcSha256.clone();
    }

    public byte[] prevChainHead() {
      return prevChainHead.clone();
    }

    public byte[] capSha256() {
      return capSha256.clone();
    }

    public byte[] cplcSha256() {
      return cplcSha256.clone();
    }
  }

  /**
   * SAM batch extension: {@code SEQUENCE{version INTEGER (3), issuerId INTEGER, batch INTEGER,
   * initialQuota INTEGER, initialTimestamp OCTET STRING(8), paramsDigest OCTET STRING(32),
   * allocationSeq INTEGER, registryHead OCTET STRING(32)}}.
   */
  public static final class SamBatch {
    public final int issuerId;
    public final int batch;
    public final long initialQuota;
    private final byte[] initialTimestamp;
    private final byte[] paramsDigest;

    /** Registry seq of the allocation this SAM was bound to. */
    public final long allocationSeq;

    private final byte[] registryHead;

    SamBatch(
        int issuerId,
        int batch,
        long initialQuota,
        byte[] initialTimestamp,
        byte[] paramsDigest,
        long allocationSeq,
        byte[] registryHead) {
      this.issuerId = issuerId;
      this.batch = batch;
      this.initialQuota = initialQuota;
      this.initialTimestamp = initialTimestamp.clone();
      this.paramsDigest = paramsDigest.clone();
      this.allocationSeq = allocationSeq;
      this.registryHead = registryHead.clone();
    }

    /** SHA-256 of the registry's bind line for this SAM. */
    public byte[] registryHead() {
      return registryHead.clone();
    }

    public byte[] initialTimestamp() {
      return initialTimestamp.clone();
    }

    public byte[] paramsDigest() {
      return paramsDigest.clone();
    }
  }

  /**
   * PIV leaf extension: {@code SEQUENCE{version INTEGER 2, appletVersion OCTET STRING(4),
   * buildFlags OCTET STRING(1), vciSuite OCTET STRING(1), platformId OCTET STRING, keyReference
   * OCTET STRING(1), mechanism OCTET STRING(1), role OCTET STRING(1), attributes OCTET STRING(1),
   * origin ENUMERATED, contactMode OCTET STRING(1), contactlessMode OCTET STRING(1), buildSha256
   * OCTET STRING(32)}}. buildSha256 is the {@code build.sha256} identity of the applet build, as
   * recorded in the CAP's {@code .cap.properties}.
   *
   * <p>One-octet fields are exposed as unsigned values {@code 0..255}.
   */
  public static final class PivLeaf {
    private final byte[] appletVersion;
    public final int buildFlags;
    public final int vciSuite;
    private final byte[] platformId;
    public final int keyReference;
    public final int mechanism;
    public final int role;
    public final int attributes;
    public final int origin;
    public final int contactMode;
    public final int contactlessMode;
    private final byte[] buildSha256;

    PivLeaf(
        byte[] appletVersion,
        int buildFlags,
        int vciSuite,
        byte[] platformId,
        int keyReference,
        int mechanism,
        int role,
        int attributes,
        int origin,
        int contactMode,
        int contactlessMode,
        byte[] buildSha256) {
      this.appletVersion = appletVersion.clone();
      this.buildFlags = buildFlags;
      this.vciSuite = vciSuite;
      this.platformId = platformId.clone();
      this.keyReference = keyReference;
      this.mechanism = mechanism;
      this.role = role;
      this.attributes = attributes;
      this.origin = origin;
      this.contactMode = contactMode;
      this.contactlessMode = contactlessMode;
      this.buildSha256 = buildSha256.clone();
    }

    public byte[] appletVersion() {
      return appletVersion.clone();
    }

    public byte[] platformId() {
      return platformId.clone();
    }

    public byte[] buildSha256() {
      return buildSha256.clone();
    }
  }

  /**
   * Returns the extnValue contents of the extension {@code oid}, which must be present and
   * non-critical.
   *
   * @throws IllegalArgumentException when the extension is absent or marked critical
   */
  public static byte[] requireNonCritical(Extensions extensions, ASN1ObjectIdentifier oid) {
    Extension extension = extensions == null ? null : extensions.getExtension(oid);
    if (extension == null) {
      throw new IllegalArgumentException("extension " + oid + " is absent");
    }
    if (extension.isCritical()) {
      throw new IllegalArgumentException("extension " + oid + " must be non-critical");
    }
    return extension.getExtnValue().getOctets();
  }

  /** Parses the F9 issuance extension value. */
  public static F9Issuance parseF9Issuance(byte[] value) {
    ASN1Sequence seq = sequence(value, 6, "F9 issuance");
    requireVersion(seq.getObjectAt(0), F9_ISSUANCE_VERSION, "F9 issuance");
    long issuanceSeq = nonNegativeLong(seq.getObjectAt(1), "issuanceSeq");
    long eventSeq = nonNegativeLong(seq.getObjectAt(2), "eventSeq");
    byte[] head = octets(seq.getObjectAt(3), CHAIN_HEAD_LENGTH, "prevChainHead");
    byte[] cap = octets(seq.getObjectAt(4), MEASUREMENT_LENGTH, "capSha256");
    byte[] cplc = octets(seq.getObjectAt(5), MEASUREMENT_LENGTH, "cplcSha256");
    return new F9Issuance(issuanceSeq, eventSeq, head, cap, cplc);
  }

  /** Parses the SAM batch extension value. */
  public static SamBatch parseSamBatch(byte[] value) {
    ASN1Sequence seq = sequence(value, 8, "SAM batch");
    if (!BigInteger.valueOf(SAM_BATCH_VERSION).equals(integer(seq.getObjectAt(0), "version"))) {
      throw new IllegalArgumentException(
          "SAM batch extension version must be " + SAM_BATCH_VERSION);
    }
    int issuerId = boundedInt(seq.getObjectAt(1), 0, 9999, "issuerId");
    int batch = boundedInt(seq.getObjectAt(2), 0, 9999, "batch");
    long initialQuota = nonNegativeLong(seq.getObjectAt(3), "initialQuota");
    byte[] timestamp = octets(seq.getObjectAt(4), TIMESTAMP_LENGTH, "initialTimestamp");
    byte[] digest = octets(seq.getObjectAt(5), PARAMS_DIGEST_LENGTH, "paramsDigest");
    long allocationSeq = nonNegativeLong(seq.getObjectAt(6), "allocationSeq");
    byte[] registryHead = octets(seq.getObjectAt(7), CHAIN_HEAD_LENGTH, "registryHead");
    return new SamBatch(
        issuerId, batch, initialQuota, timestamp, digest, allocationSeq, registryHead);
  }

  /** Parses the PIV leaf extension value. */
  public static PivLeaf parsePivLeaf(byte[] value) {
    ASN1Sequence seq = sequence(value, 13, "PIV leaf");
    requireVersion(seq.getObjectAt(0), PIV_LEAF_VERSION, "PIV leaf");
    byte[] appletVersion = octets(seq.getObjectAt(1), APPLET_VERSION_LENGTH, "appletVersion");
    int buildFlags = octet(seq.getObjectAt(2), "buildFlags");
    int vciSuite = octet(seq.getObjectAt(3), "vciSuite");
    byte[] platformId = octets(seq.getObjectAt(4), -1, "platformId");
    int keyReference = octet(seq.getObjectAt(5), "keyReference");
    int mechanism = octet(seq.getObjectAt(6), "mechanism");
    int role = octet(seq.getObjectAt(7), "role");
    int attributes = octet(seq.getObjectAt(8), "attributes");
    ASN1Encodable originElement = seq.getObjectAt(9);
    if (!(originElement instanceof ASN1Enumerated)) {
      throw new IllegalArgumentException("PIV leaf origin must be ENUMERATED");
    }
    BigInteger originValue = ((ASN1Enumerated) originElement).getValue();
    if (originValue.signum() < 0 || originValue.bitLength() > 8) {
      throw new IllegalArgumentException("PIV leaf origin must be 0..255");
    }
    int origin = originValue.intValue();
    int contactMode = octet(seq.getObjectAt(10), "contactMode");
    int contactlessMode = octet(seq.getObjectAt(11), "contactlessMode");
    byte[] buildSha256 = octets(seq.getObjectAt(12), MEASUREMENT_LENGTH, "buildSha256");
    return new PivLeaf(
        appletVersion,
        buildFlags,
        vciSuite,
        platformId,
        keyReference,
        mechanism,
        role,
        attributes,
        origin,
        contactMode,
        contactlessMode,
        buildSha256);
  }

  private static ASN1Sequence sequence(byte[] value, int elements, String name) {
    ASN1Primitive parsed = StrictDer.parse(value);
    if (!(parsed instanceof ASN1Sequence)) {
      throw new IllegalArgumentException(name + " extension must be a SEQUENCE");
    }
    ASN1Sequence seq = (ASN1Sequence) parsed;
    if (seq.size() != elements) {
      throw new IllegalArgumentException(
          name + " extension must have " + elements + " elements, found " + seq.size());
    }
    return seq;
  }

  private static void requireVersion(ASN1Encodable element, int version, String name) {
    if (!BigInteger.valueOf(version).equals(integer(element, "version"))) {
      throw new IllegalArgumentException(name + " extension version must be " + version);
    }
  }

  private static BigInteger integer(ASN1Encodable element, String field) {
    if (!(element instanceof ASN1Integer)) {
      throw new IllegalArgumentException(field + " must be INTEGER");
    }
    return ((ASN1Integer) element).getValue();
  }

  private static long nonNegativeLong(ASN1Encodable element, String field) {
    BigInteger value = integer(element, field);
    if (value.signum() < 0 || value.bitLength() > 63) {
      throw new IllegalArgumentException(field + " must be a non-negative 63-bit INTEGER");
    }
    return value.longValue();
  }

  private static int boundedInt(ASN1Encodable element, int min, int max, String field) {
    BigInteger value = integer(element, field);
    if (value.compareTo(BigInteger.valueOf(min)) < 0
        || value.compareTo(BigInteger.valueOf(max)) > 0) {
      throw new IllegalArgumentException(field + " must be " + min + ".." + max);
    }
    return value.intValue();
  }

  private static byte[] octets(ASN1Encodable element, int length, String field) {
    if (!(element instanceof ASN1OctetString)) {
      throw new IllegalArgumentException(field + " must be OCTET STRING");
    }
    byte[] value = ((ASN1OctetString) element).getOctets();
    if (length >= 0 && value.length != length) {
      throw new IllegalArgumentException(field + " must be " + length + " octets");
    }
    return Arrays.copyOf(value, value.length);
  }

  private static int octet(ASN1Encodable element, String field) {
    return octets(element, 1, field)[0] & 0xFF;
  }
}
