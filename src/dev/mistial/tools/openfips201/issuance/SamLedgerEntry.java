/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import dev.mistial.tools.openfips201.common.BerTlvReader;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * One SAM ledger entry, in the SAM's fixed binary format:
 *
 * <pre>
 * "OPSAMLE1"(8) | type(1) | samSki(20) | eventSeq(4) | prevHead(32) | payload
 *  GENESIS 01: sha256(samCert)(32) | paramsDigest(32) | quota(4) | lastTs(8)
 *  ISSUE   02: issuanceSeq(4) | opidLen(1) | opid(opidLen) | f9Ski(20) | tbsHash(32)
 *  TOPUP   03: ts(8) | added(4) | newQuota(4)
 *  TERM    04: issued(4) | quota(4)
 *  VOID    05: issuanceSeq(4) | opidLen(1) = 17 | opid(17) | reason(1)
 *  CLOSE   06: issued(4) | quota(4)
 * </pre>
 *
 * <p>head = SHA-256(entry). The SAM signs each entry with ECDSA P-256 over SHA-256(entry), so the
 * signature verifies as SHA256withECDSA over the entry octets.
 */
public final class SamLedgerEntry {
  public static final int TYPE_GENESIS = 0x01;
  public static final int TYPE_ISSUE = 0x02;
  public static final int TYPE_TOPUP = 0x03;
  public static final int TYPE_TERMINATE = 0x04;
  public static final int TYPE_VOID = 0x05;
  public static final int TYPE_CLOSE = 0x06;

  static final byte[] PREFIX = "OPSAMLE1".getBytes(StandardCharsets.US_ASCII);
  private static final int HEADER_LENGTH = 65;

  private final byte[] encoded;
  public final int type;
  private final byte[] samSki;
  public final long eventSeq;
  private final byte[] prevHead;

  // GENESIS
  private final byte[] samCertificateSha256;
  private final byte[] paramsDigest;
  public final long quota;
  public final long timestamp;

  // ISSUE
  public final long issuanceSeq;
  public final String opid;
  private final byte[] f9Ski;
  private final byte[] tbsHash;

  // TOPUP
  public final long added;

  // TERM, CLOSE
  public final long issued;

  // VOID
  public final int reason;

  private SamLedgerEntry(byte[] entry) {
    if (entry.length < HEADER_LENGTH
        || !Arrays.equals(Arrays.copyOf(entry, PREFIX.length), PREFIX)) {
      throw new IllegalArgumentException("SAM ledger entry lacks the OPSAMLE1 header");
    }
    this.encoded = entry.clone();
    this.type = entry[8] & 0xFF;
    this.samSki = Arrays.copyOfRange(entry, 9, 29);
    this.eventSeq = IssuanceCrypto.unsigned(entry, 29, 4);
    this.prevHead = Arrays.copyOfRange(entry, 33, 65);
    int p = HEADER_LENGTH;
    byte[] certHash = null;
    byte[] digest = null;
    long quotaValue = -1;
    long ts = -1;
    long seq = -1;
    String opidValue = null;
    byte[] ski = null;
    byte[] tbs = null;
    long addedValue = -1;
    long issuedValue = -1;
    int reasonValue = -1;
    switch (type) {
      case TYPE_GENESIS:
        requireLength(entry, p + 32 + 32 + 4 + 8);
        certHash = Arrays.copyOfRange(entry, p, p + 32);
        digest = Arrays.copyOfRange(entry, p + 32, p + 64);
        quotaValue = IssuanceCrypto.unsigned(entry, p + 64, 4);
        ts = IssuanceCrypto.unsigned(entry, p + 68, 8);
        break;
      case TYPE_ISSUE:
        if (entry.length < p + 5) {
          throw new IllegalArgumentException("SAM ISSUE entry is truncated");
        }
        seq = IssuanceCrypto.unsigned(entry, p, 4);
        int opidLength = entry[p + 4] & 0xFF;
        requireLength(entry, p + 5 + opidLength + 20 + 32);
        opidValue = new String(entry, p + 5, opidLength, StandardCharsets.US_ASCII);
        ski = Arrays.copyOfRange(entry, p + 5 + opidLength, p + 25 + opidLength);
        tbs = Arrays.copyOfRange(entry, p + 25 + opidLength, p + 57 + opidLength);
        break;
      case TYPE_TOPUP:
        requireLength(entry, p + 16);
        ts = IssuanceCrypto.unsigned(entry, p, 8);
        addedValue = IssuanceCrypto.unsigned(entry, p + 8, 4);
        quotaValue = IssuanceCrypto.unsigned(entry, p + 12, 4);
        break;
      case TYPE_TERMINATE:
      case TYPE_CLOSE:
        requireLength(entry, p + 8);
        issuedValue = IssuanceCrypto.unsigned(entry, p, 4);
        quotaValue = IssuanceCrypto.unsigned(entry, p + 4, 4);
        break;
      case TYPE_VOID:
        if (entry.length < p + 5) {
          throw new IllegalArgumentException("SAM VOID entry is truncated");
        }
        seq = IssuanceCrypto.unsigned(entry, p, 4);
        int voidLength = entry[p + 4] & 0xFF;
        requireLength(entry, p + 5 + voidLength + 1);
        opidValue = new String(entry, p + 5, voidLength, StandardCharsets.US_ASCII);
        reasonValue = entry[p + 5 + voidLength] & 0xFF;
        break;
      default:
        throw new IllegalArgumentException("unknown SAM ledger entry type " + type);
    }
    this.samCertificateSha256 = certHash;
    this.paramsDigest = digest;
    this.quota = quotaValue;
    this.timestamp = ts;
    this.issuanceSeq = seq;
    this.opid = opidValue;
    this.f9Ski = ski;
    this.tbsHash = tbs;
    this.added = addedValue;
    this.issued = issuedValue;
    this.reason = reasonValue;
  }

  public static SamLedgerEntry parse(byte[] entry) {
    if (entry == null) {
      throw new IllegalArgumentException("SAM ledger entry is required");
    }
    return new SamLedgerEntry(entry);
  }

  private static void requireLength(byte[] entry, int length) {
    if (entry.length != length) {
      throw new IllegalArgumentException(
          "SAM ledger entry is " + entry.length + " octets, expected " + length);
    }
  }

  public byte[] encoded() {
    return encoded.clone();
  }

  public byte[] head() {
    return IssuanceCrypto.sha256(encoded);
  }

  public byte[] samSki() {
    return samSki.clone();
  }

  public byte[] prevHead() {
    return prevHead.clone();
  }

  public byte[] samCertificateSha256() {
    return copy(samCertificateSha256);
  }

  public byte[] paramsDigest() {
    return copy(paramsDigest);
  }

  public byte[] f9Ski() {
    return copy(f9Ski);
  }

  public byte[] tbsHash() {
    return copy(tbsHash);
  }

  /** Whether {@code signature} is the SAM's ECDSA signature over this entry. */
  public boolean verify(byte[] signature, PublicKey samKey) {
    return IssuanceCrypto.verify(samKey, encoded, signature);
  }

  public String typeName() {
    switch (type) {
      case TYPE_GENESIS:
        return "GENESIS";
      case TYPE_ISSUE:
        return "ISSUE";
      case TYPE_TOPUP:
        return "TOPUP";
      case TYPE_VOID:
        return "VOID";
      case TYPE_CLOSE:
        return "CLOSE";
      default:
        return "TERM";
    }
  }

  private static byte[] copy(byte[] value) {
    return value == null ? null : value.clone();
  }

  /** A ledger entry with the SAM signature that accompanied it. */
  public static final class Signed {
    public final SamLedgerEntry entry;
    private final byte[] signature;

    public Signed(SamLedgerEntry entry, byte[] signature) {
      this.entry = entry;
      this.signature = signature == null ? null : signature.clone();
    }

    /** Parses {@code 71 L entry [72 L sig]} with nothing trailing. */
    public static Signed parse(byte[] data) {
      BerTlvReader.Tlv entryTlv = BerTlvReader.read(data, 0);
      if (entryTlv.tag != 0x71) {
        throw new IllegalArgumentException("SAM response does not begin with a 71 entry");
      }
      SamLedgerEntry entry =
          SamLedgerEntry.parse(Arrays.copyOfRange(data, entryTlv.valueOffset, entryTlv.nextOffset));
      if (entryTlv.nextOffset == data.length) {
        return new Signed(entry, null);
      }
      BerTlvReader.Tlv sigTlv = BerTlvReader.read(data, entryTlv.nextOffset);
      if (sigTlv.tag != 0x72 || sigTlv.nextOffset != data.length) {
        throw new IllegalArgumentException("SAM entry response must end with one 72 signature");
      }
      return new Signed(entry, Arrays.copyOfRange(data, sigTlv.valueOffset, sigTlv.nextOffset));
    }

    public byte[] signature() {
      return signature == null ? null : signature.clone();
    }

    /** Whether the signature is present and verifies under {@code samKey}. */
    public boolean verify(PublicKey samKey) {
      return signature != null && entry.verify(signature, samKey);
    }
  }
}
