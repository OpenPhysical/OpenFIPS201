/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import dev.mistial.tools.openfips201.common.BerTlvReader;
import dev.mistial.tools.openfips201.common.ByteArrays;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * Issuer SAM STATUS (GET DATA P1=00 P2=01): 80 lifecycle, 82 IIN (4 ASCII digits), 83 batch (4
 * ASCII digits), 85 issued, 86 quota, 87 m, 88 lastTopUpTs, 89 eventSeq, 8A chainHead, 8B samSki,
 * 8C PIN state (set flag, tries remaining), 8E version, 8F allocationSeq, 90 registryHead. Tags
 * this parser does not name are skipped.
 */
public final class SamStatus {
  public static final byte LC_INSTALLED = (byte) 0x5A;
  public static final byte LC_PARAMS_SET = (byte) 0x69;
  public static final byte LC_KEY_GENERATED = (byte) 0x96;
  public static final byte LC_CERT_LOADED = (byte) 0xA5;
  public static final byte LC_OPERATIONAL = (byte) 0xC3;
  public static final byte LC_TERMINATED = (byte) 0x3C;
  public static final byte LC_CLOSED = (byte) 0xE1;

  /** Domain prefix of the SAM-signed STATUS: {@code "OPSAMSTAT1" || nonce || statusTLV}. */
  static final byte[] PREFIX_STATUS = "OPSAMSTAT1".getBytes(StandardCharsets.US_ASCII);

  private final byte[] encoded;
  public final byte lifecycle;
  public final String iin;
  public final String batch;
  public final long issued;
  public final long quota;
  public final long modulus;
  public final long lastTopUpTs;
  public final long eventSeq;
  private final byte[] chainHead;
  private final byte[] samSki;
  public final boolean pinSet;
  public final int pinTries;
  public final long allocationSeq;
  private final byte[] registryHead;

  private SamStatus(byte[] encoded) {
    this.encoded = encoded.clone();
    byte lc = 0;
    String iinDigits = "";
    String batchDigits = "";
    long issuedValue = 0;
    long quotaValue = 0;
    long m = 0;
    long ts = 0;
    long event = 0;
    byte[] head = new byte[0];
    byte[] ski = new byte[0];
    boolean set = false;
    int tries = 0;
    long allocation = -1;
    byte[] registry = new byte[0];
    int offset = 0;
    while (offset < encoded.length) {
      BerTlvReader.Tlv tlv = BerTlvReader.read(encoded, offset);
      byte[] value = Arrays.copyOfRange(encoded, tlv.valueOffset, tlv.nextOffset);
      switch (tlv.tag) {
        case 0x80:
          lc = single(value);
          break;
        case 0x82:
          iinDigits = new String(value, StandardCharsets.US_ASCII);
          break;
        case 0x83:
          batchDigits = new String(value, StandardCharsets.US_ASCII);
          break;
        case 0x85:
          issuedValue = IssuanceCrypto.unsigned(value, 0, value.length);
          break;
        case 0x86:
          quotaValue = IssuanceCrypto.unsigned(value, 0, value.length);
          break;
        case 0x87:
          m = IssuanceCrypto.unsigned(value, 0, value.length);
          break;
        case 0x88:
          ts = IssuanceCrypto.unsigned(value, 0, value.length);
          break;
        case 0x89:
          event = IssuanceCrypto.unsigned(value, 0, value.length);
          break;
        case 0x8A:
          head = value;
          break;
        case 0x8B:
          ski = value;
          break;
        case 0x8C:
          if (value.length != 2) {
            throw new IllegalArgumentException("SAM STATUS PIN state must be two octets");
          }
          set = value[0] == 0x01;
          tries = value[1] & 0xFF;
          break;
        case 0x8F:
          allocation = IssuanceCrypto.unsigned(value, 0, value.length);
          break;
        case 0x90:
          registry = value;
          break;
        default:
          break;
      }
      offset = tlv.nextOffset;
    }
    this.lifecycle = lc;
    this.iin = iinDigits;
    this.batch = batchDigits;
    this.issued = issuedValue;
    this.quota = quotaValue;
    this.modulus = m;
    this.lastTopUpTs = ts;
    this.eventSeq = event;
    this.chainHead = head;
    this.samSki = ski;
    this.pinSet = set;
    this.pinTries = tries;
    this.allocationSeq = allocation;
    this.registryHead = registry;
  }

  public byte[] registryHead() {
    return registryHead.clone();
  }

  public boolean isClosed() {
    return lifecycle == LC_CLOSED;
  }

  public static SamStatus parse(byte[] encoded) {
    if (encoded == null || encoded.length == 0) {
      throw new IllegalArgumentException("SAM STATUS is empty");
    }
    return new SamStatus(encoded);
  }

  /**
   * Parses a signed STATUS response {@code statusTLV || 9E L sig} and verifies the signature over
   * {@code "OPSAMSTAT1" || nonce || statusTLV} with {@code samKey}.
   *
   * @throws IllegalStateException when the signature does not verify
   */
  public static SamStatus parseSigned(byte[] response, byte[] nonce, PublicKey samKey) {
    int offset = 0;
    int statusEnd = -1;
    byte[] signature = null;
    while (offset < response.length) {
      BerTlvReader.Tlv tlv = BerTlvReader.read(response, offset);
      if (tlv.tag == 0x9E) {
        if (tlv.nextOffset != response.length) {
          throw new IllegalArgumentException("signed SAM STATUS has data after the signature");
        }
        statusEnd = offset;
        signature = Arrays.copyOfRange(response, tlv.valueOffset, tlv.nextOffset);
      }
      offset = tlv.nextOffset;
    }
    if (signature == null) {
      throw new IllegalArgumentException("signed SAM STATUS carries no signature");
    }
    byte[] status = Arrays.copyOfRange(response, 0, statusEnd);
    if (!IssuanceCrypto.verify(
        samKey, ByteArrays.concat(PREFIX_STATUS, nonce, status), signature)) {
      throw new IllegalStateException("SAM STATUS signature does not verify under the SAM key");
    }
    return parse(status);
  }

  private static byte single(byte[] value) {
    if (value.length != 1) {
      throw new IllegalArgumentException("SAM STATUS field must be one octet");
    }
    return value[0];
  }

  public byte[] encoded() {
    return encoded.clone();
  }

  public byte[] chainHead() {
    return chainHead.clone();
  }

  public byte[] samSki() {
    return samSki.clone();
  }

  public boolean isOperational() {
    return lifecycle == LC_OPERATIONAL;
  }

  public long remaining() {
    return quota - issued;
  }

  public static String lifecycleName(byte lifecycle) {
    switch (lifecycle) {
      case LC_INSTALLED:
        return "INSTALLED";
      case LC_PARAMS_SET:
        return "PARAMS_SET";
      case LC_KEY_GENERATED:
        return "KEY_GENERATED";
      case LC_CERT_LOADED:
        return "CERT_LOADED";
      case LC_OPERATIONAL:
        return "OPERATIONAL";
      case LC_TERMINATED:
        return "TERMINATED";
      case LC_CLOSED:
        return "CLOSED";
      default:
        return String.format("UNKNOWN(%02X)", lifecycle & 0xFF);
    }
  }
}
