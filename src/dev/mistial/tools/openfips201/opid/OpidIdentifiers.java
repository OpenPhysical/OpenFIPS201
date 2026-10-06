/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.opid;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.util.encoders.Hex;

/**
 * Card identifiers derived from an OPID. Every derivation starts from the 17 digits D = {@link
 * Opid#toPrinted()}.
 */
public final class OpidIdentifiers {
  /** GUID node field: ASCII "OPNPHY". */
  public static final String GUID_NODE_HEX = "4F504E504859";

  public static final int FASCN_AGENCY_CODE = 9999;
  public static final int FASCN_SYSTEM_CODE = 9999;
  public static final int FASCN_CREDENTIAL_NUMBER = 999999;

  /** FASC-N Organizational Category 3: commercial enterprise. */
  public static final int FASCN_ORGANIZATIONAL_CATEGORY = 3;

  /** FASC-N Person/Organization Association Category 6: organizational affiliate. Fixed. */
  public static final int FASCN_PERSON_ASSOCIATION = 6;

  private static final byte[] CCC_CARD_IDENTIFIER_PREFIX = {
    (byte) 0xF0, 0x15, 0x00, 0x00, 0x00, 0x00
  };

  private OpidIdentifiers() {}

  /**
   * Returns the 32 hex digits of the RFC 9562 UUIDv8 {@code D[0..8] || D[8..12] || "8" || D[12..15]
   * || "8" || "0" || D[15..17] || "4F504E504859"}: version nibble 8, variant nibble 8.
   */
  public static String guidHex(Opid opid) {
    String d = opid.toPrinted();
    return d.substring(0, 12)
        + "8"
        + d.substring(12, 15)
        + "80"
        + d.substring(15, 17)
        + GUID_NODE_HEX;
  }

  /** Returns the 16 GUID bytes in big-endian (network) order, the value of CHUID tag 0x34. */
  public static byte[] guidBytes(Opid opid) {
    return Hex.decode(guidHex(opid));
  }

  /** Returns {@code DDDDDDDD-DDDD-8DDD-80DD-4F504E504859}, upper case. */
  public static String guidString(Opid opid) {
    String hex = guidHex(opid);
    return hex.substring(0, 8)
        + "-"
        + hex.substring(8, 12)
        + "-"
        + hex.substring(12, 16)
        + "-"
        + hex.substring(16, 20)
        + "-"
        + hex.substring(20, 32);
  }

  /** Returns the ITU-T X.667 UUID OID {@code 2.25.<GUID as unsigned 128-bit integer>}. */
  public static String uuidOid(Opid opid) {
    return "2.25." + new BigInteger(1, guidBytes(opid)).toString();
  }

  /** Returns the 23-byte CCC card identifier TLV {@code F0 15 || 00 00 00 00 || ASCII(D)}. */
  public static byte[] cccCardIdentifier(Opid opid) {
    byte[] digits = opid.toPrinted().getBytes(StandardCharsets.US_ASCII);
    byte[] out = new byte[CCC_CARD_IDENTIFIER_PREFIX.length + digits.length];
    System.arraycopy(CCC_CARD_IDENTIFIER_PREFIX, 0, out, 0, CCC_CARD_IDENTIFIER_PREFIX.length);
    System.arraycopy(digits, 0, out, CCC_CARD_IDENTIFIER_PREFIX.length, digits.length);
    return out;
  }

  /**
   * Returns the PIV-I FASC-N: Agency/System/Credential {@code 9999 9999 999999}; CS = E[2]; ICI =
   * E[3]; PI = E[0] E[1] E[4..12] (10 digits); OC = 3; OI = IIN; POA = 6. E is fixed by the OPID,
   * so the FASC-N is unique per OPID.
   */
  public static FascN fascN(Opid opid) {
    String e = Digits.pad(opid.e, Opid.E_DIGITS);
    return new FascN(
        FASCN_AGENCY_CODE,
        FASCN_SYSTEM_CODE,
        FASCN_CREDENTIAL_NUMBER,
        e.charAt(2) - '0',
        e.charAt(3) - '0',
        Long.parseLong(e.substring(0, 2) + e.substring(4, 12)),
        FASCN_ORGANIZATIONAL_CATEGORY,
        opid.iin,
        FASCN_PERSON_ASSOCIATION);
  }

  /** Returns the 25-byte encoded {@link #fascN}, the value of CHUID tag 0x30. */
  public static byte[] fascNBytes(Opid opid) {
    return FascNCodec.encode(fascN(opid));
  }
}
