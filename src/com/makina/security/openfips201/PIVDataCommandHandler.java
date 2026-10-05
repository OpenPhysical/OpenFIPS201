/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2017 Commonwealth of Australia
 ******************************************************************************/

package com.makina.security.openfips201;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/** Handles standard PIV discovery and GET/PUT DATA commands. */
final class PIVDataCommandHandler {
  private static final short ZERO = (short) 0;
  static final short INVALID_DISCOVERY_POLICY = (short) -1;

  // SP 800-73-5 Part 1 Section 3.3.2, first byte of the PIN Usage Policy
  // "Bit 7 is set to 1 to indicate that the mandatory PIV Card Application PIN satisfies the PIV
  // Access Control Rules (ACRs)"
  static final byte PIN_POLICY_APPLICATION_PIN = (byte) 0x40;
  // "Bit 6 indicates whether the optional Global PIN satisfies the PIV ACRs"
  static final byte PIN_POLICY_GLOBAL_PIN = (byte) 0x20;
  // "Bit 5 indicates whether the optional OCC satisfies the PIV ACRs"
  static final byte PIN_POLICY_OCC = (byte) 0x10;
  // "Bit 4 indicates whether the optional VCI is implemented."
  static final byte PIN_POLICY_VCI = (byte) 0x08;
  // "Bit 3 is set to zero if the pairing code is required to establish a VCI and is set to one if
  // a VCI is established without a pairing code."
  static final byte PIN_POLICY_VCI_WITHOUT_PAIRING = (byte) 0x04;
  // "Bits 8, 2, and 1 of the first byte SHALL be set to zero."
  private static final byte PIN_POLICY_ZERO_BITS = (byte) 0x83;
  // Second byte: "0x10 indicates that the PIV Card Application PIN is the primary PIN" and "0x20
  // indicates that the Global PIN is the primary PIN"
  private static final byte PIN_PREFERENCE_APPLICATION_PIN = (byte) 0x10;
  private static final byte PIN_PREFERENCE_GLOBAL_PIN = (byte) 0x20;

  // Position of the pairing code value inside the stored 5FC123 object '53 0C 99 08 ...'
  static final short PAIRING_CODE_OFFSET = (short) 4;
  static final short PAIRING_CODE_LENGTH = (short) 8;

  // SP 800-73-5 Part 1 Section 3.3.6, footnote 6: "A BIT Group Template with no BITs is encoded as
  // '7F 61 03 02 01 00'."
  private static final byte[] EMPTY_BIT_GROUP_TEMPLATE = {
    (byte) 0x7F, (byte) 0x61, (byte) 0x03, (byte) 0x02, (byte) 0x01, (byte) 0x00
  };
  private static final byte[] PIV_AID = {
    (byte) 0xA0,
    (byte) 0x00,
    (byte) 0x00,
    (byte) 0x03,
    (byte) 0x08,
    (byte) 0x00,
    (byte) 0x00,
    (byte) 0x10,
    (byte) 0x00,
    (byte) 0x01,
    (byte) 0x00
  };

  private final Config config;
  private final PIVSecurityProvider security;
  private final PIVDataStore dataStore;
  private final ChainBuffer chainBuffer;
  private final byte[] scratch;

  PIVDataCommandHandler(
      Config config,
      PIVSecurityProvider security,
      PIVDataStore dataStore,
      ChainBuffer chainBuffer,
      byte[] scratch) {
    this.config = config;
    this.security = security;
    this.dataStore = dataStore;
    this.chainBuffer = chainBuffer;
    this.scratch = scratch;
  }

  short getData(byte[] buffer, short offset, short length, boolean vciSatisfied) {
    if (buffer[offset++] != (byte) 0x5C) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    short idLength = (short) (buffer[offset++] & 0xFF);
    if (idLength < (short) 1 || idLength > (short) 3) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    if (length != (short) (idLength + (short) 2)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    PIVDataObject object = dataStore.find(buffer, offset, idLength);
    if (object == null) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
      return ZERO;
    }
    if (!security.checkAccessModeObject(object, vciSatisfied, isGlobalPinAdvertised())) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    short responseLength;
    byte[] data;
    if (object.isInitialised()) {
      responseLength = object.getLength();
      data = object.content;
    } else if (isDiscoveryDataObject(buffer, offset, idLength)) {
      responseLength = buildDiscoveryObject(scratch, ZERO);
      data = scratch;
    } else if (idLength == (short) 2
        && buffer[offset] == (byte) 0x7F
        && buffer[(short) (offset + 1)] == (byte) 0x61) {
      // SP 800-73-5 Part 2 Section 3.1.2 returns the "BER-TLV of the 0x7F61 BIT Group Template"
      // rather than a '53' container. OCC is not implemented, so the template has no BITs.
      responseLength = (short) EMPTY_BIT_GROUP_TEMPLATE.length;
      data = EMPTY_BIT_GROUP_TEMPLATE;
    } else {
      // SP 800-73-5 Part 1 Section 4.1: "data objects that are created but not used SHALL be set
      // to zero-length value." They are returned as an empty '53' container.
      scratch[ZERO] = PIV.CONST_TAG_DATA;
      scratch[(short) 1] = (byte) 0x00;
      responseLength = (short) 2;
      data = scratch;
    }
    chainBuffer.setOutgoing(data, ZERO, responseLength, false);
    return responseLength;
  }

  /** Returns whether a valid {@code policy} has every bit of {@code bits} in its first byte set. */
  static boolean hasPolicyBits(short policy, byte bits) {
    return policy != INVALID_DISCOVERY_POLICY && (byte) ((byte) (policy >> 8) & bits) == bits;
  }

  boolean isGlobalPinAdvertised() {
    return hasPolicyBits(getDiscoveryPolicy(), PIN_POLICY_GLOBAL_PIN);
  }

  /**
   * Returns whether a stored PIN Usage Policy describes only features this applet provides.
   *
   * <p>SP 800-73-5 Part 1 Section 3.3.2: bit 6 "indicates whether the optional Global PIN satisfies
   * the PIV ACRs", bit 5 "whether the optional OCC satisfies the PIV ACRs" and bit 4 "whether the
   * optional VCI is implemented". OCC is not implemented, so bit 5 must be clear. The Global PIN
   * bit requires the Global PIN to be enabled, and the VCI bit must match the VCI configuration.
   * With VCI, bit 3 must state the configured pairing requirement.
   *
   * @param policy validated policy from {@link #getDiscoveryPolicy()}
   * @param globalPinEnabled whether the Global PIN is enabled in the configuration
   * @param vciMode configured {@link Config#CONFIG_VCI_MODE}
   */
  static boolean isDiscoveryPolicyConsistent(short policy, boolean globalPinEnabled, byte vciMode) {
    if (policy == INVALID_DISCOVERY_POLICY) return false;
    if (hasPolicyBits(policy, PIN_POLICY_OCC)) return false;
    if (hasPolicyBits(policy, PIN_POLICY_GLOBAL_PIN) && !globalPinEnabled) return false;
    boolean vciConfigured = vciMode != Config.VCI_MODE_DISABLED;
    if (hasPolicyBits(policy, PIN_POLICY_VCI) != vciConfigured) return false;
    return !vciConfigured
        || hasPolicyBits(policy, PIN_POLICY_VCI_WITHOUT_PAIRING)
            == (vciMode != Config.VCI_MODE_PAIRING_CODE);
  }

  /**
   * Returns the validated PIN Usage Policy, or -1 when the stored Discovery Object is absent or
   * invalid.
   */
  short getDiscoveryPolicy() {
    PIVDataObject discovery = dataStore.findSingleByte(PIV.ID_DATA_DISCOVERY);
    if (discovery == null || !discovery.isInitialised()) return INVALID_DISCOVERY_POLICY;

    byte[] content = discovery.content;
    short total = discovery.getLength();
    try {
      if (total < (short) 2 || content[ZERO] != (byte) 0x7E) return INVALID_DISCOVERY_POLICY;
      short outerLength = TLVReader.getLength(content, ZERO);
      short cursor = TLVReader.getDataOffset(content, ZERO);
      short end = (short) (cursor + outerLength);
      if (end < cursor || end != total) return INVALID_DISCOVERY_POLICY;

      // SP 800-73-5 Part 1, Section 3.3.2 fixes the Discovery Object to 4F(AID),
      // followed by the two-byte 5F2F PIN Usage Policy.
      if (cursor >= end || content[cursor] != (byte) 0x4F) return INVALID_DISCOVERY_POLICY;
      short aidLength = TLVReader.getLength(content, cursor);
      short aidOffset = TLVReader.getDataOffset(content, cursor);
      if (aidLength != (short) 11 || !isPivAid(content, aidOffset)) {
        return INVALID_DISCOVERY_POLICY;
      }
      cursor = (short) (aidOffset + aidLength);
      if ((short) (cursor + 2) >= end
          || content[cursor] != (byte) 0x5F
          || content[(short) (cursor + 1)] != (byte) 0x2F) {
        return INVALID_DISCOVERY_POLICY;
      }
      short policyLength = TLVReader.getLength(content, cursor);
      short policyOffset = TLVReader.getDataOffset(content, cursor);
      if (policyLength != (short) 2 || (short) (policyOffset + policyLength) != end) {
        return INVALID_DISCOVERY_POLICY;
      }
      byte first = content[policyOffset];
      byte second = content[(short) (policyOffset + 1)];
      // "Table 1 lists the acceptable values for the first byte of the PIN Usage Policy": 0x40,
      // 0x48, 0x4C, 0x50, 0x58, 0x5C, 0x60, 0x68, 0x6C, 0x70, 0x78 and 0x7C. Bit 7 is set, bits 8,
      // 2 and 1 are zero, and bit 3 (VCI without pairing) occurs only with bit 4 (VCI).
      if ((first & PIN_POLICY_ZERO_BITS) != (byte) 0
          || (first & PIN_POLICY_APPLICATION_PIN) == (byte) 0
          || (byte) (first & (byte) (PIN_POLICY_VCI | PIN_POLICY_VCI_WITHOUT_PAIRING))
              == PIN_POLICY_VCI_WITHOUT_PAIRING) {
        return INVALID_DISCOVERY_POLICY;
      }
      // "If Bit 6 of the first byte of the PIN Usage Policy is set to zero, then the second byte
      // is RFU and SHALL be set to 0x00."
      if ((first & PIN_POLICY_GLOBAL_PIN) == (byte) 0) {
        if (second != (byte) 0x00) return INVALID_DISCOVERY_POLICY;
      } else if (second != PIN_PREFERENCE_APPLICATION_PIN && second != PIN_PREFERENCE_GLOBAL_PIN) {
        return INVALID_DISCOVERY_POLICY;
      }
      return (short) (((short) (first & 0xFF) << 8) | (short) (second & 0xFF));
    } catch (RuntimeException ignored) {
      return INVALID_DISCOVERY_POLICY;
    }
  }

  private static boolean isPivAid(byte[] content, short offset) {
    for (short index = ZERO; index < (short) PIV_AID.length; index++) {
      if (content[(short) (offset + index)] != PIV_AID[index]) {
        return false;
      }
    }
    return true;
  }

  void putData(byte[] buffer, short offset, short length, boolean vciSatisfied, byte protection) {
    final short initialOffset = offset;
    final short end = (short) (offset + length);
    if (length <= ZERO || end < offset || end > (short) buffer.length) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    short idOffset = offset;
    short idLength;

    switch (buffer[offset]) {
      case (byte) 0x7E:
        idLength = (short) 1;
        break;
      case (byte) 0x7F:
        if ((short) (offset + 1) >= end) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        if (buffer[(short) (offset + 1)] != (byte) 0x61) {
          ISOException.throwIt(PIV.SW_REFERENCE_NOT_FOUND);
        }
        idLength = (short) 2;
        break;
      case (byte) 0x5C:
        if ((short) (offset + 1) >= end) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        offset++;
        idLength = (short) (buffer[offset] & 0xFF);
        if (idLength < (short) 1 || idLength > (short) 3) {
          ISOException.throwIt(PIV.SW_REFERENCE_NOT_FOUND);
        }
        offset++;
        idOffset = offset;
        if ((short) (offset + idLength) < offset || (short) (offset + idLength) >= end) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        offset += idLength;
        if ((short) (offset - initialOffset) >= length) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (buffer[offset] != PIV.CONST_TAG_DATA) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
          return;
        }
        break;
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return;
    }

    PIVDataObject object = dataStore.find(buffer, idOffset, idLength);
    if (object == null) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
      return;
    }
    if (!security.checkAccessModeAdmin(object, vciSatisfied, isGlobalPinAdvertised())) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // The tag and length fields must lie inside this frame; the value may continue in later
    // chained frames.
    short valueOffset = TLV.dataOffset(buffer, offset, end, false);
    short objectLength = TLV.readLength(buffer, offset, end, false);
    if (objectLength == 0) {
      // SP 800-73-5 Part 2 Section 3.3.1 Table 10: the data field is the tag list followed by the
      // '53' object only. An empty object is complete in this frame, so neither trailing bytes nor
      // an announced continuation (ISO/IEC 7816-4 Section 5.3.3: "If bit b5 is set to 1, then the
      // command is not the last command of a chain.") belong to it.
      if (valueOffset != end || (buffer[ISO7816.OFFSET_CLA] & ChainBuffer.CLA_CHAINING) != 0) {
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }
      object.clear();
      return;
    }

    objectLength += (short) (valueOffset - offset);
    length -= (short) (offset - initialOffset);
    chainBuffer.setIncomingObject(object, objectLength);
    chainBuffer.processIncomingObject(buffer, offset, length, protection);
  }

  private short buildDiscoveryObject(byte[] buffer, short offset) {
    short length = (short) Config.TEMPLATE_DISCOVERY.length;
    offset = Util.arrayCopyNonAtomic(Config.TEMPLATE_DISCOVERY, ZERO, buffer, offset, length);
    offset -= (short) 2;
    // A synthesized Discovery Object advertises neither VCI nor the Global PIN: SP 800-73-5 Part 1
    // Sections 3.3.2 and 5.5 make the issuer-stored Discovery Object the source of both policies.
    buffer[offset++] =
        config.readFlag(Config.CONFIG_PIN_ENABLE_LOCAL) ? PIN_POLICY_APPLICATION_PIN : (byte) 0;
    buffer[offset] = (byte) 0x00;
    return length;
  }

  private static boolean isDiscoveryDataObject(byte[] idBuffer, short idOffset, short idLength) {
    if (idLength < (short) 1 || idLength > (short) 3) return false;
    short leading = (short) (idLength - (short) 1);
    for (short index = ZERO; index < leading; index++) {
      if (idBuffer[(short) (idOffset + index)] != (byte) 0) return false;
    }
    return idBuffer[(short) (idOffset + leading)] == PIV.ID_DATA_DISCOVERY;
  }

  static boolean isStructurallyValidMandatoryObject(PIVDataObject object, byte suffix) {
    if (object == null || !object.isInitialised() || object.getLength() < (short) 2) return false;

    // SP 800-73-5 Part 1 Sections 3 and 4 require complete BER-TLV containers before the
    // irreversible personalization transition.
    byte[] content = object.content;
    short limit = object.getLength();
    short offset = (short) 0;

    // SP 800-73-5 Part 2 Section 3.3.1 defines PUT DATA as 5C <tag list> followed by
    // 53 <data>. PIVDataObject stores that complete 53 data object, so validate its value rather
    // than treating the outer container as the first Part 1 data element.
    if (content[offset] != PIV.CONST_TAG_DATA) return false;
    if (TLV.endOrInvalid(content, offset, limit, false) != limit) return false;
    offset = TLV.valueOffsetOrInvalid(content, offset, limit, false);
    if (offset >= limit) return false;
    if (suffix == (byte) 0x05 || suffix == (byte) 0x01) {
      offset = element(content, offset, limit, (byte) 0x70, (short) -1);
      offset = element(content, offset, limit, (byte) 0x71, (short) 1);
      return element(content, offset, limit, (byte) 0xFE, (short) 0) == limit;
    }
    if (suffix == (byte) 0x06) {
      short mappingLength = valueLength(content, offset, limit, (byte) 0xBA);
      if (mappingLength <= (short) 0 || (short) (mappingLength % (short) 3) != (short) 0) {
        return false;
      }
      offset = element(content, offset, limit, (byte) 0xBA, (short) -1);
      if (valueLength(content, offset, limit, (byte) 0xBB) <= (short) 0) return false;
      offset = element(content, offset, limit, (byte) 0xBB, (short) -1);
      return offset == limit || element(content, offset, limit, (byte) 0xFE, (short) 0) == limit;
    }
    if (suffix == (byte) 0x0C) {
      // SP 800-73-5 Part 1 Table 20: keysWithOnCardCerts 'C1' and keysWithOffCardCerts 'C2' (one
      // byte each), the conditional offCardCertURL 'F3' and the Error Detection Code 'FE'.
      // Footnote 25: "The offCardCertURL data element shall be present if keysWithOffCardCerts is
      // greater than zero and shall be absent if both keysWithOnCardCerts and keysWithOffCardCerts
      // are zero."
      short onCard = valueOffsetOf(content, offset, limit, (byte) 0xC1, (short) 1);
      offset = element(content, offset, limit, (byte) 0xC1, (short) 1);
      short offCard = valueOffsetOf(content, offset, limit, (byte) 0xC2, (short) 1);
      offset = element(content, offset, limit, (byte) 0xC2, (short) 1);
      if (onCard < (short) 0 || offCard < (short) 0) return false;
      boolean url = offset >= (short) 0 && offset < limit && content[offset] == (byte) 0xF3;
      if (url) {
        if (valueLength(content, offset, limit, (byte) 0xF3) <= (short) 0) return false;
        offset = element(content, offset, limit, (byte) 0xF3, (short) -1);
      }
      if (content[offCard] != (byte) 0 && !url) return false;
      if (content[onCard] == (byte) 0 && content[offCard] == (byte) 0 && url) return false;
      return element(content, offset, limit, (byte) 0xFE, (short) 0) == limit;
    }
    while (offset < limit) {
      offset = TLV.endOrInvalid(content, offset, limit, false);
      if (offset == TLV.INVALID) return false;
    }
    return true;
  }

  /**
   * Returns whether {@code object} holds a well-formed Pairing Code Reference Data Container.
   *
   * <p>SP 800-73-5 Part 1 Table 44: Pairing Code '99', "Fixed Text (ASCII)", 8 bytes, followed by
   * the Error Detection Code 'FE' with no value. The stored PUT DATA object is therefore exactly
   * {@code 53 0C 99 08 <8 ASCII digits> FE 00}. SP 800-73-5 Part 1 Section 5.1.3: "the pairing code
   * SHALL consist of eight decimal digits".
   */
  static boolean isValidPairingCodeContainer(PIVDataObject object) {
    if (object == null
        || !object.isInitialised()
        || object.getLength() != (short) 14
        || object.content[ZERO] != PIV.CONST_TAG_DATA
        || object.content[(short) 1] != (byte) 0x0C) {
      return false;
    }
    byte[] content = object.content;
    short offset = element(content, (short) 2, (short) 14, (byte) 0x99, PAIRING_CODE_LENGTH);
    if (element(content, offset, (short) 14, (byte) 0xFE, (short) 0) != (short) 14) return false;
    return isDecimalDigits(content, PAIRING_CODE_OFFSET, PAIRING_CODE_LENGTH);
  }

  /** Returns whether every byte of the range is an ASCII decimal digit. */
  static boolean isDecimalDigits(byte[] buffer, short offset, short length) {
    for (short index = ZERO; index < length; index++) {
      byte value = buffer[(short) (offset + index)];
      if (value < (byte) 0x30 || value > (byte) 0x39) return false;
    }
    return true;
  }

  /**
   * Returns the end of the single-byte-tag element at {@code offset}, or {@link TLV#INVALID} when
   * {@code offset} is already invalid, the tag differs, the element is malformed, or its value
   * length differs from {@code expectedLength} (negative means any length).
   */
  private static short element(
      byte[] data, short offset, short limit, byte tag, short expectedLength) {
    short length = valueLength(data, offset, limit, tag);
    if (length < (short) 0 || (expectedLength >= (short) 0 && length != expectedLength)) {
      return TLV.INVALID;
    }
    return TLV.endOrInvalid(data, offset, limit, false);
  }

  /**
   * Returns the value offset of an element accepted by {@link #element}, or {@link TLV#INVALID}.
   */
  private static short valueOffsetOf(
      byte[] data, short offset, short limit, byte tag, short expectedLength) {
    if (element(data, offset, limit, tag, expectedLength) == TLV.INVALID) return TLV.INVALID;
    return TLV.valueOffsetOrInvalid(data, offset, limit, false);
  }

  /** Returns the value length of a complete element with {@code tag}, or {@link TLV#INVALID}. */
  private static short valueLength(byte[] data, short offset, short limit, byte tag) {
    if (offset < (short) 0
        || offset >= limit
        || data[offset] != tag
        || TLV.endOrInvalid(data, offset, limit, false) == TLV.INVALID) {
      return TLV.INVALID;
    }
    return TLV.valueLengthOrInvalid(data, offset, limit, false);
  }
}
