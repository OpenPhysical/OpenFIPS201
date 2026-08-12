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
  private static final short INVALID_DISCOVERY_POLICY = (short) -1;
  private static final byte[] PIV_AID = {
    (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x08, (byte) 0x00,
    (byte) 0x00, (byte) 0x10, (byte) 0x00, (byte) 0x01, (byte) 0x00
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

  short getData(
      byte[] buffer,
      short offset,
      short length,
      boolean vciSatisfied,
      boolean vciAdvertised) {
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

    boolean discovery = isDiscoveryDataObject(buffer, offset, idLength);
    if (!discovery && !object.isInitialised()) {
      scratch[ZERO] = (byte) 0x53;
      scratch[(short) 1] = (byte) 0x00;
      chainBuffer.setOutgoing(scratch, ZERO, (short) 2, false);
      return (short) 2;
    }

    short responseLength;
    byte[] data;
    if (discovery && object.isInitialised()) {
      responseLength = object.getLength();
      data = object.content;
    } else if (discovery) {
      responseLength = buildDiscoveryObject(scratch, ZERO, vciAdvertised);
      data = scratch;
    } else {
      responseLength = object.getLength();
      data = object.content;
    }
    chainBuffer.setOutgoing(data, ZERO, responseLength, false);
    return responseLength;
  }

  boolean isGlobalPinAdvertised() {
    short policy = getDiscoveryPolicy();
    return policy != INVALID_DISCOVERY_POLICY && (((byte) (policy >> 8) & (byte) 0x20) != (byte) 0);
  }

  /** Returns the validated PIN Usage Policy, or -1 when the stored Discovery Object is absent or invalid. */
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
      if ((first & (byte) 0xC3) != (byte) 0x40) return INVALID_DISCOVERY_POLICY;
      if ((first & (byte) 0x20) == (byte) 0) {
        if (second != (byte) 0x00) return INVALID_DISCOVERY_POLICY;
      } else if (second != (byte) 0x10 && second != (byte) 0x20) {
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

  void putData(
      byte[] buffer,
      short offset,
      short length,
      boolean vciSatisfied,
      byte protection) {
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
        if (buffer[offset] != (byte) 0x53) {
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

    requireCompleteLengthHeader(buffer, offset, end);
    short objectLength = TLVReader.getLength(buffer, offset);
    if (objectLength == 0) {
      object.clear();
      return;
    }

    objectLength += (short) (TLVReader.getDataOffset(buffer, offset) - offset);
    length -= (short) (offset - initialOffset);
    chainBuffer.setIncomingObject(object, objectLength);
    chainBuffer.processIncomingObject(buffer, offset, length, protection);
  }

  /** Bounds the BER length header before TLVReader examines the APDU backing array. */
  private static void requireCompleteLengthHeader(byte[] buffer, short offset, short end) {
    if ((short) (offset + 1) >= end) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    short first = (short) (buffer[(short) (offset + 1)] & 0xFF);
    short lengthBytes;
    if (first < (short) 0x80) {
      lengthBytes = (short) 0;
    } else if (first == (short) 0x81) {
      lengthBytes = (short) 1;
    } else if (first == (short) 0x82) {
      lengthBytes = (short) 2;
    } else {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return;
    }
    if ((short) (offset + (short) 1 + lengthBytes) >= end) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
  }

  private short buildDiscoveryObject(byte[] buffer, short offset, boolean vciAdvertised) {
    short length = (short) Config.TEMPLATE_DISCOVERY.length;
    offset = Util.arrayCopyNonAtomic(Config.TEMPLATE_DISCOVERY, ZERO, buffer, offset, length);
    offset -= (short) 2;
    buffer[offset++] =
        (byte)
            ((config.readFlag(Config.CONFIG_PIN_ENABLE_LOCAL) ? (byte) (1 << 6) : (byte) 0)
                | (vciAdvertised ? (byte) (1 << 3) : (byte) 0)
                | (vciAdvertised
                        && config.readValue(Config.CONFIG_VCI_MODE) == Config.VCI_MODE_ENABLED
                    ? (byte) (1 << 2)
                    : (byte) 0));
    // A synthesized Discovery Object cannot authorize Global PIN use. The issuer must store the
    // exact policy bytes before key reference 00 becomes available.
    buffer[offset] = (byte) 0x00;
    return length;
  }

  private static boolean isDiscoveryDataObject(
      byte[] idBuffer, short idOffset, short idLength) {
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
    if (suffix == (byte) 0x05 || suffix == (byte) 0x01) {
      if (content[offset] != (byte) 0x70) return false;
      offset = tlvEnd(content, offset, limit);
      if (offset < (short) 0 || offset >= limit || content[offset] != (byte) 0x71) return false;
      if (tlvValueLength(content, offset, limit) != (short) 1) return false;
      offset = tlvEnd(content, offset, limit);
      if (offset < (short) 0 || offset >= limit || content[offset] != (byte) 0xFE) return false;
      return tlvValueLength(content, offset, limit) == (short) 0
          && tlvEnd(content, offset, limit) == limit;
    }
    if (suffix == (byte) 0x06) {
      if (content[offset] != (byte) 0xBA) return false;
      short mappingLength = tlvValueLength(content, offset, limit);
      if (mappingLength <= (short) 0 || (short) (mappingLength % (short) 3) != (short) 0) {
        return false;
      }
      offset = tlvEnd(content, offset, limit);
      if (offset < (short) 0
          || offset >= limit
          || content[offset] != (byte) 0xBB
          || tlvValueLength(content, offset, limit) <= (short) 0) return false;
      offset = tlvEnd(content, offset, limit);
      if (offset == limit) return true;
      return offset >= (short) 0
          && offset < limit
          && content[offset] == (byte) 0xFE
          && tlvValueLength(content, offset, limit) == (short) 0
          && tlvEnd(content, offset, limit) == limit;
    }
    while (offset < limit) {
      offset = tlvEnd(content, offset, limit);
      if (offset < (short) 0) return false;
    }
    return offset == limit;
  }

  private static short tlvValueLength(byte[] data, short offset, short limit) {
    short cursor = (short) (offset + (short) 1);
    if (cursor >= limit) return (short) -1;
    if ((data[offset] & (byte) 0x1F) == (byte) 0x1F) {
      do {
        if (cursor >= limit) return (short) -1;
      } while ((data[cursor++] & (byte) 0x80) != (byte) 0);
    }
    if (cursor >= limit) return (short) -1;
    short first = (short) (data[cursor++] & 0xFF);
    if (first < (short) 0x80) return first;
    short count = (short) (first & (short) 0x7F);
    if (count == (short) 0 || count > (short) 2 || (short) (cursor + count) > limit) {
      return (short) -1;
    }
    short length = (short) 0;
    while (count-- > (short) 0) length = (short) ((length << 8) | (data[cursor++] & 0xFF));
    return length;
  }

  private static short tlvEnd(byte[] data, short offset, short limit) {
    short cursor = (short) (offset + (short) 1);
    if (cursor >= limit) return (short) -1;
    if ((data[offset] & (byte) 0x1F) == (byte) 0x1F) {
      do {
        if (cursor >= limit) return (short) -1;
      } while ((data[cursor++] & (byte) 0x80) != (byte) 0);
    }
    if (cursor >= limit) return (short) -1;
    short first = (short) (data[cursor++] & 0xFF);
    short length = first;
    if (first >= (short) 0x80) {
      short count = (short) (first & (short) 0x7F);
      if (count == (short) 0 || count > (short) 2 || (short) (cursor + count) > limit) {
        return (short) -1;
      }
      length = (short) 0;
      while (count-- > (short) 0) length = (short) ((length << 8) | (data[cursor++] & 0xFF));
    }
    return length <= (short) (limit - cursor) ? (short) (cursor + length) : (short) -1;
  }
}
