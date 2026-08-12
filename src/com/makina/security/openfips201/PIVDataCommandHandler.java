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
      boolean vciSatisfied,
      boolean vciAdvertised) {
    if (buffer[offset++] != (byte) 0x5C) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    short idLength = (short) (buffer[offset++] & 0xFF);
    if (idLength < (short) 1 || idLength > (short) 3) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    PIVDataObject object = dataStore.find(buffer, offset, idLength);
    if (object == null) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
      return ZERO;
    }
    if (!security.checkAccessModeObject(object, vciSatisfied)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    boolean discovery = isDiscoveryDataObject(buffer, offset, idLength);
    if (!discovery && !object.isInitialised()) {
      scratch[ZERO] = (byte) 0x53;
      scratch[(short) 1] = (byte) 0x00;
      chainBuffer.setOutgoing(scratch, ZERO, (short) 2, false);
      return (short) 2;
    }

    short length;
    byte[] data;
    if (discovery) {
      length = buildDiscoveryObject(scratch, ZERO, vciAdvertised);
      data = scratch;
    } else {
      length = object.getLength();
      data = object.content;
    }
    chainBuffer.setOutgoing(data, ZERO, length, false);
    return length;
  }

  void putData(
      byte[] buffer,
      short offset,
      short length,
      boolean vciSatisfied,
      byte protection) {
    final short initialOffset = offset;
    short idOffset = offset;
    short idLength;

    switch (buffer[offset]) {
      case (byte) 0x7E:
        idLength = (short) 1;
        break;
      case (byte) 0x7F:
        if (buffer[(short) (offset + 1)] != (byte) 0x61) {
          ISOException.throwIt(PIV.SW_REFERENCE_NOT_FOUND);
        }
        idLength = (short) 2;
        break;
      case (byte) 0x5C:
        offset++;
        idLength = (short) (buffer[offset] & 0xFF);
        if (idLength < (short) 1 || idLength > (short) 3) {
          ISOException.throwIt(PIV.SW_REFERENCE_NOT_FOUND);
        }
        offset++;
        idOffset = offset;
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
    if (!security.checkAccessModeAdmin(object, vciSatisfied)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

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

  private short buildDiscoveryObject(byte[] buffer, short offset, boolean vciAdvertised) {
    short length = (short) Config.TEMPLATE_DISCOVERY.length;
    offset = Util.arrayCopyNonAtomic(Config.TEMPLATE_DISCOVERY, ZERO, buffer, offset, length);
    offset -= (short) 2;
    buffer[offset++] =
        (byte)
            ((config.readFlag(Config.CONFIG_PIN_ENABLE_LOCAL) ? (byte) (1 << 6) : (byte) 0)
                | (config.readFlag(Config.CONFIG_PIN_ENABLE_GLOBAL) ? (byte) (1 << 5) : (byte) 0)
                | (vciAdvertised ? (byte) (1 << 3) : (byte) 0)
                | (vciAdvertised
                        && config.readValue(Config.CONFIG_VCI_MODE) == Config.VCI_MODE_ENABLED
                    ? (byte) (1 << 2)
                    : (byte) 0));
    buffer[offset] =
        config.readFlag(Config.CONFIG_PIN_ENABLE_GLOBAL)
            ? (config.readFlag(Config.CONFIG_PIN_PREFER_GLOBAL) ? (byte) 0x20 : (byte) 0x10)
            : (byte) 0x00;
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
}
