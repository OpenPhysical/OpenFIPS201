/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2017 Commonwealth of Australia
 ******************************************************************************/

package com.makina.security.openfips201;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;

/** Owns the persistent directory of PIV data-object definitions. */
final class PIVDataStore {

  private PIVDataObject first;

  PIVDataObject find(byte[] idBuffer, short idOffset, short idLength) {
    PIVDataObject object = first;
    while (object != null) {
      if (object.match(idBuffer, idOffset, idLength)) return object;
      object = (PIVDataObject) object.getNext();
    }
    return null;
  }

  PIVDataObject findSingleByte(byte id) {
    PIVDataObject object = first;
    while (object != null) {
      if (object.matchSingleByteId(id)) return object;
      object = (PIVDataObject) object.getNext();
    }
    return null;
  }

  void create(
      byte[] idBuffer,
      short idOffset,
      short idLength,
      byte modeContact,
      byte modeContactless,
      byte adminKey) {
    if (find(idBuffer, idOffset, idLength) != null) {
      ISOException.throwIt(PIV.SW_PUT_DATA_OBJECT_EXISTS);
    }

    PIVDataObject object =
        new PIVDataObject(
            idBuffer, idOffset, idLength, modeContact, modeContactless, adminKey);
    object.setNext(first);
    first = object;
  }

  void delete(byte[] idBuffer, short idOffset, short idLength) {
    PIVDataObject previous = null;
    PIVDataObject object = first;
    while (object != null && !object.match(idBuffer, idOffset, idLength)) {
      previous = object;
      object = (PIVDataObject) object.getNext();
    }
    if (object == null) {
      ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
      return;
    }

    JCSystem.beginTransaction();
    if (previous == null) {
      first = (PIVDataObject) object.getNext();
    } else {
      previous.setNext(object.getNext());
    }
    object.setNext(null);
    JCSystem.commitTransaction();

    object.clear();
    object.runGc();
  }

  void clearContents() {
    PIVDataObject object = first;
    while (object != null) {
      object.clear();
      object = (PIVDataObject) object.getNext();
    }
  }
}
