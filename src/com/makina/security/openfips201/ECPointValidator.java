/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2017 Commonwealth of Australia
 ******************************************************************************/

package com.makina.security.openfips201;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/** Validates uncompressed prime-field EC points before scalar multiplication. */
final class ECPointValidator {
  private static final short MAX_FIELD_LENGTH = (short) 48;
  private static final short SLOT_COUNT = (short) 7;
  private static final short WORKSPACE_LENGTH = (short) (MAX_FIELD_LENGTH * SLOT_COUNT);

  private static final short SLOT_X = (short) 0;
  private static final short SLOT_Y = (short) 1;
  private static final short SLOT_Y2 = (short) 2;
  private static final short SLOT_X2 = (short) 3;
  private static final short SLOT_RHS = (short) 4;
  private static final short SLOT_ACC = (short) 5;
  private static final short SLOT_TMP = (short) 6;

  private static byte[] workspace;

  private ECPointValidator() {}

  static void terminate() {
    workspace = null;
  }

  static void setWorkspaceForTest(byte[] testWorkspace) {
    workspace = testWorkspace;
  }

  static boolean isValid(byte[] encoded, short offset, short length, ECParams params) {
    byte[] modulus = params.getP();
    short fieldLength = (short) modulus.length;
    if (length != (short) (fieldLength * (short) 2 + (short) 1) || encoded[offset] != (byte) 0x04) {
      return false;
    }

    ensureWorkspace();
    short x = slot(SLOT_X);
    short y = slot(SLOT_Y);
    short y2 = slot(SLOT_Y2);
    short x2 = slot(SLOT_X2);
    short rhs = slot(SLOT_RHS);

    Util.arrayCopyNonAtomic(encoded, (short) (offset + 1), workspace, x, fieldLength);
    Util.arrayCopyNonAtomic(encoded, (short) (offset + 1 + fieldLength), workspace, y, fieldLength);

    if (compare(workspace, x, modulus, (short) 0, fieldLength) >= 0
        || compare(workspace, y, modulus, (short) 0, fieldLength) >= 0) {
      clearWorkspace();
      return false;
    }

    multiply(workspace, y, workspace, y, workspace, y2, modulus, fieldLength);
    multiply(workspace, x, workspace, x, workspace, x2, modulus, fieldLength);
    multiply(workspace, x2, workspace, x, workspace, rhs, modulus, fieldLength);
    multiply(params.getA(), (short) 0, workspace, x, workspace, x2, modulus, fieldLength);
    addMod(workspace, rhs, workspace, x2, workspace, rhs, modulus, fieldLength);
    addMod(workspace, rhs, params.getB(), (short) 0, workspace, rhs, modulus, fieldLength);

    boolean valid = compare(workspace, y2, workspace, rhs, fieldLength) == 0;
    clearWorkspace();
    return valid;
  }

  private static void ensureWorkspace() {
    if (workspace == null) {
      workspace = JCSystem.makeTransientByteArray(WORKSPACE_LENGTH, JCSystem.CLEAR_ON_DESELECT);
    }
  }

  private static short slot(short index) {
    return (short) (index * MAX_FIELD_LENGTH);
  }

  private static void multiply(
      byte[] left,
      short leftOffset,
      byte[] right,
      short rightOffset,
      byte[] output,
      short outputOffset,
      byte[] modulus,
      short length) {
    short acc = slot(SLOT_ACC);
    short tmp = slot(SLOT_TMP);
    Util.arrayFillNonAtomic(workspace, acc, length, (byte) 0);

    for (short i = 0; i < length; i++) {
      byte value = right[(short) (rightOffset + i)];
      for (byte bit = (byte) 0x80; bit != (byte) 0; bit = (byte) ((bit & 0xFF) >>> 1)) {
        addMod(workspace, acc, workspace, acc, workspace, tmp, modulus, length);
        Util.arrayCopyNonAtomic(workspace, tmp, workspace, acc, length);
        if ((value & bit) != (byte) 0) {
          addMod(workspace, acc, left, leftOffset, workspace, tmp, modulus, length);
          Util.arrayCopyNonAtomic(workspace, tmp, workspace, acc, length);
        }
      }
    }
    Util.arrayCopyNonAtomic(workspace, acc, output, outputOffset, length);
  }

  private static void addMod(
      byte[] left,
      short leftOffset,
      byte[] right,
      short rightOffset,
      byte[] output,
      short outputOffset,
      byte[] modulus,
      short length) {
    short carry = 0;
    for (short i = (short) (length - 1); i >= 0; i--) {
      short sum =
          (short)
              ((left[(short) (leftOffset + i)] & 0xFF)
                  + (right[(short) (rightOffset + i)] & 0xFF)
                  + carry);
      output[(short) (outputOffset + i)] = (byte) sum;
      carry = (short) (sum >>> 8);
    }

    if (carry != 0 || compare(output, outputOffset, modulus, (short) 0, length) >= 0) {
      short borrow = 0;
      for (short i = (short) (length - 1); i >= 0; i--) {
        short difference =
            (short) ((output[(short) (outputOffset + i)] & 0xFF) - (modulus[i] & 0xFF) - borrow);
        output[(short) (outputOffset + i)] = (byte) difference;
        borrow = difference < 0 ? (short) 1 : (short) 0;
      }
    }
  }

  private static short compare(
      byte[] left, short leftOffset, byte[] right, short rightOffset, short length) {
    for (short i = 0; i < length; i++) {
      short a = (short) (left[(short) (leftOffset + i)] & 0xFF);
      short b = (short) (right[(short) (rightOffset + i)] & 0xFF);
      if (a < b) return (short) -1;
      if (a > b) return (short) 1;
    }
    return (short) 0;
  }

  private static void clearWorkspace() {
    Util.arrayFillNonAtomic(workspace, (short) 0, WORKSPACE_LENGTH, (byte) 0);
  }
}
