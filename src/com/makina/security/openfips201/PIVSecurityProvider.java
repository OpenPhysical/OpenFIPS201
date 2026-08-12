/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2017 Commonwealth of Australia
 * Author: Kim O'Sullivan - Makina (kim@makina.com.au)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ******************************************************************************/

package com.makina.security.openfips201;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Provides all security and cryptographic services required by PIV, including the storage of PIN
 * and KEY objects, as well as cryptographic primitives.
 */
final class PIVSecurityProvider {

  private final ECCurveRegistry curves;

  /** Compares the entire requested range without returning early on a mismatch. */
  static boolean arrayEqualsConstantTime(
      byte[] first, short firstOffset, byte[] second, short secondOffset, short length) {
    short difference = 0;
    for (short index = 0; index < length; index++) {
      difference |=
          (short)
              ((first[(short) (firstOffset + index)] ^ second[(short) (secondOffset + index)])
                  & 0xFF);
    }
    return difference == 0;
  }

  //
  // Constants - Security Flags
  //

  // If non-zero, the current communications interface is contactless
  private static final short STATE_IS_CONTACTLESS = (short) 0;

  // If non-zero, a valid GP Secure Channel authentication with CENC+CMAC is established
  private static final short STATE_IS_SECURE_CHANNEL = (short) 1;

  // If non-zero, a PIN verification occurred prior to the last GENERAL AUTHENTICATE command
  private static final short STATE_PIN_ALWAYS = (short) 2;

  // If non-zero, indicates the last key that was successfully authenticated
  private static final short STATE_AUTH_KEY = (short) 3;

  private static final short LENGTH_TRANSIENT_STATE = (short) 4;

  //
  // Constants - Security Counters
  //
  private static final short STATE_HISTORY_NEXT = (short) 0;
  private static final short STATE_LOCAL_PIN_PROVISIONED = (short) 1;
  private static final short STATE_PUK_PROVISIONED = (short) 2;
  private static final short LENGTH_PERSISTENT_STATE = (short) 3;

  //
  // Persistent Objects
  //

  // PERSISTENT - PIN objects
  private final PIVPIN cardPIN; // 80 - Card Application PIN
  private final PIVPIN cardPUK; // 81 - PIN Unlocking Key (PUK)
  private final PIVPIN globalPIN; // 00 - Global PIN
  private final byte[] pinHistory;
  private final byte[] pinHistoryLengths;

  // PERSISTENT - Counters related to security operations
  private final byte[] persistentState;

  // PERSISTENT - Key objects (linked list)
  private PIVKeyObject firstKey;

  //
  // Transient Objects
  //

  // TRANSIENT - Security Status Flags
  private final byte[] transientState;

  private static final byte FLAG_FALSE = (byte) 0;
  private static final byte FLAG_TRUE = (byte) 0xFF;

  PIVSecurityProvider(ECCurveRegistry curves) {
    this.curves = curves;

    // Initialise our PIV crypto provider
    PIVCrypto.init();

    // Create our internal state
    transientState =
        JCSystem.makeTransientByteArray(LENGTH_TRANSIENT_STATE, JCSystem.CLEAR_ON_DESELECT);
    persistentState = new byte[LENGTH_PERSISTENT_STATE];

    //
    // Create our PIN objects
    //

    // TODO: Change this to be made when the applet transitions to the PERSONALISED state and state
    // the limitation that it can only be set once. This is because OwnerPIN won't let you change it

    // Mandatory
    cardPIN = new PIVOwnerPIN(Config.LIMIT_PIN_MAX_RETRIES, Config.LIMIT_PIN_MAX_LENGTH);

    // Mandatory
    cardPUK = new PIVOwnerPIN(Config.LIMIT_PUK_MAX_RETRIES, Config.LIMIT_PUK_MAX_LENGTH);

    // Optional - But we still have to create it because it can be enabled at runtime
    globalPIN = new PIVCVMPIN();

    // Keep history storage compact and allocate it at install time. Command processing must not
    // create persistent objects on Java Card.
    pinHistory =
        new byte[(short) (Config.LIMIT_PIN_HISTORY * Config.LIMIT_PIN_MAX_LENGTH)];
    pinHistoryLengths = new byte[Config.LIMIT_PIN_HISTORY];
  }

  void clearVerification() {
    // Reset all PINs
    if (cardPIN.isValidated()) cardPIN.reset();
    if (cardPUK.isValidated()) cardPUK.reset();
    if (globalPIN.isValidated()) globalPIN.reset();
  }

  void setAuthenticatedKey(byte key) {
    transientState[STATE_AUTH_KEY] = key;
  }

  void clearAuthenticatedKey() {
    // Reset any authenticated keys
    // NOTE: We do NOT reset the secure channel, which is controlled from the applet
    transientState[STATE_AUTH_KEY] = (byte) 0;
  }

  boolean getIsPINAlways() {
    return (transientState[STATE_PIN_ALWAYS] == FLAG_TRUE
        && (cardPIN.isValidated() || globalPIN.isValidated()));
  }

  void markPINAlways() {
    transientState[STATE_PIN_ALWAYS] = FLAG_TRUE;
  }

  void clearPINAlways() {
    transientState[STATE_PIN_ALWAYS] = FLAG_FALSE;
  }

  private boolean consumePINAlways() {
    boolean active = getIsPINAlways();
    clearPINAlways();
    return active;
  }

  boolean getIsPINVerified() {
    return (cardPIN.isValidated() || globalPIN.isValidated());
  }

  /**
   * Gets the current flag for whether the communications interface is contactless
   *
   * @return True if the current communications interface is contactless
   */
  boolean getIsContactless() {
    return (transientState[STATE_IS_CONTACTLESS] == FLAG_TRUE);
  }

  /**
   * Sets the current flag for whether the communications interface is contactless
   *
   * @param value The new value to set
   */
  void setIsContactless(boolean value) {
    transientState[STATE_IS_CONTACTLESS] = value ? FLAG_TRUE : FLAG_FALSE;
  }

  /**
   * Gets the current flag for the GlobalPlatform Secure Channel Status
   *
   * @return True if there is a current GlobalPlatform Secure Channel with CENC+CMAC
   */
  boolean getIsSecureChannel() {
    return (transientState[STATE_IS_SECURE_CHANNEL] == FLAG_TRUE);
  }

  /**
   * Sets the current flag for the GlobalPlatform Secure Channel Status
   *
   * @param value The new value to set
   */
  void setIsSecureChannel(boolean value) {
    transientState[STATE_IS_SECURE_CHANNEL] = value ? FLAG_TRUE : FLAG_FALSE;
  }

  PIVKeyObject selectKey(byte id, byte mechanism) {

    // First, map the default mechanism code to TDEA 3KEY
    if (mechanism == PIV.ID_ALG_DEFAULT) {
      mechanism = PIV.ID_ALG_TDEA_3KEY;
    }

    PIVKeyObject key = selectKey(id);
    if (key != null && key.match(id, mechanism)) return key;

    return null;
  }

  PIVKeyObject selectKey(byte id) {

    PIVKeyObject key = firstKey;

    // Traverse the linked list
    while (key != null) {
      if (key.match(id)) return key;
      key = (PIVKeyObject) key.getNext();
    }

    return null;
  }

  boolean keyExists(byte id) {
    return selectKey(id) != null;
  }

  boolean hasUsableManagementKey() {
    PIVKeyObject key = selectKey((byte) 0x9B);
    return key != null
        && key.hasRole(PIVKeyObject.ROLE_AUTHENTICATE)
        && key.isInitialised();
  }

  /**
   * Adds a key to the internal key store
   *
   * @param id The key reference identifier
   * @param modeContact The access mode for the contact interface
   * @param modeContactless The access mode for the contactless interface
   * @param adminKey The administrative key for this key object
   * @param mechanism The cryptographic mechanism
   * @param role The key role / privileges control bitmap
   * @param attributes The optional key attributes
   */
  void createKey(
      byte id,
      byte modeContact,
      byte modeContactless,
      byte adminKey,
      byte mechanism,
      byte role,
      byte attributes) {

    // First, map the default mechanism code to TDEA 3KEY
    if (mechanism == PIV.ID_ALG_DEFAULT) {
      mechanism = PIV.ID_ALG_TDEA_3KEY;
    }

    if (!FipsPolicy.allowsKeyDefinition(
        id, modeContact, modeContactless, mechanism, role, attributes)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    if (keyExists(id)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_OBJECT_EXISTS);
    }

    // Create our new key
    PIVKeyObject key =
        PIVKeyObject.create(
            id, modeContact, modeContactless, adminKey, mechanism, role, attributes, curves);

    // Add it to our linked list
    // NOTE: If this is the first key added, just set our firstKey. Otherwise add it to the head
    // to save a traversal (inspired by having no good answer to Steve Paik's question why we
    // add it to the end).
    if (firstKey == null) {
      firstKey = key;
    } else {
      // Insert at the head of the list
      key.setNext(firstKey);
      firstKey = key;
    }
  }

  /** Atomically removes a key from the store, then wipes its detached key material. */
  void deleteKey(byte id, byte mechanism) {
    if (mechanism == PIV.ID_ALG_DEFAULT) {
      mechanism = PIV.ID_ALG_TDEA_3KEY;
    }

    PIVKeyObject previous = null;
    PIVKeyObject key = firstKey;
    while (key != null && !key.match(id, mechanism)) {
      previous = key;
      key = (PIVKeyObject) key.getNext();
    }
    if (key == null) {
      ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
      return;
    }

    if (transientState[STATE_AUTH_KEY] == id) {
      clearAuthenticatedKey();
    }

    JCSystem.beginTransaction();
    if (previous == null) {
      firstKey = (PIVKeyObject) key.getNext();
    } else {
      previous.setNext(key.getNext());
    }
    key.setNext(null);
    JCSystem.commitTransaction();

    key.clear();
    key.runGc();
  }

  boolean deleteKey(byte id) {

    PIVKeyObject previous = null;
    PIVKeyObject key = firstKey;

    while (key != null) {
      PIVKeyObject next = (PIVKeyObject) key.getNext();
      if (key.match(id)) {
        if (transientState[STATE_AUTH_KEY] == id) {
          clearAuthenticatedKey();
        }
        JCSystem.beginTransaction();
        if (previous == null) {
          firstKey = next;
        } else {
          previous.setNext(next);
        }
        key.setNext(null);
        JCSystem.commitTransaction();
        key.clear();
        key.runGc();
        return true;
      }
      previous = key;
      key = next;
    }

    return false;
  }

  void clearKeyMaterialExcept(byte retainedId) {
    PIVKeyObject key = firstKey;
    while (key != null) {
      if (key.getId() != retainedId) {
        key.clear();
      }
      key = (PIVKeyObject) key.getNext();
    }
    // Keep linked-list definitions in place; only sensitive material and authenticated key state
    // are cleared so provisioning profiles do not need to recreate object metadata.
    clearAuthenticatedKey();
  }

  /**
   * Validates the current security conditions for administering the specified object.
   *
   * @param object The object to check permissions for
   * @param vciEstablished True if the Virtual Contact Interface (secure messaging) is established
   * @return True of the access mode check passed
   */
  boolean checkAccessModeAdmin(PIVObject object, boolean vciEstablished) {

    //
    // This check can pass by any of the following conditions being true:
    // 1) The STATE_IS_SECURE_CHANNEL flag is set
    // 2) The object admin key is the last successfully authenticated key
    // 3) The object has the USER_ADMIN flag set and passes normal read access conditions, with
    //    the exception of objects that can ALWAYS be read.
    //

    boolean result = false;

    byte mode;
    if (getIsContactless()) {
      mode = object.getModeContactless();
    } else {
      mode = object.getModeContact();
    }

    //
    // ACCESS CONDITION 1 - Secure Channel (God Mode)
    //
    if (getIsSecureChannel()) {
      result = true;
    }

    //
    // ACCESS CONDITION 2 - Administrative Key
    //
    if (object.getAdminKey() == transientState[STATE_AUTH_KEY]) {
      result = true;
    }

    //
    // ACCESS CONDITION 3 - User Administration Privilege
    //
    if ((mode != PIVObject.ACCESS_MODE_ALWAYS)
        && ((mode & PIVObject.ACCESS_MODE_USER_ADMIN) == PIVObject.ACCESS_MODE_USER_ADMIN)
        && checkAccessModeObject(object, vciEstablished)) {
      result = true;
    }

    // Now that we have performed a security check, clear the pinAlways flag
    // NOTE: This incidentally always runs with access condition 3 above.
    clearPINAlways();

    // Done
    return result;
  }

  /** Returns whether SCP or the specified administrative key currently authorizes management. */
  boolean checkAccessModeAdmin(byte adminKey) {
    return getIsSecureChannel() || transientState[STATE_AUTH_KEY] == adminKey;
  }

  /**
   * Validates the current security conditions for access to a given data or key object
   *
   * @param object The object to check permissions for
   * @param vciEstablished True if the Virtual Contact Interface (secure messaging) is established
   * @return True of the access mode check passed
   */
  boolean checkAccessModeObject(PIVObject object, boolean vciEstablished) {

    boolean valid = false;
    boolean pinAlways = consumePINAlways();

    // Select the appropriate access mode to check
    final boolean contactless = (transientState[STATE_IS_CONTACTLESS] == FLAG_TRUE);
    byte mode;
    if (contactless) {
      mode = object.getModeContactless();
    } else {
      mode = object.getModeContact();
    }

    // Check for special ALWAYS condition, which ignores PIN_ALWAYS and VCI
    if (mode == PIVObject.ACCESS_MODE_ALWAYS) {
      valid = true;
    } else {
      // SP 800-73-5 Part 1 Section 5.5 defines VCI as a contactless security condition;
      // contact-interface rules do not depend on VCI state.
      final boolean vciRequired =
          contactless && (mode & PIVObject.ACCESS_MODE_VCI) == PIVObject.ACCESS_MODE_VCI;

      if (!vciRequired || vciEstablished) {
        // Check for PIN and GLOBAL PIN
        if ((mode & PIVObject.ACCESS_MODE_PIN) == PIVObject.ACCESS_MODE_PIN
            || (mode & PIVObject.ACCESS_MODE_PIN_ALWAYS) == PIVObject.ACCESS_MODE_PIN_ALWAYS) {
          // At least one PIN type must be both Enabled and Validated or we fail
          // NOTE: We don't check if they are enabled here, because if they weren't they could
          // never be valid.
          if (cardPIN.isValidated() || globalPIN.isValidated()) {
            valid = true;
          }
        } else if (vciRequired && (mode & PIVObject.ACCESS_MODE_OCC) == 0) {
          // VCI-only condition (no PIN/OCC): satisfied once VCI is established.
          valid = true;
        }

        // Check for PIN_ALWAYS
        if (((mode & PIVObject.ACCESS_MODE_PIN_ALWAYS) == PIVObject.ACCESS_MODE_PIN_ALWAYS)
            && !pinAlways) {
          valid = false;
        }
      }
    }

    // Done
    return valid;
  }

  PIVPIN getPIN(byte id) {

    switch (id) {
      case PIV.ID_CVM_LOCAL_PIN:
        return cardPIN;

      case PIV.ID_CVM_GLOBAL_PIN:
        return globalPIN;

      case PIV.ID_CVM_PUK:
        return cardPUK;

      default:
        return null; // Keep compiler happy
    }
  }

  void clearBootstrapCvmProvisioningState() {
    persistentState[STATE_LOCAL_PIN_PROVISIONED] = FLAG_FALSE;
    persistentState[STATE_PUK_PROVISIONED] = FLAG_FALSE;
  }

  boolean areMandatoryCvmsProvisioned() {
    return persistentState[STATE_LOCAL_PIN_PROVISIONED] == FLAG_TRUE
        && persistentState[STATE_PUK_PROVISIONED] == FLAG_TRUE;
  }

  boolean hasUsableAsymmetricKey(byte id) {
    PIVKeyObject key = firstKey;
    while (key != null) {
      if (key.getId() == id
          && key instanceof PIVKeyObjectPKI
          && ((PIVKeyObjectPKI) key).isInitialised()) {
        return true;
      }
      key = (PIVKeyObject) key.getNext();
    }
    return false;
  }

  void updatePIN(byte id, byte[] buffer, short offset, byte length, byte historyCount) {

    PIVPIN pin;

    switch (id) {
      case PIV.ID_CVM_LOCAL_PIN:
        pin = cardPIN;
        persistentState[STATE_LOCAL_PIN_PROVISIONED] = FLAG_TRUE;
        break;

      case PIV.ID_CVM_GLOBAL_PIN:
        pin = globalPIN;
        break;

      case PIV.ID_CVM_PUK:
        // Update the PUK, no history matching required
        cardPUK.update(buffer, offset, length);
        persistentState[STATE_PUK_PROVISIONED] = FLAG_TRUE;
        return;

      default:
        ISOException.throwIt(PIV.SW_REFERENCE_NOT_FOUND);
        return; // Keep compiler happy
    }

    // Optionally verify the PIN history
    // NOTE: Any elements beyond the historyCheck count will not be used at all, so we ignore
    // their values
    boolean matched = false;

    // Interate through our history list (which may be zero)
    for (byte i = 0; i < historyCount; i++) {
      short historyOffset = (short) (i * Config.LIMIT_PIN_MAX_LENGTH);
      if (pinHistoryLengths[i] == length
          && arrayEqualsConstantTime(pinHistory, historyOffset, buffer, offset, length)) {
        matched = true;
        break;
      }
    }

    // If we got a match, the PIN check fails and we will not update
    if (matched) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      return; // Keep compiler happy
    }

    // Update the PIN
    pin.update(buffer, offset, length);

    // Update the PIN History if enabled
    if (historyCount > 0) {
      // Move/Roll to the next position we will write to
      byte next = persistentState[STATE_HISTORY_NEXT];
      if (next >= historyCount) next = (byte) 0;
      short historyOffset = (short) (next * Config.LIMIT_PIN_MAX_LENGTH);
      Util.arrayCopy(
          buffer, offset, pinHistory, historyOffset, length);
      pinHistoryLengths[next] = length;
      next = (byte) ((byte) (next + (byte) 1) % historyCount);
      persistentState[STATE_HISTORY_NEXT] = next;
    }
  }

  /**
   * Performs a comprehensive erase of the target buffer
   *
   * @param buffer The buffer to clear
   * @param offset The starting offset of the buffer
   * @param length The length within the buffer to clear
   */
  static void zeroise(byte[] buffer, short offset, short length) {

    Util.arrayFillNonAtomic(buffer, offset, length, (byte) 0x00);
    Util.arrayFillNonAtomic(buffer, offset, length, (byte) 0xFF);
    Util.arrayFillNonAtomic(buffer, offset, length, (byte) 0x00);
  }
}
