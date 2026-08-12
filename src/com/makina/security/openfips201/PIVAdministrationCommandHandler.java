/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2017 Commonwealth of Australia
 ******************************************************************************/

package com.makina.security.openfips201;

import static com.makina.security.openfips201.PIV.*;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.PIN;
import javacard.framework.Util;
import org.globalplatform.GPSystem;

/** Handles proprietary administration, configuration, deletion, version, and status commands. */
final class PIVAdministrationCommandHandler {
  private final PIV owner;
  private final Config config;
  private final PIVSecurityProvider cspPIV;
  private final PIVDataStore dataStore;
  private final ChainBuffer chainBuffer;
  private final PIVSecureMessaging secureMessaging;
  private final byte[] scratch;
  private final byte[] smCommand;
  // #if ATTESTATION_ENABLED
  private final PIVAttestation attestation;
  // #endif

  PIVAdministrationCommandHandler(
      PIV owner,
      Config config,
      PIVSecurityProvider cspPIV,
      PIVDataStore dataStore,
      ChainBuffer chainBuffer,
      PIVSecureMessaging secureMessaging,
      byte[] scratch,
      byte[] smCommand
      // #if ATTESTATION_ENABLED
      , PIVAttestation attestation
      // #endif
      ) {
    this.owner = owner;
    this.config = config;
    this.cspPIV = cspPIV;
    this.dataStore = dataStore;
    this.chainBuffer = chainBuffer;
    this.secureMessaging = secureMessaging;
    this.scratch = scratch;
    this.smCommand = smCommand;
    // #if ATTESTATION_ENABLED
    this.attestation = attestation;
    // #endif
  }

  private void requireStructureMutable() {
    if (GPSystem.getCardContentState() != GPSystem.APPLICATION_SELECTABLE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  private void processPersonalizeAppletRequest(short requestLength) {
    if (requestLength != (short) 0
        || GPSystem.getCardContentState() != GPSystem.APPLICATION_SELECTABLE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    if (!GPSystem.setCardContentState(APP_STATE_PERSONALIZED)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  private void processCreateObjectRequest(TLVReader reader) {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The 'ID' tag MUST be present
    if (!reader.match(CONST_TAG_ID)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_ID_MISSING);
      return;
    }

    // PRE-CONDITION 2 - The 'ID' tag MUST have length between 1 and 3
    short objectIdLength = reader.getLength();
    if (objectIdLength < (short) 1 || objectIdLength > (short) 3) {
      ISOException.throwIt(PIV.SW_PUT_DATA_ID_INVALID_LENGTH);
      return;
    }

    short idOffset = reader.getDataOffset();
    reader.moveNext();

    // PRE-CONDITION 3 - The 'MODE CONTACT' tag MUST be present
    if (!reader.match(CONST_TAG_MODE_CONTACT)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_MODE_CONTACT_MISSING);
      return;
    }

    // PRE-CONDITION 4 - The 'MODE CONTACT' tag MUST be length 1
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(PIV.SW_PUT_DATA_MODE_CONTACT_INVALID_LENGTH);
      return;
    }

    byte modeContact = reader.toByte();
    owner.rejectUnsupportedOccAccessMode(modeContact);
    reader.moveNext();

    // PRE-CONDITION 5 - The 'MODE CONTACTLESS' tag MUST be present
    if (!reader.match(CONST_TAG_MODE_CONTACTLESS)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_MODE_CONTACTLESS_MISSING);
      return;
    }

    // PRE-CONDITION 6 - The 'MODE CONTACTLESS' tag MUST be length 1
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(PIV.SW_PUT_DATA_MODE_CONTACTLESS_INVALID_LENGTH);
      return;
    }

    byte modeContactless = reader.toByte();
    owner.rejectUnsupportedOccAccessMode(modeContactless);
    reader.moveNext();

    // PRE-CONDITION 7 - The 'ADMIN KEY' tag MAY be present
    byte adminKey = (byte) 0;
    if (reader.match(CONST_TAG_ADMIN_KEY)) {

      // PRE-CONDITION 8 - If the 'ADMIN KEY' tag is present, it MUST be length 1
      if (reader.getLength() != (short) 1) {
        ISOException.throwIt(PIV.SW_PUT_DATA_MODE_ADMIN_KEY_INVALID_LENGTH);
        return;
      }

      adminKey = reader.toByte();
      reader.moveNext();
    }

    dataStore.create(
        scratch,
        idOffset,
        objectIdLength,
        modeContact,
        modeContactless,
        adminKey);
  }

  private void processDeleteObjectRequest(TLVReader reader) {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The 'ID' tag MUST be present
    if (!reader.match(CONST_TAG_ID)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_ID_MISSING);
      return;
    }

    // PRE-CONDITION 2 - The 'ID' tag MUST have length between 1 and 3
    short objectIdLength = reader.getLength();
    if (objectIdLength < (short) 1 || objectIdLength > (short) 3) {
      ISOException.throwIt(PIV.SW_PUT_DATA_ID_INVALID_LENGTH);
      return;
    }

    short idOffset = reader.getDataOffset();
    reader.moveNext();

    dataStore.delete(scratch, idOffset, objectIdLength);
  }

  private void processCreateKeyRequest(TLVReader reader, boolean legacy) {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The 'ID' tag MUST be present
    if (!reader.match(CONST_TAG_ID)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_ID_MISSING);
      return;
    }

    // PRE-CONDITION 2 - The 'ID' tag MUST have length 1 only
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(PIV.SW_PUT_DATA_ID_INVALID_LENGTH);
      return;
    }
    byte id = reader.toByte();
    reader.moveNext();

    // PRE-CONDITION 3 - The 'MODE CONTACT' tag MUST be present
    if (!reader.match(CONST_TAG_MODE_CONTACT)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_MODE_CONTACT_MISSING);
      return;
    }

    // PRE-CONDITION 4 - The 'MODE CONTACT' tag MUST be length 1
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(PIV.SW_PUT_DATA_MODE_CONTACT_INVALID_LENGTH);
      return;
    }

    byte modeContact = reader.toByte();
    owner.rejectUnsupportedOccAccessMode(modeContact);
    reader.moveNext();

    // PRE-CONDITION 5 - The 'MODE CONTACTLESS' tag MUST be present
    if (!reader.match(CONST_TAG_MODE_CONTACTLESS)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_MODE_CONTACTLESS_MISSING);
      return;
    }

    // PRE-CONDITION 6 - The 'MODE CONTACTLESS' tag MUST be length 1
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(PIV.SW_PUT_DATA_MODE_CONTACTLESS_INVALID_LENGTH);
      return;
    }

    byte modeContactless = reader.toByte();
    owner.rejectUnsupportedOccAccessMode(modeContactless);
    reader.moveNext();

    // PRE-CONDITION 7 - The 'ADMIN KEY' tag MAY be present
    byte adminKey = (byte) 0;
    if (reader.match(CONST_TAG_ADMIN_KEY)) {

      // PRE-CONDITION 8 - If the 'ADMIN KEY' tag is present, it MUST be length 1
      if (reader.getLength() != (short) 1) {
        ISOException.throwIt(PIV.SW_PUT_DATA_MODE_ADMIN_KEY_INVALID_LENGTH);
        return;
      }

      adminKey = reader.toByte();
      reader.moveNext();
    }

    // PRE-CONDITION 9 - The 'KEY MECHANISM' tag MUST be present
    if (!reader.match(CONST_TAG_KEY_MECHANISM)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_KEY_MECHANISM_MISSING);
      return;
    }

    // PRE-CONDITION 10 - The 'KEY MECHANISM' tag MUST have length 1 only
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(PIV.SW_PUT_DATA_KEY_MECHANISM_INVALID_LENGTH);
      return;
    }
    byte keyMechanism = reader.toByte();
    reader.moveNext();

    // PRE-CONDITION 11 - The supplied mechanism must be supported by this instance
    if (!PIVCrypto.supportsMechanism(keyMechanism)) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }

    // PRE-CONDITION 12 - The 'KEY ROLE' tag MUST be present
    if (!reader.match(CONST_TAG_KEY_ROLE)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_KEY_ROLE_MISSING);
      return;
    }

    // PRE-CONDITION 13 - The 'KEY ROLE' tag MUST have length 1
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(PIV.SW_PUT_DATA_KEY_ROLE_INVALID_LENGTH);
      return;
    }
    byte keyRole = reader.toByte();
    reader.moveNext();

    // PRE-CONDITION 14 - The 'KEY ATTRIBUTE' tag MUST be present
    if (!reader.match(CONST_TAG_KEY_ATTRIBUTE)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_KEY_ATTR_MISSING);
      return;
    }

    // PRE-CONDITION 15 - The 'KEY ATTRIBUTE' tag MUST have length 1
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(PIV.SW_PUT_DATA_KEY_ATTR_INVALID_LENGTH);
      return;
    }
    byte keyAttribute = reader.toByte();
    reader.moveNext();

    // F9 is reserved for the attestation authority. It is still created through the normal
    // key-object definition path, but its shape is fixed so provisioning can use CHANGE REFERENCE
    // DATA without introducing an attestation-specific import APDU.
    if (id == ID_KEY_ATTESTATION
        // #if ATTESTATION_ENABLED
        && (modeContact != PIVObject.ACCESS_MODE_NEVER
            || modeContactless != PIVObject.ACCESS_MODE_NEVER
            || keyMechanism != ID_ALG_ECC_P256
            || keyRole != PIVKeyObject.ROLE_SIGN
            || keyAttribute != PIVKeyObject.ATTR_IMPORTABLE)
        // #else
        && true
    // #endif
    ) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    if (id == ID_KEY_SECURE_MESSAGING
        && (keyMechanism == ID_ALG_ECC_CS2 || keyMechanism == ID_ALG_ECC_CS7)) {
      if (keyMechanism != ID_ALG_ECC_SM) {
        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
      }
    }

    // PRE-CONDITION 16 - The key reference MUST NOT already have a key definition. SP 800-73
    // commands select a key by reference (P2) and validate the mechanism separately (P1), so
    // OpenFIPS201 stores exactly one key object for each key reference.
    if (cspPIV.keyExists(id)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_OBJECT_EXISTS);
      return;
    }

    //
    // EXECUTION STEPS
    //

    // STEP 1 - If this is a legacy request, apply the PERMIT_MUTUAL
    // key attribute as a default.
    if (legacy && PIVCrypto.isSymmetricMechanism(keyMechanism)) {
      keyAttribute |= PIVKeyObject.ATTR_PERMIT_MUTUAL;
    }

    // STEP 2 - Add the key to the key store
    cspPIV.createKey(
        id, modeContact, modeContactless, adminKey, keyMechanism, keyRole, keyAttribute);
  }

  private void processDeleteKeyRequest(TLVReader reader) {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The 'ID' tag MUST be present
    if (!reader.match(CONST_TAG_ID)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_ID_MISSING);
      return;
    }

    // PRE-CONDITION 2 - The 'ID' tag MUST have length 1 only
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(PIV.SW_PUT_DATA_ID_INVALID_LENGTH);
      return;
    }
    byte id = reader.toByte();
    reader.moveNext();

    if (id == ID_KEY_ATTESTATION) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 3 - The 'KEY MECHANISM' tag MUST be present
    if (!reader.match(CONST_TAG_KEY_MECHANISM)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_KEY_MECHANISM_MISSING);
      return;
    }

    // PRE-CONDITION 4 - The 'KEY MECHANISM' tag MUST have length 1 only
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(PIV.SW_PUT_DATA_KEY_MECHANISM_INVALID_LENGTH);
      return;
    }
    byte keyMechanism = reader.toByte();
    reader.moveNext();

    // PRE-CONDITION 5 - The key reference MUST exist and the supplied mechanism must match the
    // slot's single key definition.
    PIVKeyObject key = cspPIV.selectKey(id);
    if (key == null) {
      ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
      return;
    }
    if (cspPIV.selectKey(id, keyMechanism) == null) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      return;
    }

    //
    // EXECUTION STEPS
    //

    // STEP 1 - Clear related authenticated state, unlink the key, and wipe its material.
    cspPIV.deleteKey(id, keyMechanism);
  }

  /**
   * Clears the value of every defined data object without deleting the object definitions.
   *
   * <p>This is used when committing a new attestation authority. The object directory remains
   * personalized, but certificate and data contents from the previous trust root are removed before
   * the new authority is marked active.
   */
  /**
   * This is the administrative equivalent for the PUT DATA card and is intended for use by Card
   * Management Systems to generate the on-card file-system.
   *
   * @param buffer - The incoming APDU buffer
   * @param offset - The starting offset of the CDATA section
   * @param length - The length of the CDATA section
   */
  void putDataAdmin(byte[] buffer, short offset, short length) throws ISOException {

    //
    // SECURITY PRE-CONDITION
    //

    // The command must have been sent over SCP with CEnc+CMac
    if (!cspPIV.getIsSecureChannel()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    //
    // COMMAND CHAIN HANDLING
    //

    // Pass the APDU to the chainBuffer instance first. It will return zero if there is store more
    // to of the chain to process, otherwise it will return the length of the large CDATA buffer
    length = chainBuffer.processIncomingAPDU(buffer, offset, length, scratch, ZERO);

    // If the length is zero, just return so the caller can keep sending
    if (length == 0) return;

    // If we got this far, the scratch buffer now contains the incoming command. Keep in mind that
    // the original buffer still contains the APDU header.

    // Initialise our TLV reader
    TLVReader reader = TLVReader.getInstance();
    reader.init(scratch, ZERO, length);

    //
    // PRE-PROCESSING
    //

    // If the top-level tag indicates this is a BULK request, we move into it and then we are left
    // with an array of objects. If it doesn't, we are already at the start of the only request.
    boolean isBulk;
    if (reader.match(CONST_TAG_BULK_REQUEST)) {
      // Object allocation and key deletion cannot be rolled back reliably as one Java Card
      // transaction. Reject batches instead of leaving a partially applied administration set.
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
      return;
    } else {
      isBulk = false;
    }

    final byte CONST_OP_LEGACY_DATA = (byte) 0x01;
    final byte CONST_OP_LEGACY_KEY = (byte) 0x02;

    // Loop through all the requests
    do {
      // Get the operation value
      byte operation = reader.getTag();
      short operationLength = reader.getLength();

      // PRE-CONDITION 1 - The tag must be constructed
      if (!reader.isConstructed()) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        return;
      }

      // Move into the constructed tag
      reader.moveInto();

      //
      // LEGACY SUPPORT:
      // To minimise impact on issuance systems, we will continue to support the legacy PUT DATA
      // ADMIN format until we decide it isn't needed anymore.
      // There are limitations:
      // - The legacy format can only create data objects and keys, not update configuration
      // - This means only the default applet settings will apply (NIST compliant profile)
      //
      boolean legacy = false;
      if (operation == CONST_TAG_LEGACY) {
        // PRE-CONDITION 2A - If this is a LEGACY operation, the 'LEGACY OPERATION' tag MUST
        // be present
        if (!reader.match(CONST_TAG_LEGACY_OPERATION)) {
          ISOException.throwIt(PIV.SW_PUT_DATA_OP_MISSING);
        }
        // PRE-CONDITION 2B - The 'OPERATION' tag MUST have length 1
        if (reader.getLength() != (short) 1) {
          ISOException.throwIt(PIV.SW_PUT_DATA_ID_INVALID_LENGTH);
        }

        // Update the operation and move on
        legacy = true;
        operation = reader.toByte();
        reader.moveNext();
      }

      switch (operation) {

          // Create a data object record
        case CONST_OP_LEGACY_DATA:
        case CONST_TAG_CREATE_OBJECT:
          requireStructureMutable();
          processCreateObjectRequest(reader);
          break;

        case CONST_TAG_DELETE_OBJECT:
          requireStructureMutable();
          processDeleteObjectRequest(reader);
          break;

          // Create a key object record
        case CONST_OP_LEGACY_KEY:
        case CONST_TAG_CREATE_KEY:
          requireStructureMutable();
          processCreateKeyRequest(reader, legacy);
          break;

        case CONST_TAG_DELETE_KEY:
          requireStructureMutable();
          processDeleteKeyRequest(reader);
          break;

          // Update one or more configuration parameters
        case CONST_TAG_UPDATE_CONFIG:
          requireStructureMutable();
          JCSystem.beginTransaction();
          config.update(reader);
          JCSystem.commitTransaction();
          break;

        case CONST_TAG_PERSONALIZE_APPLET:
          processPersonalizeAppletRequest(operationLength);
          break;

        default:
          ISOException.throwIt(SW_PUT_DATA_OP_INVALID_VALUE);
          return;
      }

      // If this is a bulk operation,
    } while (isBulk && !reader.isEOF());
  }

  /**
   * This method is the equivalent of the CHANGE REFERENCE DATA command, however it is intended to
   * operate on key references that are NOT listed in SP800-37-4. This is the primary method by
   * which administrative key references are updated and is intended to fill in the gap in PIV that
   * does not cover how pre-personalisation is implemented.
   *
   * @param id The target key / pin reference being changed
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset of the CDATA section
   * @param length The length of the CDATA section
   *     <p>The main differences to CHANGE REFERENCE DATA are: - It supports updating any key
   *     reference that is not covered by CHANGE REFERENCE DATA already - It requires a global
   *     platform secure channel with CEncDec, or prior authentication of the applicable
   *     administrative key - It does NOT require the old value to be supplied in order to change a
   *     key - It also supports updating the PIN/PUK values, without requiring knowledge of the old
   *     value
   */
  void changeReferenceDataAdmin(byte id, byte[] buffer, short offset, short length)
      throws ISOException {

    final byte CONST_TAG_SEQUENCE = (byte) 0x30;
    final byte mechanism = buffer[ISO7816.OFFSET_P1];

    // The PIV Card Application may allow the reference data associated with other key references
    // to be changed by the PIV Card Application CHANGE REFERENCE DATA, if PIV Card Application will
    // only perform the command with other key references if the requirements specified in Section
    // 2.9.2 of FIPS 201-2 are satisfied.

    //
    // COMMAND CHAIN HANDLING
    //

    byte[] commandBuffer = scratch;
    // #if VCI_CS7
    // CS7 SM CVCs may be larger than LENGTH_SCRATCH. Keep the advertised CS7 CVC limit
    // provisionable by reassembling that admin update into the larger OPACITY command buffer.
    if (id == ID_KEY_SECURE_MESSAGING && mechanism == ID_ALG_ECC_SM) {
      commandBuffer = smCommand;
    }
    // #endif

    // Pass the APDU to the chainBuffer instance first. It will return zero if there is store more
    // to of the chain to process, otherwise it will return the length of the large CDATA buffer
    length = chainBuffer.processIncomingAPDU(buffer, offset, length, commandBuffer, ZERO);

    // If the length is zero, just return so the caller can keep sending
    if (length == 0) return;

    // If we got this far, the scratch buffer now contains the incoming DATA. Keep in mind that the
    // original buffer
    // still contains the APDU header.
    try {

      //
      // SPECIAL CASE 1 - LOCAL PIN
      //
      if (id == ID_CVM_LOCAL_PIN) {
        if (!cspPIV.checkAccessModeAdmin(PIVObject.DEFAULT_ADMIN_KEY)) {
          ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // NOTE:
        // We deliberately ignore the value of CONFIG_PIN_ENABLE_LOCAL here as there may be a good
        // reason for setting a pre-defined PIN value with the anticipation of enabling it later

        if (!owner.verifyPinFormat(commandBuffer, ZERO, length)) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        if (!owner.verifyPinRules(commandBuffer, ZERO, length)) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Update the PIN
        // NOTE: We ignore the history check here since this is an administrative update
        cspPIV.updatePIN(ID_CVM_LOCAL_PIN, commandBuffer, ZERO, (byte) length, ZERO);
        return; // Done
      }

      //
      // SPECIAL CASE 2 - PUK
      //
      if (id == ID_CVM_PUK) {
        if (!cspPIV.checkAccessModeAdmin(PIVObject.DEFAULT_ADMIN_KEY)) {
          ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // NOTES:
        // - We deliberately ignore the value of CONFIG_PUK_ENABLED here as there may be a good
        //   reason for setting a pre-defined PUK value with the anticipation of enabling it later
        // - No format verification required is for the PUK

        // Update the PUK
        cspPIV.updatePIN(ID_CVM_PUK, commandBuffer, ZERO, (byte) length, ZERO);

        return; // Done
      }

      // PRE-CONDITION 1 - Management key updates MUST use explicit PIV algorithm identifiers.
      // This keeps 9B updates aligned with PIV symmetric mechanisms and avoids "default" ambiguity.
      if (id == PIVObject.DEFAULT_ADMIN_KEY
          && mechanism != ID_ALG_TDEA_3KEY
          && mechanism != ID_ALG_AES_128
          && mechanism != ID_ALG_AES_192
          && mechanism != ID_ALG_AES_256) {
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      }

      // PRE-CONDITION 1 - The key reference and mechanism MUST point to an existing key
      PIVKeyObject key = cspPIV.selectKey(id, mechanism);
      if (key == null) {
        // If any key reference value is specified that is not supported by the card, the PIV Card
        // Application shall return the status word '6A 88'.
        ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        return; // Keep static analyser happy
      }

      // F9 carries the authority private scalar and issuer profile. A prior management-key
      // authentication may authorize ordinary key rotation, but it must not downgrade authority
      // import to plaintext.
      // #if ATTESTATION_ENABLED
      if (key.getId() == ID_KEY_ATTESTATION && !cspPIV.getIsSecureChannel()) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        return; // Keep static analyser happy
      }
      // #endif

      // PRE-CONDITION 2 - Administrative conditions for this key object must be satisfied.
      // This allows either SCP or prior successful authentication with the key's admin key.
      if (!cspPIV.checkAccessModeAdmin(key, owner.isVciSatisfied())) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        return; // Keep static analyser happy
      }

      // Set up our TLV reader
      TLVReader reader = TLVReader.getInstance();
      reader.init(commandBuffer, ZERO, length);

      // PRE-CONDITION 3 - The parent tag MUST be of type SEQUENCE
      if (!reader.match(CONST_TAG_SEQUENCE)) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return; // Keep static analyser happy
      }

      // PRE-CONDITION 4 - The SEQUENCE length MUST be smaller than the APDU data length
      if (reader.getLength() > length) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return; // Keep static analyser happy
      }

      // Move to the child tag
      if (!reader.moveInto()) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return; // Keep static analyser happy
      }

      // PRE-CONDITION 5 - Capture the key element to update from the same parse that will drive the
      // mutation. This avoids separate CVC-specific parsing of the same command bytes.
      byte elementTag = reader.getTag();
      short elementOffset = reader.getDataOffset();
      short elementLength = reader.getLength();

      // PRE-CONDITION 6 - Reject malformed payloads containing multiple key update elements.
      if (reader.moveNext()) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return; // Keep static analyser happy
      }

      // PRE-CONDITION 7 - The key object MUST have the ATTR_IMPORTABLE attribute, except that the
      // post-generation PIV secure messaging CVC can be loaded onto the generated non-exportable
      // VCI
      // key without enabling private-key import.
      if (!key.hasAttribute(PIVKeyObject.ATTR_IMPORTABLE)
          && !(key instanceof PIVKeyObjectECC
              && key.getId() == ID_KEY_SECURE_MESSAGING
              && key.getMechanism() == ID_ALG_ECC_SM
              && elementTag == PIVKeyObjectECC.ELEMENT_SM_CVC
              && elementLength > ZERO)) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        return; // Keep static analyser happy
      }

      //
      // EXECUTION STEPS
      //

      // STEP 1 - Update the relevant key element.
      // #if ATTESTATION_ENABLED
      if (key.getId() == ID_KEY_ATTESTATION
          && (elementTag == PIVAttestation.ELEMENT_SUBJECT
              || elementTag == PIVAttestation.ELEMENT_VALIDITY)) {
        attestation.updateElement(elementTag, scratch, elementOffset, elementLength);
      } else {
        // #endif
        if (key instanceof PIVKeyObjectPKI) {
          JCSystem.beginTransaction();
          try {
            key.updateElement(elementTag, commandBuffer, elementOffset, elementLength);
            JCSystem.commitTransaction();
          } finally {
            if (JCSystem.getTransactionDepth() != (byte) 0) {
              JCSystem.abortTransaction();
            }
          }
        } else {
          key.updateElement(elementTag, commandBuffer, elementOffset, elementLength);
        }
        // #if ATTESTATION_ENABLED
        if (key.getId() == ID_KEY_ATTESTATION) {
          if (elementTag == PIVKeyObject.ELEMENT_CLEAR) {
            attestation.clearProfile();
          } else {
            attestation.noteKeyElementUpdated(elementTag);
          }
        }
        // #endif
        // #if ATTESTATION_ENABLED
      }
      // #endif
      if (elementTag != PIVKeyObjectECC.ELEMENT_SM_CVC) {
        key.markImported();
      }

      // #if ATTESTATION_ENABLED
      if (key.getId() == ID_KEY_ATTESTATION) {
        if (!(key instanceof PIVKeyObjectECC)) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        PIVKeyObjectECC authority = (PIVKeyObjectECC) key;
        if (!attestation.isAuthorityActive() && attestation.isAuthorityReadyToCommit(authority)) {
          attestation.validateAuthority(authority, scratch);
          // Committing a new authority changes the card's trust root. Keep object definitions, but
          // clear data contents and non-F9 key material tied to the prior authority.
          boolean transactionStarted = false;
          try {
            JCSystem.beginTransaction();
            transactionStarted = true;
            dataStore.clearContents();
            cspPIV.clearKeyMaterialExcept(ID_KEY_ATTESTATION);
            attestation.markAuthorityActive();
            JCSystem.commitTransaction();
            transactionStarted = false;
          } catch (RuntimeException e) {
            if (transactionStarted) {
              JCSystem.abortTransaction();
            }
            throw e;
          }
        }
      }
      // #endif

      // STEP 4 - Clear any prior key-authenticated session after a key value change.
      cspPIV.clearAuthenticatedKey();
    } finally {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
    }
  }

  private short processGetVersion(TLVWriter writer) {

    final byte CONST_TAG_APPLICATION = (byte) 0x80;
    final byte CONST_TAG_MAJOR = (byte) 0x81;
    final byte CONST_TAG_MINOR = (byte) 0x82;
    final byte CONST_TAG_REVISION = (byte) 0x83;
    final byte CONST_TAG_DEBUG = (byte) 0x84;

    // Application
    writer.write(
        CONST_TAG_APPLICATION, Config.APPLICATION_NAME, ZERO, Config.LENGTH_APPLICATION_NAME);

    // Major
    writer.write(CONST_TAG_MAJOR, Config.VERSION_MAJOR);

    // Minor
    writer.write(CONST_TAG_MINOR, Config.VERSION_MINOR);

    // Revision
    writer.write(CONST_TAG_REVISION, Config.VERSION_REVISION);

    // Debug
    writer.write(CONST_TAG_DEBUG, Config.VERSION_DEBUG);

    return writer.finish();
  }

  private short processGetStatus(TLVWriter writer) {

    final byte CONST_TAG_APPLET_STATE = (byte) 0x80;
    final byte CONST_TAG_PIN_VERIFIED = (byte) 0x81;
    final byte CONST_TAG_PIN_ALWAYS = (byte) 0x82;
    final byte CONST_TAG_SM_STATE = (byte) 0x83;
    final byte CONST_TAG_VCI_STATE = (byte) 0x84;
    final byte CONST_TAG_SCP_STATE = (byte) 0x85;
    final byte CONST_TAG_CONTACTLESS = (byte) 0x86;
    final byte CONST_TAG_FIPS_MODE = (byte) 0x87;

    // Applet State
    writer.write(CONST_TAG_APPLET_STATE, GPSystem.getCardContentState());

    // PIN Verified
    writer.write(CONST_TAG_PIN_VERIFIED, cspPIV.getIsPINVerified() ? (byte) 1 : (byte) 0);

    // PIN Always
    writer.write(CONST_TAG_PIN_ALWAYS, cspPIV.getIsPINAlways() ? (byte) 1 : (byte) 0);

    // SM State
    writer.write(CONST_TAG_SM_STATE, secureMessaging.isEstablished() ? (byte) 1 : (byte) 0);

    // VCI State
    writer.write(CONST_TAG_VCI_STATE, secureMessaging.isVciEstablished() ? (byte) 1 : (byte) 0);

    // SCP State
    writer.write(CONST_TAG_SCP_STATE, cspPIV.getIsSecureChannel() ? (byte) 1 : (byte) 0);

    // Contactless
    writer.write(CONST_TAG_CONTACTLESS, cspPIV.getIsContactless() ? (byte) 1 : (byte) 0);

    // FIPS Mode
    writer.write(CONST_TAG_FIPS_MODE, (byte) 0); // TODO

    return writer.finish();
  }

  /**
   * The GET DATA card command retrieves the data content of the single data object whose tag is
   * given in the data field.
   *
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset of the CDATA section
   * @param length The length of the CDATA section
   * @return The length of the entire data object
   */
  short getDataExtended(byte[] buffer, short offset, short length) throws ISOException {

    final byte CONST_TAG = (byte) 0x5C;
    final short CONST_LEN = (short) 3;
    final byte CONST_TAG_EXTENDED = (byte) 0x2F;

    final byte CONST_TAG_DATA = (byte) 0x53;

    final short CONST_DO_GET_VERSION = (short) 0x4756; // GV
    final short CONST_DO_GET_STATUS = (short) 0x4753; // GS
    // final short CONST_DO_GET_CONFIG = (short) 0x4743; // GC
    // final short CONST_DO_GET_FIRST_DO = (short) 0x4644; // FD
    // final short CONST_DO_GET_NEXT_DO = (short) 0x4E44; // ND
    // final short CONST_DO_GET_FIRST_KEY = (short) 0x464B; // FK
    // final short CONST_DO_GET_NEXT_KEY = (short) 0x4E4B; // NK

    //
    // PRE-CONDITIONS
    //

    // Copy the APDU buffer to the scratch buffer so that we can reference it with our TLVReader
    if (buffer == null
        || offset < ZERO
        || length < ZERO
        || offset > (short) (buffer.length - length)
        || length > LENGTH_SCRATCH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    Util.arrayCopyNonAtomic(buffer, offset, scratch, ZERO, length);
    TLVReader reader = TLVReader.getInstance();
    reader.init(scratch, ZERO, length);

    // PRE-CONDITION 1 - The 'TAG' data element must be present
    if (!reader.match(CONST_TAG)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 2 - The 'TAG' data element must be the correct length
    if (reader.getLength() != CONST_LEN) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    // PRE-CONDITION 3 - The 'TAG' value must start with CONST_TAG_EXTENDED
    if (!reader.matchData(CONST_TAG_EXTENDED)) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    // Retrieve the 2-byte extended data identifier
    offset = reader.getDataOffset();
    offset++; // Move to the 2nd data byte
    short id = Util.getShort(scratch, offset);

    //
    // EXECUTION
    //
    // NOTE:
    // An assumption is made here that all responses can fit within a short length TLV object
    // so we put a sanity check at the end to make sure this is the case.
    //
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(scratch, ZERO, TLV.LENGTH_1BYTE_MAX, CONST_TAG_DATA);

    switch (id) {
      case CONST_DO_GET_VERSION:
        length = processGetVersion(writer);
        break;

      case CONST_DO_GET_STATUS:
        length = processGetStatus(writer);
        break;

      default:
        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        return (0); // Keep static analyser happy
    }

    // Length sanity check (I should never construct a length larger than a short length)
    if (length > TLV.LENGTH_1BYTE_MAX) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    // STEP 1 - Set up the outgoing chainbuffer
    chainBuffer.setOutgoing(scratch, ZERO, length, false);

    // Done - return how many bytes we will process
    return length;
  }
}
