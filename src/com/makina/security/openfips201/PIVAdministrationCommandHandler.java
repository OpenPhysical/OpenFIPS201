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
import javacard.framework.Util;
import javacard.security.CryptoException;
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
      byte[] scratch
          // #if ATTESTATION_ENABLED
          ,
      PIVAttestation attestation
      // #endif
      ) {
    this.owner = owner;
    this.config = config;
    this.cspPIV = cspPIV;
    this.dataStore = dataStore;
    this.chainBuffer = chainBuffer;
    this.secureMessaging = secureMessaging;
    this.scratch = scratch;
    // #if ATTESTATION_ENABLED
    this.attestation = attestation;
    // #endif
  }

  private void requireStructureMutable() {
    if (GPSystem.getCardContentState() != GPSystem.APPLICATION_SELECTABLE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  /**
   * Checks the required 'ID' element at the reader position and returns its value length. The
   * reader is left on the element so the caller can read the identifier before advancing.
   *
   * @param maxLength the longest identifier the operation accepts
   * @throws ISOException {@link PIV#SW_PUT_DATA_ID_MISSING} if the element is absent, or {@link
   *     PIV#SW_PUT_DATA_ID_INVALID_LENGTH} if its length is not between 1 and {@code maxLength}
   */
  private static short readIdLength(TLVReader reader, short maxLength) {
    if (!reader.match(CONST_TAG_ID)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_ID_MISSING);
    }
    short length = reader.getLength();
    if (length < (short) 1 || length > maxLength) {
      ISOException.throwIt(PIV.SW_PUT_DATA_ID_INVALID_LENGTH);
    }
    return length;
  }

  /** Reads the required contact and contactless access modes and advances past both tags. */
  private short readAccessModes(TLVReader reader) {
    if (!reader.match(CONST_TAG_MODE_CONTACT)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_MODE_CONTACT_MISSING);
    }
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(PIV.SW_PUT_DATA_MODE_CONTACT_INVALID_LENGTH);
    }
    byte contact = reader.toByte();
    owner.rejectUnsupportedOccAccessMode(contact);
    reader.moveNext();

    if (!reader.match(CONST_TAG_MODE_CONTACTLESS)) {
      ISOException.throwIt(PIV.SW_PUT_DATA_MODE_CONTACTLESS_MISSING);
    }
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(PIV.SW_PUT_DATA_MODE_CONTACTLESS_INVALID_LENGTH);
    }
    byte contactless = reader.toByte();
    owner.rejectUnsupportedOccAccessMode(contactless);
    reader.moveNext();
    return (short) (((short) (contact & 0xFF) << 8) | (short) (contactless & 0xFF));
  }

  /** Reads the optional administrative-key reference and advances when present. */
  private byte readOptionalAdminKey(TLVReader reader) {
    if (!reader.match(CONST_TAG_ADMIN_KEY)) {
      return (byte) 0;
    }
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(PIV.SW_PUT_DATA_MODE_ADMIN_KEY_INVALID_LENGTH);
    }
    byte adminKey = reader.toByte();
    reader.moveNext();
    return adminKey;
  }

  private void processPersonalizeAppletRequest(short requestLength) {
    if (requestLength != (short) 0
        || GPSystem.getCardContentState() != GPSystem.APPLICATION_SELECTABLE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    if (!cspPIV.hasUsableManagementKey()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // The FIPS certification profile may enter its irreversible operational
    // lifecycle only after its SP 800-73-5 Part 1, Table 1 profile is ready.
    if (FipsPolicy.ENABLED && !owner.isFipsPersonalizationReady()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    if (!GPSystem.setCardContentState(APP_STATE_PERSONALIZED)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  /**
   * Validates and creates one administrative data-object definition.
   *
   * <p>The request format selects whether capacity is required. Access-control parsing and object
   * policy checks are identical for every applet profile.
   *
   * @param reader reader positioned at the object identifier
   * @param compatibilityFormat {@code true} when the operation selector uses the compatibility
   *     request format, which does not carry a capacity field
   * @throws ISOException if a field is missing, malformed, unsupported, or not permitted
   */
  private void processCreateObjectRequest(TLVReader reader, boolean compatibilityFormat) {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITIONS 1 and 2 - The 'ID' tag MUST be present with length between 1 and 3
    short objectIdLength = readIdLength(reader, (short) 3);
    short idOffset = reader.getDataOffset();
    reader.moveNext();

    short accessModes = readAccessModes(reader);
    byte modeContact = (byte) (accessModes >> 8);
    byte modeContactless = (byte) accessModes;
    byte adminKey = readOptionalAdminKey(reader);

    short capacity = (short) 0;
    if (reader.match(CONST_TAG_CAPACITY)) {
      if (reader.getLength() != (short) 2) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      capacity = reader.toShort();
      if (capacity <= (short) 0) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      reader.moveNext();
    }
    if (!reader.isEOF()) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    // SP 800-73-5 Part 1 Table 8 defines card object capacities. Allocate that capacity during
    // CREATE OBJECT so later PUT DATA commands neither allocate persistent memory nor exceed it.
    if (capacity == (short) 0 && (!compatibilityFormat || FipsPolicy.ENABLED)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    if (!FipsPolicy.allowsObjectDefinition(
            reader.getBuffer(), idOffset, objectIdLength, modeContact, modeContactless)
        || !FipsPolicy.allowsObjectCapacity(
            reader.getBuffer(), idOffset, objectIdLength, capacity)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // #if ATTESTATION_ENABLED
    // 5FFF01 is the virtual read-only F9 certificate object served by the attestation authority.
    byte[] idBuffer = reader.getBuffer();
    if (objectIdLength == (short) 3
        && idBuffer[idOffset] == (byte) 0x5F
        && idBuffer[(short) (idOffset + 1)] == (byte) 0xFF
        && idBuffer[(short) (idOffset + 2)] == (byte) 0x01) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    // #endif

    dataStore.create(
        reader.getBuffer(),
        idOffset,
        objectIdLength,
        modeContact,
        modeContactless,
        adminKey,
        capacity);
  }

  private void processDeleteObjectRequest(TLVReader reader) {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITIONS 1 and 2 - The 'ID' tag MUST be present with length between 1 and 3
    short objectIdLength = readIdLength(reader, (short) 3);
    short idOffset = reader.getDataOffset();
    reader.moveNext();

    dataStore.delete(reader.getBuffer(), idOffset, objectIdLength);
  }

  /**
   * Validates and creates one administrative key definition.
   *
   * <p>The request format selects whether the key-attribute field is required. Mechanism, role,
   * access-control, and profile-policy validation remain the same for both request formats.
   *
   * @param reader reader positioned at the key identifier
   * @param compatibilityFormat {@code true} when the operation selector uses the compatibility
   *     request format, which does not carry a key-attribute field
   * @throws ISOException if a field is missing, malformed, unsupported, or not permitted
   */
  private void processCreateKeyRequest(TLVReader reader, boolean compatibilityFormat) {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITIONS 1 and 2 - The 'ID' tag MUST be present with length 1 only
    readIdLength(reader, (short) 1);
    byte id = reader.toByte();
    reader.moveNext();

    short accessModes = readAccessModes(reader);
    byte modeContact = (byte) (accessModes >> 8);
    byte modeContactless = (byte) accessModes;
    byte adminKey = readOptionalAdminKey(reader);

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
    // key-object definition path, but its shape is fixed: a P-256 signing key that is generated on
    // the card and never importable.
    if (id == ID_KEY_ATTESTATION
        // #if ATTESTATION_ENABLED
        && (modeContact != PIVObject.ACCESS_MODE_NEVER
            || modeContactless != PIVObject.ACCESS_MODE_NEVER
            || keyMechanism != ID_ALG_ECC_P256
            || keyRole != PIVKeyObject.ROLE_SIGN
            || keyAttribute != PIVKeyObject.ATTR_NONE)
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

    // STEP 1 - The compatibility format predates explicit key attributes. Apply PERMIT_MUTUAL
    // to preserve its symmetric-key behavior.
    if (compatibilityFormat && PIVCrypto.isSymmetricMechanism(keyMechanism)) {
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

    // PRE-CONDITIONS 1 and 2 - The 'ID' tag MUST be present with length 1 only
    readIdLength(reader, (short) 1);
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

    requireAdministrativeInterface();

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

    // A BULK request is refused: object allocation and key deletion cannot be rolled back reliably
    // as one Java Card transaction, so a batch could leave a partially applied administration set.
    // Each command therefore carries exactly one operation.
    if (reader.match(CONST_TAG_BULK_REQUEST)) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }

    final byte CONST_OP_COMPATIBILITY_DATA = (byte) 0x01;
    final byte CONST_OP_COMPATIBILITY_KEY = (byte) 0x02;

    // Get the operation value
    byte operation = reader.getTag();
    short operationLength = reader.getLength();
    short operationEnd = (short) (reader.getDataOffset() + operationLength);
    if (operationEnd != length) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    // PRE-CONDITION 1 - The tag must be constructed
    if (!reader.isConstructed()) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    // Move into the constructed tag
    reader.moveInto();

    //
    // The compatibility format supports existing issuance systems. It creates data objects and
    // keys only, and it uses the default applet settings.
    boolean compatibilityFormat = false;
    if (operation == CONST_TAG_COMPATIBILITY) {
      // PRE-CONDITION 2A - The compatibility operation tag must be present.
      if (!reader.match(CONST_TAG_COMPATIBILITY_OPERATION)) {
        ISOException.throwIt(PIV.SW_PUT_DATA_OP_MISSING);
      }
      // PRE-CONDITION 2B - The 'OPERATION' tag MUST have length 1
      if (reader.getLength() != (short) 1) {
        ISOException.throwIt(PIV.SW_PUT_DATA_OP_INVALID_LENGTH);
      }

      // Update the operation and move on
      compatibilityFormat = true;
      operation = reader.toByte();
      reader.moveNext();
    }

    switch (operation) {

        // Create a data object record
      case CONST_OP_COMPATIBILITY_DATA:
      case CONST_TAG_CREATE_OBJECT:
        requireStructureMutable();
        processCreateObjectRequest(reader, compatibilityFormat);
        break;

      case CONST_TAG_DELETE_OBJECT:
        requireStructureMutable();
        processDeleteObjectRequest(reader);
        break;

        // Create a key object record
      case CONST_OP_COMPATIBILITY_KEY:
      case CONST_TAG_CREATE_KEY:
        requireStructureMutable();
        processCreateKeyRequest(reader, compatibilityFormat);
        break;

      case CONST_TAG_DELETE_KEY:
        requireStructureMutable();
        processDeleteKeyRequest(reader);
        break;

        // Update one or more configuration parameters
      case CONST_TAG_UPDATE_CONFIG:
        requireStructureMutable();
        JCSystem.beginTransaction();
        try {
          config.update(reader);
          JCSystem.commitTransaction();
        } finally {
          if (JCSystem.getTransactionDepth() != (byte) 0) JCSystem.abortTransaction();
        }
        break;

      case CONST_TAG_PERSONALIZE_APPLET:
        processPersonalizeAppletRequest(operationLength);
        break;

      default:
        ISOException.throwIt(SW_PUT_DATA_OP_INVALID_VALUE);
    }
  }

  /**
   * Refuses a proprietary administrative command on an interface where administration is not
   * permitted ({@code OPTION_RESTRICT_CONTACTLESS_ADMIN}). {@link #putDataAdmin} and {@link
   * #changeReferenceDataAdmin} apply it before chaining or authorization, so the rule holds for
   * every CLA/INS form that reaches them (INS DB, 24 and 25), whether authorized by SCP or by a
   * prior admin-key authentication.
   */
  private void requireAdministrativeInterface() {
    if (!owner.isInterfacePermittedForAdmin()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  /**
   * This method is the equivalent of the CHANGE REFERENCE DATA command, however it is intended to
   * operate on key references that are NOT listed in SP 800-73-5. This is the primary method by
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
    byte mechanism = buffer[ISO7816.OFFSET_P1];

    // The PIV Card Application may allow the reference data associated with other key references
    // to be changed by the PIV Card Application CHANGE REFERENCE DATA, if PIV Card Application will
    // only perform the command with other key references if the requirements specified in Section
    // 2.9.2 of FIPS 201-2 are satisfied.
    requireAdministrativeInterface();

    //
    // COMMAND CHAIN HANDLING
    //

    // Pass the APDU to the chainBuffer instance first. It will return zero if there is store more
    // to of the chain to process, otherwise it will return the length of the large CDATA buffer.
    // The scratch buffer holds every key update, including the largest: a CS7 SM CVC of up to 384
    // octets with its sequence, element and algorithm headers.
    length = chainBuffer.processIncomingAPDU(buffer, offset, length, scratch, ZERO);

    // If the length is zero, just return so the caller can keep sending
    if (length == 0) return;

    // Proprietary UPDATE KEY uses P1=01 and carries the PIV algorithm reference in tag 80 before
    // the existing single-element key-update sequence.
    if (mechanism == (byte) 0x01 && id != ID_CVM_LOCAL_PIN && id != ID_CVM_PUK) {
      if (length < (short) 5 || scratch[ZERO] != (byte) 0x80 || scratch[(short) 1] != (byte) 0x01) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
      mechanism = scratch[(short) 2];
      length -= (short) 3;
      Util.arrayCopyNonAtomic(scratch, (short) 3, scratch, ZERO, length);
    }

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

        if (!owner.verifyPinFormat(scratch, ZERO, length)) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        if (!owner.verifyPinRules(scratch, ZERO, length)) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Update the PIN
        // NOTE: We ignore the history check here since this is an administrative update
        cspPIV.updatePIN(ID_CVM_LOCAL_PIN, scratch, ZERO, (byte) length, ZERO);
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
        // SP 800-73-5 Part 2 Section 2.4 fixes the PUK wire value to eight bytes.
        if (length != config.readValue(Config.CONFIG_PUK_LENGTH)) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        cspPIV.updatePIN(ID_CVM_PUK, scratch, ZERO, (byte) length, ZERO);

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

      // F9 provisioning requires an encrypted and MACed GlobalPlatform secure channel. A prior
      // management-key authentication may authorize ordinary key rotation, but it must not
      // authorize changes to the attestation trust root.
      // #if ATTESTATION_ENABLED
      if (key.getId() == ID_KEY_ATTESTATION && !cspPIV.getIsSecureChannel()) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        return; // Keep static analyser happy
      }
      // #endif

      // PRE-CONDITION 2 - Administrative conditions for this key object must be satisfied.
      // This allows either SCP or prior successful authentication with the key's admin key.
      if (!cspPIV.checkAccessModeAdmin(
          key, owner.isVciSatisfied(), owner.isGlobalPinAdvertised())) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        return; // Keep static analyser happy
      }

      // Set up our TLV reader
      TLVReader reader = TLVReader.getInstance();
      reader.init(scratch, ZERO, length);

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

      // #if ATTESTATION_ENABLED
      // F9 key material is generated on the card and never imported. Its only provisionable
      // element is the issuer-signed certificate, which never reaches PRE-CONDITION 7 or the
      // imported-origin marking below.
      if (key.getId() == ID_KEY_ATTESTATION) {
        if (!(key instanceof PIVKeyObjectECC)) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
          return; // Keep static analyser happy
        }
        processAttestationAuthorityElement(
            (PIVKeyObjectECC) key, elementTag, scratch, elementOffset, elementLength);
        cspPIV.clearAuthenticatedKey();
        return;
      }
      // #endif

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
      if (key instanceof PIVKeyObjectPKI) {
        PIVKeyObjectPKI importedKey = (PIVKeyObjectPKI) key;
        boolean hadPrivateKey = importedKey.isInitialised();
        if (hadPrivateKey
            && !importedKey.hasPendingImportedParts()
            && importedKey.isImportedKeyMaterial(elementTag)) {
          ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // The element is written and the pair-wise consistency test runs outside any transaction.
        // JC 3.0.5 API Util.arrayCopyNonAtomic "does not use the transaction facility during the
        // copy operation even if a transaction is in progress", and the API leaves the transaction
        // participation of key-component setters unspecified, so an abort cannot be relied on to
        // restore them. A component of an incomplete import is not usable, because isInitialised()
        // requires the ready flag. Only the import-state flags are committed as one transaction,
        // which bounds its commit-capacity use (JCRE 3.0.5 Section 7.8) to a few bytes. A failure
        // clears the key after any transaction has closed, so the cleared state is what persists.
        short failure = ZERO;
        try {
          key.updateElement(elementTag, scratch, elementOffset, elementLength);
          if (elementTag != PIVKeyObject.ELEMENT_CLEAR) {
            if (importedKey.isLastImportedPart(elementTag)
                && !importedKey.pairwiseConsistencyTest(scratch, ZERO)) {
              failure = ISO7816.SW_FILE_INVALID;
            } else {
              JCSystem.beginTransaction();
              importedKey.completesImportedKeyPair(elementTag);
              if (!importedKey.hasPendingImportedParts() && importedKey.hasPrivateMaterial()) {
                importedKey.markImportedPairReady();
              }
              JCSystem.commitTransaction();
            }
          }
        } catch (CryptoException e) {
          // Key material the provider refuses, including during the pair-wise consistency test, is
          // an "Incorrect parameter in command data field" (SP 800-73-5 Part 2 Section 3.2.2).
          failure = ISO7816.SW_WRONG_DATA;
        } finally {
          if (JCSystem.getTransactionDepth() != (byte) 0) {
            JCSystem.abortTransaction();
          }
        }
        if (failure != ZERO) {
          key.clear();
          ISOException.throwIt(failure);
        }
      } else {
        key.updateElement(elementTag, scratch, elementOffset, elementLength);
      }
      if (elementTag != PIVKeyObjectECC.ELEMENT_SM_CVC) {
        key.markImported();
      }

      // STEP 4 - Clear any prior key-authenticated session after a key value change.
      cspPIV.clearAuthenticatedKey();
    } finally {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
    }
  }

  // #if ATTESTATION_ENABLED
  /**
   * Applies one provisioning element to the F9 attestation authority.
   *
   * <p>Only element 70, the issuer-signed F9 certificate, is accepted. F9 key components (86, 87)
   * are never importable because the key pair is generated on the card ({@code 6982}). Any other
   * element is malformed ({@code 6A80}). Once a certificate has been accepted or the applet is
   * PERSONALIZED, every element returns {@code 6985}. A successful load runs the activation wipe of
   * every other key and data object, then activates the authority.
   *
   * @param authority the F9 key object
   * @param elementTag element tag
   * @param buffer buffer holding the element value
   * @param offset first value octet
   * @param length value length
   */
  private void processAttestationAuthorityElement(
      PIVKeyObjectECC authority, byte elementTag, byte[] buffer, short offset, short length) {
    owner.completeAttestationActivation();
    attestation.requireAuthorityProvisionable();
    if (elementTag == PIVAttestation.ELEMENT_PUBLIC_KEY
        || elementTag == PIVAttestation.ELEMENT_PRIVATE_KEY) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
    if (elementTag != PIVAttestation.ELEMENT_CERTIFICATE) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    attestation.loadAuthorityCertificate(authority, buffer, offset, length);
    // ACTIVATING is persistent, so a tear during the wipe is resumed at the next selection.
    owner.completeAttestationActivation();
  }
  // #endif

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
    final byte CONST_TAG_PLATFORM_ID = (byte) 0x88;

    // Applet State
    writer.write(CONST_TAG_APPLET_STATE, GPSystem.getCardContentState());

    // PIN Verified
    writer.write(
        CONST_TAG_PIN_VERIFIED,
        cspPIV.getIsPINVerified(owner.isGlobalPinAdvertised()) ? (byte) 1 : (byte) 0);

    // PIN Always
    writer.write(
        CONST_TAG_PIN_ALWAYS,
        cspPIV.getIsPINAlways(owner.isGlobalPinAdvertised()) ? (byte) 1 : (byte) 0);

    // SM State
    writer.write(CONST_TAG_SM_STATE, secureMessaging.isEstablished() ? (byte) 1 : (byte) 0);

    // VCI State
    writer.write(CONST_TAG_VCI_STATE, secureMessaging.isVciEstablished() ? (byte) 1 : (byte) 0);

    // SCP State
    writer.write(CONST_TAG_SCP_STATE, cspPIV.getIsSecureChannel() ? (byte) 1 : (byte) 0);

    // Contactless
    writer.write(CONST_TAG_CONTACTLESS, cspPIV.getIsContactless() ? (byte) 1 : (byte) 0);

    // FIPS Mode
    writer.write(CONST_TAG_FIPS_MODE, FipsPolicy.ENABLED ? (byte) 1 : (byte) 0);

    writer.write(
        CONST_TAG_PLATFORM_ID,
        BuildProfile.PLATFORM_ID,
        ZERO,
        (short) BuildProfile.PLATFORM_ID.length);

    // #if ATTESTATION_ENABLED
    // Attestation authority state, and once ACTIVE the card OPID (F9 subject serialNumber) and
    // the F9 subject key identifier. The worst case (32-octet platform ID, 17-digit OPID) is 102
    // octets, within the single-octet length this response uses.
    final byte CONST_TAG_ATTESTATION_STATE = (byte) 0x89;
    final byte CONST_TAG_OPID = (byte) 0x8A;
    final byte CONST_TAG_AUTHORITY_KEY_ID = (byte) 0x8B;
    writer.write(CONST_TAG_ATTESTATION_STATE, attestation.getAuthorityState());
    if (attestation.isAuthorityActive()) {
      byte[] container = attestation.getAuthorityContainer();
      writer.write(
          CONST_TAG_OPID, container, attestation.getOpidOffset(), attestation.getOpidLength());
      writer.write(
          CONST_TAG_AUTHORITY_KEY_ID,
          container,
          attestation.getKeyIdOffset(),
          PIVAttestation.LENGTH_KEY_IDENTIFIER);
    }
    // #endif

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
    writer.init(scratch, ZERO, TLV.LENGTH_1BYTE_MAX, PIV.CONST_TAG_DATA);

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
