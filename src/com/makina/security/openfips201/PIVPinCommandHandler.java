/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2017 Commonwealth of Australia
 ******************************************************************************/

package com.makina.security.openfips201;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.PIN;

/** Handles PIV PIN, PUK, pairing-code, and CVM policy commands. */
final class PIVPinCommandHandler {
  private static final byte ZERO = (byte) 0;
  private static final byte PIN_PADDING_BYTE = (byte) 0xFF;

  // SP 800-73-5 Part 2 Sections 3.2.2 and 3.2.3 fix Lc at '10' for CHANGE REFERENCE DATA and RESET
  // RETRY COUNTER: two eight-byte fields for the PIN, PUK and new reference data. Configured PIN
  // length limits constrain the significant value before 'FF' padding, never the field width.
  private static final byte LENGTH_REFERENCE_FIELD = Config.LIMIT_PIN_MAX_LENGTH;

  private static final byte ID_CVM_GLOBAL_PIN = PIV.ID_CVM_GLOBAL_PIN;
  private static final byte ID_CVM_LOCAL_PIN = PIV.ID_CVM_LOCAL_PIN;
  private static final byte ID_CVM_PUK = PIV.ID_CVM_PUK;
  private static final byte ID_CVM_PAIRING_CODE = PIV.ID_CVM_PAIRING_CODE;
  private static final short SW_RETRIES_REMAINING = PIV.SW_RETRIES_REMAINING;
  private static final short SW_AUTHENTICATION_METHOD_BLOCKED =
      PIV.SW_AUTHENTICATION_METHOD_BLOCKED;
  private static final short SW_VERIFICATION_FAILED = PIV.SW_VERIFICATION_FAILED;
  private static final short SW_REFERENCE_NOT_FOUND = PIV.SW_REFERENCE_NOT_FOUND;
  private final PIV owner;
  private final Config config;
  private final PIVSecurityProvider cspPIV;
  private final PIVDataStore dataStore;
  private final PIVSecureMessaging secureMessaging;
  private final byte[] scratch;

  PIVPinCommandHandler(
      PIV owner,
      Config config,
      PIVSecurityProvider cspPIV,
      PIVDataStore dataStore,
      PIVSecureMessaging secureMessaging,
      byte[] scratch) {
    this.owner = owner;
    this.config = config;
    this.cspPIV = cspPIV;
    this.dataStore = dataStore;
    this.secureMessaging = secureMessaging;
    this.scratch = scratch;
  }

  void verify(byte id, byte[] buffer, short offset, short length) throws ISOException {

    //
    // PRE-CONDITIONS
    //

    if (id == ID_CVM_PAIRING_CODE) {
      requirePairingCodeReference();
      verifyPairingCode(buffer, offset, length);
      return;
    }

    // PRE-CONDITION 1 - The PIN reference must point to a valid PIN
    PIVPIN pin = cspPIV.getPIN(id);
    if (pin == null) {
      ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
      return;
    }

    requireEnabledPinReference(id);
    requirePinInterface();

    // PRE-CONDITION 3 - The supplied PIN format must be valid
    // If the key reference is '00' or '80' and the authentication data in the command data
    // field does not satisfy the criteria in Section 2.4.3, then the card command shall fail
    // and the PIV Card Application shall return either the status word '6A 80' or '63 CX'.
    // If status word '6A 80' is returned, the security status and the retry counter of the key
    // reference shall remain unchanged. If status word '63 CX' is returned, the security
    // status of the key reference shall be set to FALSE and the retry counter associated with
    // the key reference shall be decremented by one.
    // NOTE: We return 6A80 (WRONG DATA) and therefore do NOT decrement the counter or block
    if (!verifyPinFormat(buffer, offset, length)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 4 - The PIN must not be blocked
    // PRE-CONDITION 5 - If using the contactless interface, the pin retries remaining must not
    //					 fall below the specified intermediate retry amount

    // In order to protect against blocking over the contactless interface, PIV Card Applications
    // that implement secure messaging shall define an issuer-specified intermediate retry value for
    // each of these key references and return '69 83' if the command is submitted over the
    // contactless interface (over secure messaging or the VCI, as required for the key reference)
    // and the current value of the retry counter associated with the key reference is at or below
    // the issuer-specified intermediate retry value. If status word '69 83' is returned, then the
    // comparison shall not be made, and the security status and the retry counter of the key
    // reference shall remain unchanged.
    byte intermediateRetries = config.getIntermediatePINRetries();
    requireUsableRetries(pin, intermediateRetries);

    //
    // EXECUTION STEPS
    //

    // Verify the PIN
    if (!pin.check(buffer, offset, (byte) length)) {
      throwRetriesRemaining(pin, intermediateRetries);
    }

    // Verified, set the PIN ALWAYS flag
    cspPIV.markPINAlways();
  }

  /**
   * Implements the variant of the 'VERIFY' command that returns the status of the requested PIN
   *
   * @param id The requested PIN reference
   */
  void verifyGetStatus(byte id) throws ISOException {

    //
    // PRE-CONDITIONS
    //

    if (id == ID_CVM_PAIRING_CODE) {
      requirePairingCodeReference();
      if (!owner.isPairingCodeVerified()) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }
      return;
    }

    // PRE-CONDITION 1 - The PIN reference must point to a valid PIN
    PIN pin = cspPIV.getPIN(id);
    if (pin == null) {
      ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
      return;
    }

    requireEnabledPinReference(id);
    requirePinInterface();

    // SP 800-73-5 Part 2 Section 3.2.1: "If P1='00' and Lc and the command data field are absent,
    // the command CAN be used to retrieve the number of further retries allowed ('63 CX') or to
    // check whether verification is not needed ('90 00')." The contactless intermediate-retry
    // '69 83' rule applies when "Lc and the command data field are present", so the status form
    // reports the retries usable on this interface (63C0 at the reserve) and returns '69 83' only
    // for a retry counter of zero.
    if (pin.getTriesRemaining() == ZERO) ISOException.throwIt(SW_AUTHENTICATION_METHOD_BLOCKED);

    // If we are not validated
    if (!pin.isValidated()) {
      throwRetriesRemaining(pin, config.getIntermediatePINRetries());
    }

    // If we got this far we are authenticated, so just return (9000)
  }

  /**
   * Returns the retries usable on the current interface. Over contactless, SP 800-73-5 Part 2
   * Section 3.2.1 reserves the issuer-specified intermediate retry value for the contact interface.
   * The result is never negative.
   */
  static short usableRetries(byte triesRemaining, byte intermediateRetries, boolean contactless) {
    short remaining = (short) (triesRemaining & 0xFF);
    if (contactless) remaining -= (short) (intermediateRetries & 0xFF);
    return remaining < (short) 0 ? (short) 0 : remaining;
  }

  private short usableRetries(PIN pin, byte intermediateRetries) {
    return usableRetries(pin.getTriesRemaining(), intermediateRetries, cspPIV.getIsContactless());
  }

  /**
   * Throws '69 83' when the reference is blocked, or over contactless when its retry counter is at
   * or below the intermediate retry value. SP 800-73-5 Part 2 Sections 3.2.1, 3.2.2 and 3.2.3 apply
   * this before any comparison, leaving the security status and retry counter unchanged.
   */
  private void requireUsableRetries(PIN pin, byte intermediateRetries) {
    if (usableRetries(pin, intermediateRetries) <= (short) 0) {
      ISOException.throwIt(SW_AUTHENTICATION_METHOD_BLOCKED);
    }
  }

  /** Throws '63 CX' with the retries usable on the current interface after a failed comparison. */
  private void throwRetriesRemaining(PIN pin, byte intermediateRetries) {
    ISOException.throwIt((short) (SW_RETRIES_REMAINING | usableRetries(pin, intermediateRetries)));
  }

  /**
   * Replaces reference data after a successful comparison against {@code authenticator}.
   *
   * <p>PIN history is evaluated inside {@link PIVSecurityProvider#updatePIN} after the comparison,
   * so a history match is never reported to a caller that has not proven the current PIN or PUK.
   * When history or the platform rejects the update, the reference data is unchanged and the
   * authenticator's security status returns to its value before the comparison.
   */
  private void commitReferenceData(
      byte id, PIN authenticator, boolean wasValidated, byte[] buffer, short offset) {
    try {
      cspPIV.updatePIN(
          id, buffer, offset, LENGTH_REFERENCE_FIELD, config.readValue(Config.CONFIG_PIN_HISTORY));
    } catch (ISOException e) {
      if (!wasValidated) authenticator.reset();
      ISOException.throwIt(e.getReason());
    }
  }

  /**
   * Implements the variant of the 'VERIFY' command that resets the authentication state of the
   * requested PIN
   *
   * @param id The requested PIN reference
   */
  void verifyResetStatus(byte id) throws ISOException {

    // The security status of the key reference specified in P2 shall be set to FALSE and
    // the retry counter associated with the key reference shall remain unchanged.

    if (id == ID_CVM_PAIRING_CODE) {
      requirePairingCodeReference();
      // VERIFY reset for key reference 0x98 resets pairing security status only. Keep the
      // established SM session so the application status can still be returned under SM.
      secureMessaging.resetPairingVerified();
      return;
    }

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The PIN reference must point to a valid PIN
    PIN pin = cspPIV.getPIN(id);
    if (pin == null) {
      ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
      return;
    }

    requireEnabledPinReference(id);
    requirePinInterface();

    // Reset the requested PIN
    pin.reset();

    // Reset the PIN ALWAYS flag
    cspPIV.clearPINAlways();
  }

  private void requireEnabledPinReference(byte id) {
    if (id == ID_CVM_GLOBAL_PIN) {
      if (!config.readFlag(Config.CONFIG_PIN_ENABLE_GLOBAL) || !owner.isGlobalPinAdvertised()) {
        ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
      }
      return;
    }
    if (id == ID_CVM_LOCAL_PIN) {
      if (!config.readFlag(Config.CONFIG_PIN_ENABLE_LOCAL)) {
        ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
      }
      return;
    }
    ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
  }

  private void requirePinInterface() {
    if (!cspPIV.getIsContactless() || config.readFlag(Config.OPTION_IGNORE_CONTACTLESS_ACL)) {
      return;
    }
    if (!config.readFlag(Config.CONFIG_PIN_PERMIT_CONTACTLESS) || !owner.isVciSatisfied()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  /**
   * Verifies the pairing code over secure messaging.
   *
   * <p>Aligned with NIST SP 800-73-5 Part 1 Section 5.1.3 (Pairing Code) and Part 2 Table 2 (VERIFY
   * command using Key Reference 0x98 for the pairing code).
   */
  private void verifyPairingCode(byte[] buffer, short offset, short length) {
    if (length != PIVDataCommandHandler.PAIRING_CODE_LENGTH
        || !PIVDataCommandHandler.isDecimalDigits(buffer, offset, length)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Read the Pairing Code Reference Data Container (Tag 0x5FC123) defined in
    // SP 800-73-5 Part 1 Section 3.3.8 / Table 44.
    PIVDataObject object = dataStore.find(PIV.ID_DATA_PAIRING_CODE_REFERENCE, ZERO, (short) 3);
    if (object == null || !object.isInitialised()) ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
    if (!PIVDataCommandHandler.isValidPairingCodeContainer(object)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    // SP 800-73-5 Part 2 / SP 800-85A-4 AS05.16A-R4 require 63 00 for a
    // well-formed but non-matching pairing code. Pairing has no retry counter.
    if (!PIVSecurityProvider.arrayEqualsConstantTime(
        object.content,
        PIVDataCommandHandler.PAIRING_CODE_OFFSET,
        buffer,
        offset,
        PIVDataCommandHandler.PAIRING_CODE_LENGTH)) {
      // SP 800-73-5 Part 2 Section 3.2.1.3 requires a 63 00 pairing failure to set the
      // pairing-code security status to FALSE. The secure-messaging session remains established.
      secureMessaging.resetPairingVerified();
      ISOException.throwIt(SW_VERIFICATION_FAILED);
    }

    secureMessaging.markPairingVerified();
  }

  private void requirePairingCodeReference() {
    // SP 800-73-5 Part 1 Section 3.3.2 exposes key reference 98 only when the
    // stored Discovery Object advertises VCI with pairing required.
    if (!owner.isPairingCodeReferenceEnabled()) ISOException.throwIt(SW_REFERENCE_NOT_FOUND);

    // SP 800-73-5 Part 2 Table 2 permits pairing-code VERIFY as Always on contact;
    // contactless use requires a protected secure-messaging command.
    if (cspPIV.getIsContactless() && !owner.isSecureMessagingCommand()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  /**
   * The CHANGE REFERENCE DATA card command initiates the comparison of the authentication data in
   * the command data field with the current value of the reference data and, if this comparison is
   * successful, replaces the reference data with new reference data.
   *
   * @param id The requested PIN reference
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset of the CDATA element
   * @param length The length of the CDATA element
   */
  void changeReferenceData(byte id, byte[] buffer, short offset, short length) throws ISOException {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The PIN reference must point to a valid PIN
    PIN pin = cspPIV.getPIN(id);
    if (pin == null) {
      ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
      return;
    }

    if (FipsPolicy.ENABLED && cspPIV.getIsContactless() && id == ID_CVM_PUK) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }

    // PRE-CONDITION 2
    // Only reference data associated with key references '80' and '81' specific to the PIV Card
    // Application (i.e., local key reference) and the Global PIN with key reference '00' may be
    // changed by the PIV Card Application CHANGE REFERENCE DATA command.
    // Key reference '80' reference data shall be changed by the PIV Card Application CHANGE
    // REFERENCE DATA command. The ability to change reference data associated with key references
    // '81' and '00' using the PIV Card Application CHANGE REFERENCE DATA command is optional.

    // If key reference '81' is specified and the command is submitted over the contactless
    // interface (including SM or VCI), then the card command shall fail. If key reference
    // '00' or '80' is specified and the command is not submitted over either the contact interface
    // or the VCI, then the card command shall fail. In each case, the security status and the
    // retry counter of the key reference shall remain unchanged.

    byte intermediateRetries;
    boolean puk = false;

    switch (id) {
      case ID_CVM_GLOBAL_PIN:
      case ID_CVM_LOCAL_PIN:
        // Key references '00' and '80' share the VERIFY enablement rule and the Table 2 rule that
        // permits them over contactless only through the VCI. A Global PIN change additionally
        // requires the platform CVM Management privilege; PIVSecurityProvider.updatePIN reports
        // its absence.
        requireEnabledPinReference(id);
        requirePinInterface();
        intermediateRetries = config.getIntermediatePINRetries();
        break;

      case ID_CVM_PUK:
        // Make sure CONFIG_PUK_ENABLED is set
        if (!config.readFlag(Config.CONFIG_PUK_ENABLED)) {
          ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        }

        // SP 800-73-5 Part 2 Section 3.2.2: "If key reference '81' is specified and the command is
        // not submitted over the contact interface, then the card command SHALL fail." The
        // contactless PUK configuration flag does not relax this.
        if (cspPIV.getIsContactless()) {
          ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        intermediateRetries = config.getIntermediatePUKRetries();
        puk = true;
        break;

      default:
        ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
        return; // Keep static analyser happy
    }

    // If the current value of the retry counter associated with the key reference is zero, then the
    // reference data associated with the key reference shall not be changed and the
    // PIV Card Application shall return the status word '69 83'.

    // If the command is submitted over the contactless interface (VCI) and the current value of the
    // retry counter associated with the key reference is at or below the issuer-specified
    // intermediate retry value (see Section 3.2.1),
    // then the reference data associated with the key reference shall not be changed and the PIV
    // Card Application shall return the status word '69 83'.
    requireUsableRetries(pin, intermediateRetries);

    // If the authentication data in the command data field does not match the current value of the
    // reference data or if either the authentication data or the new reference data in the command
    // data field of the command does not satisfy the criteria in Section 2.4.3, the PIV Card
    // Application shall not change the reference data
    // associated with the key reference and shall return either status word '6A 80' or '63 CX',
    // with the following restrictions.
    // SIMPLIFIED: If [Old PIN format is BAD] or [New PIN format is BAD] you can choose 6A80 or
    // 63CX. We choose 6A80

    // If the authentication data in the command data field satisfies the criteria in Section 2.4.3
    // and matches the current value of the reference data, but the new reference data in the
    // command data field of the command does not satisfy the criteria in Section 2.4.3, the PIV
    // Card Application shall return status word '6A 80'.
    // SIMPLIFIED: If [Old PIN is GOOD] but [New PIN format is BAD], use 6A80.

    // If the authentication data in the command data field does not match the current value of the
    // reference data, but both the authentication data and the new reference data in the command
    // data field of the command satisfy the criteria in Section 2.4.3, the PIV Card Application
    // shall return status word '63 CX'.
    // SIMPLIFIED: If [Old PIN format is GOOD] but [Old PIN is BAD], use 63CX and decrement.

    // If status word '6A 80' is returned, the security status and retry counter associated with the
    // key reference shall remain unchanged.9 If status word '63 CX' is returned, the security
    // status of the key reference shall be set to FALSE and the retry counter associated with the
    // key reference shall be decremented by one.

    // If the new reference data (PIN) in the command data field of the command does not satisfy the
    // criteria in Section 2.4.3, then the PIV Card Application shall return the status word '6A
    // 80'.

    if (length != (short) (LENGTH_REFERENCE_FIELD + LENGTH_REFERENCE_FIELD)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // SP 800-73-5 Part 2 Section 3.2.2 requires a 6A80 format/policy failure for the new
    // reference data to leave both security status and retry state unchanged. Validate the new
    // PIN before pin.check(), because a successful OwnerPIN check changes both states.
    short newReferenceOffset = (short) (offset + LENGTH_REFERENCE_FIELD);
    if (!puk) {
      if (!verifyPinFormat(buffer, newReferenceOffset, LENGTH_REFERENCE_FIELD)) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      if (!verifyPinRules(buffer, newReferenceOffset, LENGTH_REFERENCE_FIELD)) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
    }

    // Verify the authentication reference data (old PIN/PUK) format
    if (!puk && !verifyPinFormat(buffer, offset, LENGTH_REFERENCE_FIELD)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Verify the authentication reference data (old PIN/PUK) value
    boolean wasValidated = pin.isValidated();
    if (!pin.check(buffer, offset, LENGTH_REFERENCE_FIELD)) {
      throwRetriesRemaining(pin, intermediateRetries);
    }

    //
    // EXECUTION STEPS
    //

    // If the card command succeeds, then the security status of the key reference shall be set to
    // TRUE and the retry counter associated with the key reference shall be set to the reset retry
    // value associated with the key reference.

    // STEP 1 - Update the reference data
    commitReferenceData(id, pin, wasValidated, buffer, newReferenceOffset);

    // STEP 2 - Verify the new reference data, which sets the security status to TRUE and resets the
    // retry counter. The update succeeded, so a mismatch is an internal failure.
    if (!pin.check(buffer, newReferenceOffset, LENGTH_REFERENCE_FIELD)) {
      ISOException.throwIt(ISO7816.SW_UNKNOWN);
    }

    // STEP 3 - Set the PIN ALWAYS flag as this is now verified (if it is not the PUK)
    if (!puk) {
      cspPIV.markPINAlways();
    }

    // Done
  }

  /**
   * The RESET RETRY COUNTER card command resets the retry counter of the PIN to its initial value
   * and changes the reference data. The command enables recovery of the PIV Card Application PIN in
   * the case that the cardholder has forgotten the PIV Card Application PIN.
   *
   * @param id The requested PIN reference
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset of the CDATA element
   * @param length The length of the CDATA element
   */
  void resetRetryCounter(byte id, byte[] buffer, short offset, short length) throws ISOException {

    if (FipsPolicy.ENABLED && cspPIV.getIsContactless()) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The LOCAL PIN must be enabled
    if (!config.readFlag(Config.CONFIG_PIN_ENABLE_LOCAL)) {
      ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
    }

    // PRE-CONDITION 2 - The PUK must be enabled
    if (!config.readFlag(Config.CONFIG_PUK_ENABLED)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 3 - The command is never performed over the contactless interface.
    // SP 800-73-5 Part 2 Table 2 marks RESET RETRY COUNTER "No" for the contactless interface:
    // "The PIV Card Application shall return the status word of '6A 81' (Function not supported)
    // when it receives a card command on the contactless interface marked "No" in the Contactless
    // Interface column in Table 2." Its only exception is card management meeting FIPS 201-2
    // Section 2.9.2, which a PUK-authorized cardholder reset is not, so the contactless PIN and PUK
    // configuration flags do not enable it.
    if (cspPIV.getIsContactless()) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }

    // PRE-CONDITION 4 - The supplied ID must be the Card PIN
    // The only key reference allowed in the P2 parameter of the RESET RETRY COUNTER command is the
    // PIV Card Application PIN. If a key reference is specified in P2 that is not supported by the
    // card, the PIV Card Application shall return the status word '6A 88'.
    if (id != ID_CVM_LOCAL_PIN) ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
    PIN pin = cspPIV.getPIN(id);
    if (pin == null) {
      ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
      return; // Keep compiler happy
    }

    // The command dispatcher rejects any other Lc with 6A80 before this handler runs; the same
    // status word applies to a direct call.
    if (length != (short) (LENGTH_REFERENCE_FIELD + LENGTH_REFERENCE_FIELD)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 6 - The PUK must not be blocked
    // If the current value of the PUK's retry counter is zero, then the PIN's retry counter shall
    // not be reset and the PIV Card Application shall return the status word '69 83'.
    PIN puk = cspPIV.getPIN(ID_CVM_PUK);
    if (puk == null) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      return; // Keep compiler happy
    }

    byte intermediateRetries = config.getIntermediatePUKRetries();
    requireUsableRetries(puk, intermediateRetries);

    // PRE-CONDITION 7 - Check the format and rules of the NEW PIN value before the PUK comparison
    // If the new reference data (PIN) in the command data field of the command does not satisfy the
    // criteria in Section 2.4.3, then the PIV Card Application shall return the status word '6A
    // 80'. If the PIV Card Application returns status word '6A 80', then the retry counter
    // associated with the PIN shall not be reset, the security status of the PIN's key reference
    // shall remain unchanged, and the PUK's retry counter shall remain unchanged.
    // A successful OwnerPIN check resets the PUK retry counter, so these checks precede it. When
    // the PUK is also wrong, the specification permits either '6A 80' or '63 CX'; this card
    // returns '6A 80'.
    short newReferenceOffset = (short) (offset + LENGTH_REFERENCE_FIELD);
    if (!verifyPinFormat(buffer, newReferenceOffset, LENGTH_REFERENCE_FIELD)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Since this will be the new value, apply our PIN complexity rules
    if (!verifyPinRules(buffer, newReferenceOffset, LENGTH_REFERENCE_FIELD)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 8 - Verify the PUK value
    // If the reset retry counter authentication data (PUK) in the command data field of the command
    // does not match reference data associated with the PUK, then the PIV Card Application shall
    // return the status word '63 CX'. If the PIV Card Application returns status word '63 CX', then
    // the retry counter associated with the PIN shall not be reset, the security status of the
    // PIN's key reference shall be set to FALSE, and the PUK's retry counter shall be decremented
    // by one.
    boolean pukWasValidated = puk.isValidated();
    if (!puk.check(buffer, offset, LENGTH_REFERENCE_FIELD)) {
      pin.reset();
      throwRetriesRemaining(puk, intermediateRetries);
    }

    //
    // EXECUTION STEPS
    //

    // If the card command succeeds, then the PIN's retry counter shall be set to its reset retry
    // value. Optionally, the PUK's retry counter may be set to its initial reset retry value.
    // The security status of the PIN's key reference shall not be changed.

    // NOTE: Since the PUK was verified, the OwnerPIN object automatically resets the PUK counter,
    // which governs the above behaviour

    boolean wasValidated = pin.isValidated();

    // Update, reset and unblock the PIN.
    commitReferenceData(id, puk, pukWasValidated, buffer, newReferenceOffset);

    // SP 800-73-5 Part 2 Section 3.2.3 requires successful RESET RETRY COUNTER to
    // leave the PIN security status unchanged. OwnerPIN.update clears validation.
    if (wasValidated && !pin.check(buffer, newReferenceOffset, LENGTH_REFERENCE_FIELD)) {
      ISOException.throwIt(ISO7816.SW_UNKNOWN);
    }
  }

  /**
   * Allows the applet to provide state information to PIV for access control
   *
   * @param value Sets whether the current interface is contactless
   */
  boolean verifyPinRules(byte[] buffer, short offset, short length) {

    boolean passed = true;

    //
    // RULE 1 - SEQUENCE RULE (Ascending and Descending)
    //
    byte ruleSequence = config.readValue(Config.CONFIG_PIN_RULE_SEQUENCE);
    if (ruleSequence > (byte) 0) {
      byte last = (byte) 0;
      byte ascendingCount = (byte) 1;
      byte descendingCount = (byte) 1;
      byte maxAscending = (byte) 0;
      byte maxDescending = (byte) 0;

      for (short i = 0; i < length; i++) {

        byte value = buffer[(short) (offset + i)];

        // If we have reached padding bytes, we are done checking
        if (value == PIN_PADDING_BYTE) break;

        // HACK: We make use of the fact that the ASCII value 0h is not possible
        // for a PIN value.

        // ASCENDING TALLY
        if (last != (byte) 0 && (byte) (last + (byte) 1) == value) {
          ascendingCount++; // Increment the counter
        } else {
          // Track our largest sequence and continue
          maxAscending = (ascendingCount > maxAscending) ? ascendingCount : maxAscending;
          ascendingCount = (byte) 1;
        }

        // DESCENDING TALLY
        if (last != (byte) 0 && (byte) (last - (byte) 1) == value) {
          descendingCount++; // Increment the counter
        } else {
          // Track our largest sequence and continue
          maxDescending = (descendingCount > maxDescending) ? descendingCount : maxDescending;
          descendingCount = (byte) 1;
        }

        last = value;
      }

      // Track our final counts
      maxAscending = (ascendingCount > maxAscending) ? ascendingCount : maxAscending;
      maxDescending = (descendingCount > maxDescending) ? descendingCount : maxDescending;

      if (maxAscending >= ruleSequence || maxDescending >= ruleSequence) passed = false;
    }

    //
    // RULE 2 - DISTINCTIVENESS RULE
    //
    // If the distinctiveness rule applies (n > 0) then a PIN is rejected if any single character
    // is re-used more than [n] times.
    //

    byte ruleDistinct = config.readValue(Config.CONFIG_PIN_RULE_DISTINCT);
    if (ruleDistinct > (byte) 0) {
      byte maxSingle = (byte) 0;

      short end = (short) (offset + length);
      for (short i = offset; i < end; i++) {
        byte count = (byte) 1; // Every used digit has at least 1
        for (short j = (short) (i + (short) 1); j < end; j++) {
          // If we have a padding byte, we are done checking for this digit
          if (buffer[i] == PIN_PADDING_BYTE) break;
          if (buffer[i] == buffer[j]) count++;
        }
        maxSingle = (count > maxSingle) ? count : maxSingle;
      }

      if (maxSingle >= ruleDistinct) passed = false;
    }

    // Done
    return passed;
  }

  /**
   * Performs data validation on an incoming PIN number to ensure that it conforms to SP800-73-4
   * Part 2 - Authentication of an Individual
   *
   * @param buffer The buffer containing the PIN
   * @param offset The offset of the PIN data
   * @param length The length of the PIN data
   * @return True if the supplied PIN conforms to the format requirements
   */
  boolean verifyPinFormat(byte[] buffer, short offset, short length) throws ISOException {

    // The amount to add to convert upper-case to lower-case
    final byte CONST_ALPHA_CASE_DELTA = (byte) 32;

    // The pairing code shall be exactly 8 bytes in length and the PIV Card Application
    // PIN shall be between 6 and 8 bytes in length. If the actual length of PIV Card Application
    // PIN is less than 8 bytes it shall be padded to 8 bytes with 'FF' when presented to the card
    // command interface. The 'FF' padding bytes shall be appended to the actual value of the PIN.

    // The APDU field is always eight bytes. Configuration limits the significant value before
    // padding, not the wire width.
    byte minLength = config.readValue(Config.CONFIG_PIN_MIN_LENGTH);
    byte maxLength = config.readValue(Config.CONFIG_PIN_MAX_LENGTH);
    if (length != Config.LIMIT_PIN_MAX_LENGTH) {
      return false;
    }

    // The bytes comprising the PIV Card Application PIN and pairing code shall be limited to values
    // 0x30-0x39, the ASCII values for the decimal digits '0'-'9'. For example,
    // 		+ Actual PIV Card Application PIN: '123456' or '31 32 33 34 35 36'
    //		+ Padded PIV Card Application PIN presented to the card command interface:
    //        '31 32 33 34 35 36 FF FF'

    // The PIV Card Application shall enforce the minimum length requirement of six bytes for the
    // PIV Card Application PIN (i.e., shall verify that at least the first six bytes of the value
    // presented to the card command interface are in the range 0x30-0x39) as well as the other
    // formatting requirements specified in this section.

    // If the Global PIN is used by the PIV Card Application, then the above encoding, length,
    // padding, and enforcement of minimum PIN length requirements for the PIV Card Application
    // PIN shall apply to the Global PIN.

    //
    // NOTES:
    // - OpenFIPS201 permits the following PIN character sets
    //   - Default (digits 0 to 9, PIV compliant)
    //	 - Alpha Case Variant (all printable ascii characters, not PIV compliant)
    //	 - Alpha Case Invariant (all printable ascii characters, case insensitive, not PIV compliant)
    //	 - Raw (All possible values 0 to 255, same as PUK)

    byte minPermitted;
    byte maxPermitted;
    boolean invariant = false;
    boolean raw = false;

    byte charset =
        FipsPolicy.ENABLED
            ? Config.PIN_CHARSET_NUMERIC
            : config.readValue(Config.CONFIG_PIN_CHARSET);
    switch (charset) {
      case Config.PIN_CHARSET_ALPHA:
        minPermitted = ' '; // 20h
        maxPermitted = '~'; // 7Eh
        break;
      case Config.PIN_CHARSET_ALPHA_INVARIANT:
        minPermitted = ' '; // 20h
        maxPermitted = '~'; // 7Eh
        invariant = true;
        break;
      case Config.PIN_CHARSET_RAW:
        minPermitted = (byte) 0;
        maxPermitted = (byte) 0;
        raw = true;
        break;

      case Config.PIN_CHARSET_NUMERIC:
      default:
        minPermitted = '0'; // 30h
        maxPermitted = '9'; // 39h
        break;
    }

    boolean padding = false;
    for (short i = 0; i < length; i++) {
      if (padding) {
        // Once we have reached padding, all subsequent characters must be padding
        if (buffer[offset] != PIN_PADDING_BYTE) return false;
      } else {
        // Check if we have reached our padding
        if (buffer[offset] == PIN_PADDING_BYTE) {
          if (i < minLength) {
            // RULE: The minimum PIN length has not been reached
            return false;
          } else {
            padding = true;
          }
        } else {

          if (i >= maxLength) {
            return false;
          }

          // Invariant Check
          // NOTE: This converts the input buffer to all lower-case, which will then
          // ensure it matches the actual PIN value.
          if (invariant && buffer[offset] >= 'A' && buffer[offset] <= 'Z') {
            buffer[offset] |= CONST_ALPHA_CASE_DELTA;
          }

          // Range Check
          if (!raw && (buffer[offset] < minPermitted || buffer[offset] > maxPermitted)) {
            // RULE: The PIN character does not fall in the permissable range
            return false;
          }
        }
      }

      offset++;
    }

    // We got this far, passed!
    return true;
  }
}
