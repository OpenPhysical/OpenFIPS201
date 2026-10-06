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

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacardx.apdu.ExtendedLength;
import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;

/**
 * The main applet class, which is responsible for handling APDU's and dispatching them to the PIV
 * provider.
 *
 * <p>The applet also exposes INS F9 ATTEST for generated-key attestation. With P2=00 the command
 * has no request body and returns a DER X.509 certificate through the standard outgoing response
 * chaining path: the attestation certificate for slot P1, or the F9 authority certificate when
 * P1=F9. {@code 84 F9 F9 01} proves possession of the on-card F9 key over an issuer nonce.
 */
public final class OpenFIPS201 extends Applet implements AppletEvent, ExtendedLength {
  /*
   * PERSISTENT applet variables (EEPROM)
   */

  // GlobalPlatform instructions for establishing a Secure Channel
  private static final byte INS_GP_INITIALIZE_UPDATE = (byte) 0x50;
  private static final byte INS_GP_EXTERNAL_AUTHENTICATE = (byte) 0x82;
  static final byte INS_GP_GET_RESPONSE = (byte) 0xC0;
  /*
   * Applet Commands - PIV STANDARD
   */
  private static final byte INS_PIV_SELECT = (byte) 0xA4;

  /*
   * Applet Commands - Administrative
   */
  static final byte INS_PIV_GET_DATA = (byte) 0xCB;
  private static final byte INS_PIV_VERIFY = (byte) 0x20;
  static final byte INS_PIV_CHANGE_REFERENCE_DATA = (byte) 0x24;
  static final byte INS_ADMIN_UPDATE_KEY = (byte) 0x25;
  static final byte INS_PIV_RESET_RETRY_COUNTER = (byte) 0x2C;
  static final byte INS_PIV_GENERAL_AUTHENTICATE = (byte) 0x87;
  static final byte INS_PIV_PUT_DATA = (byte) 0xDB;
  private static final byte INS_PIV_GENERATE_ASYMMETRIC_KEYPAIR = (byte) 0x47;
  // Attestation command (INS F9): returns a DER X.509 certificate for an on-card generated key,
  // returns the F9 certificate (P1=F9 P2=00), or proves F9 possession (P1=F9 P2=01).
  static final byte INS_PIV_ATTEST = (byte) 0xF9;
  private static final byte P2_ATTEST_PROVE = (byte) 0x01;
  // Helper constants
  private static final short ZERO_SHORT = (short) 0;
  private static final byte SC_MASK =
      SecureChannel.AUTHENTICATED | SecureChannel.C_DECRYPTION | SecureChannel.C_MAC;
  private static final byte FIPS_STATE_PASSED = (byte) 1;
  private static final byte FIPS_STATE_FAILED = (byte) 2;
  private final PIV piv;
  private final TLVReader tlvReader;
  private final byte[] fipsState;
  // ISO 7816 transport blocks fit 256 bytes. Preserve a prefix when the final receive must
  // reuse the start of CDATA rather than the short remaining tail of the APDU array.
  static final short MAX_SHORT_APDU_RESPONSE_LENGTH = (short) 256;
  static final short MAX_SHORT_APDU_DATA_LENGTH = (short) (MAX_SHORT_APDU_RESPONSE_LENGTH - 1);
  private final byte[] receivePrefix;

  //
  // Persistent state definitions
  //

  /**
   * Allocates every object the instance uses, including the cryptographic engines and the TLV
   * codecs it shares among its handlers.
   *
   * <p>The shared services belong to this instance and no static field references them. JCRE 3.0.5
   * Section 11.3.4.2 refuses deleting an applet instance when "An object owned by the applet
   * instance is referenced from a static field on any package on the card", so instance ownership
   * keeps deletion possible without any release step in {@link #uninstall()}. JC 3.0.5 API
   * AppletEvent states "The Java Card runtime environment will not rollback state automatically if
   * applet deletion fails"; since uninstall() changes nothing, an instance whose deletion fails
   * keeps working unchanged, and a second instance of the package never shares these objects.
   */
  public OpenFIPS201() {

    // Create the shared services, then our PIV provider
    PIVCrypto crypto = new PIVCrypto();
    tlvReader = new TLVReader();
    piv = new PIV(crypto, tlvReader, new TLVWriter());
    fipsState = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
    receivePrefix =
        JCSystem.makeTransientByteArray(MAX_SHORT_APDU_RESPONSE_LENGTH, JCSystem.CLEAR_ON_DESELECT);
    ensureFipsOperational();
  }

  private void ensureFipsOperational() {
    if (!FipsPolicy.ENABLED || fipsState[0] == FIPS_STATE_PASSED) return;
    if (fipsState[0] == FIPS_STATE_FAILED) {
      ISOException.throwIt(ISO7816.SW_UNKNOWN);
    }
    fipsState[0] = FIPS_STATE_FAILED;
    if (!piv.runFipsSelfTests()) ISOException.throwIt(ISO7816.SW_UNKNOWN);
    fipsState[0] = FIPS_STATE_PASSED;
  }

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    byte aidLength = (bArray == null || bArray.length == 0) ? (byte) 0 : bArray[bOffset];
    new OpenFIPS201().register(bArray, (short) (bOffset + 1), aidLength);
  }

  @Override
  public boolean select() {
    //
    // If we are not permitted to use the applet over contactless, fail at selection.
    // This means that the rest of the applet can happily assume we are permitted.
    //
    byte media = (byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);
    boolean contactless =
        (media == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A)
            || (media == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B);

    // Update the interface. Security status survives reselection in CLEAR_ON_RESET memory, so the
    // GP secure-channel flag, which deselect() has already reset at the platform, is cleared here.
    piv.setIsContactless(contactless);
    piv.setIsSecureChannel(false);

    // Check if we are permitted to be selected over the current interface. If not, decline to be
    // selected, which means the only way to recover this is to be used over a contact interface.
    if (!piv.isInterfacePermitted()) {
      // A declined reselection leaves no PIV application selected, so its security status must
      // not survive in CLEAR_ON_RESET memory until the next selection.
      piv.deselect();
      return false;
    }
    return true;
  }

  @Override
  public void deselect() {

    // Reset any security domain session (see resetSecurity() documentation)
    SecureChannel secureChannel = GPSystem.getSecureChannel();
    secureChannel.resetSecurity();

    //
    // The PIV applet specification defines rules for how to manage security conditions when
    // it is selected or deselected. These rules/requirements are described in SP800-73-4

    // Part 2 - 3.1.1 - SELECT Card Command, and can be simplified as follows:
    // 		a.	If the PIV applet is not selected and becomes selected, the security
    //			conditions must be reset.
    //		b.	If the PIV applet is selected and becomes not selected (i.e. a different
    //			applet is selected), then the PIV applet becomes selected again, the security
    //			conditions must be reset.
    //		c.	If the PIV applet is selected and a select command is issued again for the
    //			PIV applet (i.e. it is re-selected), then the security conditions must not be
    //			reset.
    //		d.	If the PIV applet is selected and a select command is issued for a non-existent
    //			applet, then the PIV applet should remain selected and the security conditions
    //			must not be reset.

    // Reset the PIV security status only if we are not reselecting the current applet. The status
    // is held in CLEAR_ON_RESET memory because JCRE 3.0.5 Section 5.1 clears CLEAR_ON_DESELECT
    // objects even when the SELECT "Reselects the same applet".
    if (!reSelectingApplet()) {
      piv.deselect();
    }
  }

  /**
   * Prepares for deletion. Nothing is required: every object this instance allocated is referenced
   * only from the instance itself, never from a static field, so JCRE 3.0.5 Section 11.3.4.2 does
   * not block the deletion and the objects are released with the instance. Leaving the state
   * untouched also keeps the instance fully operational if the deletion then fails.
   */
  @Override
  public void uninstall() {
    // Intentionally empty: there is no static reference to release.
  }

  /**
   * Reads all incoming command data bytes into the APDU buffer.
   *
   * <p>This method is required for extended-length or segmented transports where
   * setIncomingAndReceive() may only return the first block.
   *
   * @param apdu The current APDU
   * @return The fully assembled incoming command data length (Nc)
   */
  private short receiveAllIncomingData(APDU apdu) {
    short received = apdu.setIncomingAndReceive();
    short offset = apdu.getOffsetCdata();
    short totalLength = apdu.getIncomingLength();
    byte[] buffer = apdu.getBuffer();

    // We require contiguous CDATA in the APDU buffer because downstream handlers parse in-place.
    if (received < ZERO_SHORT
        || received > totalLength
        || totalLength > (short) (buffer.length - offset)) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    short writeOffset = (short) (offset + received);

    while (received < totalLength) {
      short inputBlockSize = APDU.getInBlockSize();
      short block;
      if ((short) (buffer.length - writeOffset) < inputBlockSize) {
        // Java Card 3.0.5 APDU.receiveBytes requires room for a full input block even when
        // fewer command bytes remain. Receive at CDATA, relocate the block, then restore it.
        if (inputBlockSize > (short) receivePrefix.length
            || inputBlockSize > (short) (buffer.length - offset)) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short saved = received < inputBlockSize ? received : inputBlockSize;
        Util.arrayCopyNonAtomic(buffer, offset, receivePrefix, ZERO_SHORT, saved);
        try {
          block = receiveBlock(apdu, offset, (short) (totalLength - received));
          Util.arrayCopyNonAtomic(buffer, offset, buffer, writeOffset, block);
          Util.arrayCopyNonAtomic(receivePrefix, ZERO_SHORT, buffer, offset, saved);
        } finally {
          PIVSecurityProvider.zeroise(receivePrefix, ZERO_SHORT, saved);
        }
      } else {
        block = receiveBlock(apdu, writeOffset, (short) (totalLength - received));
      }
      received += block;
      writeOffset += block;
    }

    return received;
  }

  private static short receiveBlock(APDU apdu, short offset, short remaining) {
    short length = apdu.receiveBytes(offset);
    if (length <= ZERO_SHORT || length > remaining) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    return length;
  }

  @Override
  public void process(APDU apdu) {

    ensureFipsOperational();

    //
    // Handle incoming APDUs
    //

    final byte[] buffer = apdu.getBuffer();

    if (selectingApplet()) {
      piv.abortOutgoingResponse();
      piv.abortAuthenticationExchange();
      processPIV_SELECT(apdu);
      return;
    }

    // ISO/IEC 7816-4 response chaining is abandoned by any intervening command. Do this before
    // unwrapping a new protected command, because unwrapping replaces the secure-messaging command
    // context needed to finish the abandoned logical exchange correctly.
    if (buffer[ISO7816.OFFSET_INS] != INS_GP_GET_RESPONSE) {
      piv.abortOutgoingResponse();
    }

    validateCommandClass(apdu, buffer);
    rejectUnsupportedCommandChaining(buffer);

    boolean pivSecureMessagingCla = piv.isSecureMessagingCLA(buffer[ISO7816.OFFSET_CLA]);
    boolean gpSecureMessagingCla = apdu.isSecureMessagingCLA();
    boolean plaintextGetResponse =
        buffer[ISO7816.OFFSET_INS] == INS_GP_GET_RESPONSE
            && !pivSecureMessagingCla
            && !gpSecureMessagingCla;

    // SPECIAL CASE 1 - plaintext GET RESPONSE
    // We handle plaintext GET RESPONSE before incoming-data processing because it carries no
    // command data. A GP SCP-protected GET RESPONSE must not take this shortcut: the platform
    // secure-channel layer has to unwrap it so the host and card SCP state stay synchronized.
    if (plaintextGetResponse) {
      // The secure-channel flag describes the current command; this one is not SCP-protected.
      piv.setIsSecureChannel(false);
      piv.clearSecureMessagingCommand();
      if (piv.isSecureMessagingResponseActive()) {
        piv.processOutgoingSecureContinuation(apdu);
        return;
      }
      piv.processOutgoing(apdu);
      return;
    }
    //
    // We can now safely call setIncomingAndReceive because all other expected commands are
    // either CASE 3 or 4 (command data present). The ATTEST certificate form is case 2 and never
    // receives command data over T=0.
    //
    boolean receivesCommandData = true;
    // #if ATTESTATION_ENABLED
    receivesCommandData = !isCase2AttestOverT0(buffer);
    // #endif
    short length = receivesCommandData ? receiveAllIncomingData(apdu) : ZERO_SHORT;
    short offset = receivesCommandData ? apdu.getOffsetCdata() : ISO7816.OFFSET_CDATA;

    //
    // Process GlobalPlatform Secure Channel unwrapping if relevant to this command
    // NOTE:
    // We only consider the channel to be secure if ALL these conditions are true:
    // 1) We have a previously established secure channel
    // 2) The applet has not been deselected
    // 3) The current command indicates it is transmitting a SCP protected command
    // 4) The command unwrap method successfully completed

    // Default to no secure channel until the APDU unwrap confirms one.
    piv.setIsSecureChannel(false);
    piv.clearSecureMessagingCommand();

    if (pivSecureMessagingCla) {
      length = piv.unwrapSecureMessagingCommand(buffer, offset, length);
    } else if (!gpSecureMessagingCla && isPlaintextOpacityEstablishment(buffer, offset, length)) {
      // SP 800-73-5 Part 2 Section 4.3 requires destruction on receipt of a new
      // establishment request, even when later key lookup or establishment fails.
      piv.clearSecureMessaging();
    } else if (piv.isSecureMessagingEstablished() && !gpSecureMessagingCla) {
      // SP 800-73-5 Part 2 Section 4.2: after key establishment "subsequent communication with the
      // card CAN be performed using secure messaging"; SM-AUTH (Appendix A.6.1) continues in
      // plaintext. A plaintext command is processed under the plaintext access rules: VCI is
      // satisfied only by a protected command (PIV.isVciSatisfied()). Section 4.3 lists the only
      // session-key destruction triggers, so the session is kept. ISO/IEC 7816-4 command chaining
      // abandons an incomplete protected command when a different command arrives.
      piv.abandonSecureMessagingCommandStream();
    } else if (gpSecureMessagingCla) {
      SecureChannel secureChannel = GPSystem.getSecureChannel();
      if ((secureChannel.getSecurityLevel() & SC_MASK) == SC_MASK) {
        // Validate and unwrap the APDU, including the header bytes
        length += offset; // Add the header length
        length = secureChannel.unwrap(buffer, (short) 0, length);
        length -= offset; // Remove the header length
        piv.setIsSecureChannel(true);
      }
    }

    byte[] commandDataBuffer = buffer;
    short commandDataOffset = offset;
    if (piv.isSecureMessagingCommand()
        && (short) (commandDataOffset + length) > (short) buffer.length) {
      commandDataBuffer = piv.getSecureMessagingCommandBuffer();
      commandDataOffset = (short) 5;
    }

    //
    // Normal APDU processing
    //
    try {
      //
      // Process any outstanding chain requests
      //
      // NOTES:
      // - If there is an outstanding chain request to process, this method will throw an
      // ISOException
      //   (including SW_NO_ERROR) and no further processing will occur.
      // - It is important that this command is handled before any GP SCP authentication is called
      // to
      //   prevent a downgrade attack where the attacker waits for a sensitive large-command to be
      //   executed and then intercepts the session and cancels the secure channel (thus removing
      //   session encryption).
      // - ChainBuffer binds all frames to the protection used by the first frame, so an SCP or PIV
      //   secure-messaging write cannot be completed after a channel downgrade.
      //
      // We pass the byte array, offset and length here because the previous call to unwrap() may
      // have altered the length.
      piv.processIncomingObject(commandDataBuffer, commandDataOffset, length);

      // A multi-step GENERAL AUTHENTICATE exchange is bound to consecutive authentication APDUs.
      // GET RESPONSE may finish carrying a large GA response, but every other command abandons the
      // pending challenge before that command executes.
      if (buffer[ISO7816.OFFSET_INS] != INS_PIV_GENERAL_AUTHENTICATE
          && buffer[ISO7816.OFFSET_INS] != INS_GP_GET_RESPONSE) {
        piv.abortAuthenticationExchange();
      }

      // PIV secure messaging is handled as a transport wrapper here. Command-specific access
      // checks below still decide whether the unwrapped command is allowed in the current profile
      // and interface state.
      switch (buffer[ISO7816.OFFSET_INS]) {
        case INS_GP_INITIALIZE_UPDATE: // Case 4
          processGP_SECURECHANNEL(apdu);
          break;

        case INS_GP_EXTERNAL_AUTHENTICATE: // Case 4
          processGP_SECURECHANNEL(apdu);
          break;

        case INS_GP_GET_RESPONSE:
          piv.processOutgoing(apdu);
          return;

          // Application Commands
        case INS_PIV_SELECT: // Case 4
          processPIV_SELECT(apdu);
          break;

        case INS_PIV_GET_DATA: // Case 4
          processPIV_GET_DATA(apdu, commandDataBuffer, commandDataOffset, length);
          break;

        case INS_PIV_VERIFY: // Case 2
          processPIV_VERIFY(apdu, commandDataBuffer, commandDataOffset, length);
          break;

        case INS_PIV_CHANGE_REFERENCE_DATA: // Case 2
          processPIV_CHANGE_REFERENCE_DATA(apdu, commandDataBuffer, commandDataOffset, length);
          break;

        case INS_ADMIN_UPDATE_KEY:
          processADMIN_UPDATE_KEY(apdu, commandDataBuffer, commandDataOffset, length);
          break;

        case INS_PIV_RESET_RETRY_COUNTER: // Case 2
          processPIV_RESET_RETRY_COUNTER(apdu, commandDataBuffer, commandDataOffset, length);
          break;

        case INS_PIV_GENERAL_AUTHENTICATE: // Case 4
          // SP 800-73-5 Part 2 Section 4.1.8 requires plaintext CLA 00 for OPACITY.
          // Reject a verified wrapped request under the existing keys before it can replace them.
          if (piv.isSecureMessagingCommand()
              && buffer[ISO7816.OFFSET_P2] == PIV.ID_KEY_SECURE_MESSAGING) {
            // A failed GENERAL AUTHENTICATE also abandons any pending challenge or witness.
            piv.abortAuthenticationExchange();
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
          }
          processPIV_GENERAL_AUTHENTICATE(apdu, commandDataBuffer, commandDataOffset, length);
          break;

        case INS_PIV_PUT_DATA: // Case 2
          processPIV_PUT_DATA(apdu, commandDataBuffer, commandDataOffset, length);
          break;

        case INS_PIV_GENERATE_ASYMMETRIC_KEYPAIR: // Case 2
          processPIV_GENERATE_ASYMMETRIC_KEYPAIR(
              apdu, commandDataBuffer, commandDataOffset, length);
          break;

          // #if ATTESTATION_ENABLED
        case INS_PIV_ATTEST:
          processPIV_ATTEST(apdu, commandDataBuffer, commandDataOffset, length);
          break;
          // #endif

        default:
          ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
      }

      if (piv.isSecureMessagingCommand()) {
        piv.processOutgoing(apdu);
      }
    } catch (ISOException ex) {
      short reason = ex.getReason();
      if (!piv.isSecureMessagingCommand()
          || (short) (reason & (short) 0xFF00) == ISO7816.SW_BYTES_REMAINING_00) {
        throw ex;
      }
      // An error status produced by command processing inside a verified secure messaging
      // exchange is an application status, not a secure messaging error. SP 800-73-5 Part 2
      // Section 4.2.6 requires it to be returned encapsulated in the '99' status template of a
      // wrapped response, and the SW processing status of that exchange (Section 4.2.7) is
      // '90 00' because the secure messaging itself was performed successfully. Session key
      // destruction (Section 4.3) applies only when the SW processing status is other than
      // '61 XX' or '90 00' - that is, to the secure messaging error statuses of Section 4.2.7,
      // which are returned without wrapping - so the session keys are retained here and the
      // session continues. Secure messaging processing errors are zeroized at the point they
      // are detected, in PIVSecureMessaging.unwrapCommand().
      piv.processOutgoing(apdu, ex.getReason());
    } catch (RuntimeException ex) {
      // A runtime fault inside a protected exchange returns a status other than '61 XX' or
      // '90 00', which is an error in secure messaging; SP 800-73-5 Part 2 Section 4.3 then
      // requires the session keys to be zeroized.
      if (piv.isSecureMessagingCommand()) piv.clearSecureMessaging();
      throw ex;
    }
  }

  private void validateCommandClass(APDU apdu, byte[] buffer) {
    byte cla = buffer[ISO7816.OFFSET_CLA];
    byte ins = buffer[ISO7816.OFFSET_INS];

    if (ins == INS_GP_INITIALIZE_UPDATE || ins == INS_GP_EXTERNAL_AUTHENTICATE) {
      byte expected = ins == INS_GP_INITIALIZE_UPDATE ? (byte) 0x80 : (byte) 0x84;
      if (cla != expected) {
        // A command sent with secure messaging that fails with a status other than '61 XX' or
        // '90 00' is an error in secure messaging (SP 800-73-5 Part 2 Section 4.3, footnote 25),
        // after which the host zeroizes its session keys; the card does the same.
        if (piv.isSecureMessagingCLA(cla)) piv.clearSecureMessaging();
        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
      }
      return;
    }

    if (piv.isSecureMessagingCLA(cla)) {
      if (!piv.isSecureMessagingEstablished()) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }
      return;
    }

    // GlobalPlatform may protect an interindustry PIV command by setting the ISO secure-messaging
    // bit on its original class (00 -> 04). Accept that form only when the runtime identifies the
    // APDU as GP secure messaging; plaintext CLA 04 remains unsupported.
    if ((byte) (cla & (byte) 0xEF) == (byte) 0x04 && apdu.isSecureMessagingCLA()) {
      SecureChannel secureChannel = GPSystem.getSecureChannel();
      if (secureChannel != null && (secureChannel.getSecurityLevel() & SC_MASK) == SC_MASK) {
        return;
      }
    }

    // PIV uses the interindustry class. Administrative commands use the proprietary class 80, or
    // 84 when protected by GP SCP. Any of those classes may carry command chaining.
    byte baseCla = (byte) (cla & (byte) 0xEF);
    if (baseCla == (byte) 0x80) {
      if (!isAdministrativeInstruction(ins)) {
        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
      }
      return;
    }
    if (baseCla == (byte) 0x84) {
      SecureChannel secureChannel = GPSystem.getSecureChannel();
      if (!isAdministrativeInstruction(ins)
          || secureChannel == null
          || (secureChannel.getSecurityLevel() & SC_MASK) != SC_MASK) {
        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
      }
      return;
    }
    if (baseCla != (byte) 0x00) {
      ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }
  }

  /**
   * Rejects a command that announces more data to follow when its instruction does not support
   * command chaining, before any part of it executes.
   *
   * <p>ISO/IEC 7816-4 Section 5.3.3: "If bit b5 is set to 1, then the command is not the last
   * command of a chain." and "If SW1-SW2 is set to '6884', then command chaining is not supported."
   * SP 800-73-5 Part 2 Table 2 lists command chaining for GENERAL AUTHENTICATE, PUT DATA and
   * GENERATE ASYMMETRIC KEY PAIR, and for VERIFY and CHANGE REFERENCE DATA "only if the PIV Card
   * Application supports OCC", which this applet does not. The proprietary key and reference-data
   * updates chain as well. PIV secure messaging reassembles its chained transport frames before the
   * protected command is processed, so its class is exempt here.
   */
  private void rejectUnsupportedCommandChaining(byte[] buffer) {
    byte cla = buffer[ISO7816.OFFSET_CLA];
    if ((cla & ChainBuffer.CLA_CHAINING) == (byte) 0 || piv.isSecureMessagingCLA(cla)) return;
    switch (buffer[ISO7816.OFFSET_INS]) {
      case INS_PIV_GENERAL_AUTHENTICATE:
      case INS_PIV_PUT_DATA:
      case INS_PIV_GENERATE_ASYMMETRIC_KEYPAIR:
      case INS_ADMIN_UPDATE_KEY:
        return;
      case INS_PIV_CHANGE_REFERENCE_DATA:
        if ((cla & (byte) 0x80) != (byte) 0) return;
        break;
      default:
        break;
    }
    piv.abandonChains();
    ISOException.throwIt(ISO7816.SW_COMMAND_CHAINING_NOT_SUPPORTED);
  }

  private static boolean isAdministrativeInstruction(byte ins) {
    return ins == INS_GP_GET_RESPONSE
        || ins == INS_PIV_GET_DATA
        || ins == INS_PIV_PUT_DATA
        || ins == INS_PIV_CHANGE_REFERENCE_DATA
        || ins == INS_ADMIN_UPDATE_KEY
        || ins == INS_PIV_GENERATE_ASYMMETRIC_KEYPAIR
        // #if ATTESTATION_ENABLED
        || ins == INS_PIV_ATTEST
    // #endif
    ;
  }

  private static boolean isPlainProprietaryClass(byte cla) {
    return (byte) (cla & (byte) 0xEF) == (byte) 0x80;
  }

  private boolean isPlaintextOpacityEstablishment(byte[] buffer, short offset, short length) {
    if (buffer[ISO7816.OFFSET_CLA] != (byte) 0
        || buffer[ISO7816.OFFSET_INS] != INS_PIV_GENERAL_AUTHENTICATE
        || buffer[ISO7816.OFFSET_P1] != PIV.ID_ALG_ECC_SM
        || buffer[ISO7816.OFFSET_P2] != PIV.ID_KEY_SECURE_MESSAGING) {
      return false;
    }

    // SP 800-73-5 Part 2 Section 4.1 reserves key 04 for OPACITY. Only its Case 1A
    // request may bypass an existing PIV secure-messaging session.
    try {
      return hasOpacityCase1aTemplate(buffer, offset, length);
    } catch (ISOException malformedTemplate) {
      return false;
    }
  }

  private boolean hasOpacityCase1aTemplate(byte[] buffer, short offset, short length) {
    TLVReader reader = tlvReader;
    reader.init(buffer, offset, length);
    if (!reader.match(PIV.CONST_TAG_AUTH_TEMPLATE) || !reader.moveInto()) return false;
    if (!reader.match(PIV.CONST_TAG_AUTH_CHALLENGE) || reader.isNull() || !reader.moveNext()) {
      return false;
    }
    return reader.match(PIV.CONST_TAG_AUTH_CHALLENGE_RESPONSE)
        && reader.isNull()
        && !reader.moveNext();
  }

  /**
   * Processes the GlobalPlatform Secure Channel Protocol (SCP) authentication mechanisms
   *
   * @param apdu The APDU to process.
   */
  private void processGP_SECURECHANNEL(APDU apdu) {

    /*
     * PRE-CONDITIONS
     */

    // PRE-CONDITION 1 - The secure channel is a card management session, so card management must
    // be permitted on the current interface
    piv.requireAdministrativeInterface(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

    /*
     * EXECUTION STEPS
     */

    SecureChannel secureChannel = GPSystem.getSecureChannel();

    // STEP 1 - Call the GlobalPlatform secure-channel command handler. INITIALIZE UPDATE starts a
    // new SCP session; the platform implementation owns any required session reset.
    short length = secureChannel.processSecurity(apdu);
    short offset = apdu.getOffsetCdata();

    // STEP 2 - GP SCP03 v1.1.2 Section 5.5 sets R_MAC or R_ENCRYPTION "after successful processing
    // of an EXTERNAL AUTHENTICATE command with P1 indicating R-MAC (P1='1x' or '3x')". This applet
    // protects commands only and never wraps responses, so it refuses a session at a security level
    // it would not honour rather than return unprotected responses under it.
    if ((secureChannel.getSecurityLevel() & (SecureChannel.R_MAC | SecureChannel.R_ENCRYPTION))
        != (byte) 0) {
      secureChannel.resetSecurity();
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // Send the response
    apdu.setOutgoingAndSend(offset, length);
  }

  /**
   * Process the PIV 'SELECT' command
   *
   * @param apdu The incoming APDU object
   */
  private void processPIV_SELECT(APDU apdu) {

    /*
     * PRE-CONDITIONS
     */

    // PRE-CONDITION 1 - This must be called only when the applet is selected or re-selected
    if (!selectingApplet()) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    /*
     * EXECUTION STEPS
     */

    // STEP 1 - Call the PIV 'SELECT' command in all cases to handle the PIV SELECT rules
    piv.select();

    // STEP 2 - Return the APT through the response chain: an Ne shorter than the APT yields
    // '61 XX' and GET RESPONSE rather than a truncated template with '90 00'.
    piv.processOutgoing(apdu);
  }

  /**
   * Process the PIV 'GET DATA' command
   *
   * @param apdu The incoming APDU object
   * @param commandData buffer holding the command data after any secure-messaging unwrap
   * @param commandDataOffset first command-data octet
   * @param length The incoming APDU command-data length
   */
  private void processPIV_GET_DATA(
      APDU apdu, byte[] commandData, short commandDataOffset, short length) {

    final byte P1 = (byte) 0x3F;
    final byte P2 = (byte) 0xFF;

    byte[] buffer = apdu.getBuffer();
    boolean proprietary =
        isPlainProprietaryClass(buffer[ISO7816.OFFSET_CLA])
            || (buffer[ISO7816.OFFSET_CLA] & (byte) 0xEF) == (byte) 0x84
                && buffer[ISO7816.OFFSET_P1] == (byte) 0xFF
                && buffer[ISO7816.OFFSET_P2] == (byte) 0xFF;

    if (proprietary) {
      if (buffer[ISO7816.OFFSET_P1] != (byte) 0xFF || buffer[ISO7816.OFFSET_P2] != (byte) 0xFF) {
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      }
      piv.getDataExtended(commandData, commandDataOffset, length);
      piv.processOutgoing(apdu);
      return;
    }

    /*
     * PRE-CONDITIONS
     */

    // PRE-CONDITION 1 - The P1 value must be equal to the constant '3F'
    if (buffer[ISO7816.OFFSET_P1] != P1) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    // SP 800-73-5 Part 2, Section 3.1.2 command syntax: "P1 '3F'; P2 'FF'."
    // Administrative queries use the proprietary FF/FF form handled above.
    if (buffer[ISO7816.OFFSET_P2] != P2) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    /*
     * EXECUTION STEPS
     */

    // STEP 1 - Call the PIV 'GET DATA' command
    piv.getData(commandData, commandDataOffset, length);

    // NOTE: If no exception occurred during processing, the ChainBuffer now contains a reference
    //		 to a data object to write to the client.

    // STEP 2 - Process the first frame of the chainBuffer for this response
    piv.processOutgoing(apdu);
  }

  /**
   * Processes the PIV 'PUT DATA' command
   *
   * @param apdu The incoming APDU object
   * @param length The incoming APDU command-data length
   */
  private void processPIV_PUT_DATA(
      APDU apdu, byte[] commandDataBuffer, short commandDataOffset, short length) {

    final byte CONST_P1 = (byte) 0x3F;
    final byte CONST_P2 = (byte) 0xFF;

    byte[] buffer = apdu.getBuffer();
    // SP 800-73-5 Part 2, Table 2 marks PUT DATA "No" for the contactless interface, which takes
    // '6A 81'. Issuer-enabled contactless card management is the stated exception. This is the
    // interface rule for both the interindustry and the proprietary forms.
    piv.requireAdministrativeInterface(ISO7816.SW_FUNC_NOT_SUPPORTED);

    boolean proprietary =
        isPlainProprietaryClass(buffer[ISO7816.OFFSET_CLA])
            || (buffer[ISO7816.OFFSET_CLA] & (byte) 0xEF) == (byte) 0x84
                && buffer[ISO7816.OFFSET_P1] == (byte) 0xFF
                && buffer[ISO7816.OFFSET_P2] == (byte) 0xFF;

    if (proprietary) {
      if (buffer[ISO7816.OFFSET_P1] != (byte) 0xFF || buffer[ISO7816.OFFSET_P2] != (byte) 0xFF) {
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      }
      piv.putDataAdmin(commandDataBuffer, commandDataOffset, length);
      return;
    }

    /*
     * PRE-CONDITIONS
     */

    // PRE-CONDITION 1 - The P1 value must be equal to the constant CONST_P1
    if (buffer[ISO7816.OFFSET_P1] != CONST_P1) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    // SP 800-73-5 Part 2, Section 3.3.1 command syntax: "P1 '3F'; P2 'FF'."
    // Structural and configuration changes use the proprietary FF/FF form handled above.
    if (buffer[ISO7816.OFFSET_P2] != CONST_P2) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    /*
     * EXECUTION STEPS
     */

    // STEP 1 - Call the applicable PIV 'PUT DATA' command
    piv.putData(commandDataBuffer, commandDataOffset, length);
  }

  /**
   * Process the PIV 'VERIFY' command
   *
   * @param apdu The incoming APDU object
   * @param commandData buffer holding the command data after any secure-messaging unwrap
   * @param commandDataOffset first command-data octet
   * @param length The incoming APDU command-data length
   */
  private void processPIV_VERIFY(
      APDU apdu, byte[] commandData, short commandDataOffset, short length) {

    final byte CONST_P1_AUTH = (byte) 0x00;
    final byte CONST_P1_RESET = (byte) 0xFF;

    byte[] buffer = apdu.getBuffer();

    /*
     * PRE-CONDITIONS
     */

    // PRE-CONDITION 1 - The P1 value must be equal to the constant CONST_P1_AUTH or CONST_P1_RESET
    // PRE-CONDITION 2 - If the P1 value is set to CONST_P1_RESET, the data field must be absent
    // NOTE: This is handled by the cases below

    // PRE-CONDITION 3 - If the P1 value is set to CONST_P1_AUTH and the data field is present, the
    //					 length must be equal to CONST_LC
    // NOTE: This is handled inside the PIVProvider

    /*
     * EXECUTION STEPS
     */

    // STEP 1 - Call the appropriate PIV 'Verify' command

    // CASE 1 - If P1='00', and Lc and the command data field are absent, the command can be
    // 			used to retrieve the number of further retries allowed ('63 CX'), or to check whether
    // 			verification is not needed ('90 00').
    if (buffer[ISO7816.OFFSET_P1] == CONST_P1_AUTH && length == ZERO_SHORT) {
      // Retrieve the authentication status using the key reference supplied in P2
      piv.verifyGetStatus(buffer[ISO7816.OFFSET_P2]);
      return;
    }

    // CASE 2 - If P1='FF', and Lc and the command data field are absent, the command shall reset
    // 			the security status of the key reference in P2.
    if (buffer[ISO7816.OFFSET_P1] == CONST_P1_RESET && length == ZERO_SHORT) {
      // Reset the authentication status using the key reference supplied in P2
      piv.verifyResetStatus(buffer[ISO7816.OFFSET_P2]);
      return;
    }

    // CASE 3 - If P1='00', and Lc and the command data field are present, then the authentication
    //          data in the command data field shall be compared against the reference data
    //          associated with the key reference [...]
    if (buffer[ISO7816.OFFSET_P1] == CONST_P1_AUTH && length != ZERO_SHORT) {
      // Verify using the key reference supplied in P2
      piv.verify(buffer[ISO7816.OFFSET_P2], commandData, commandDataOffset, length);
      return;
    }

    // If we reached here, then none of the cases applied
    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
  }

  /**
   * Process the PIV 'CHANGE REFERENCE DATA' command
   *
   * @param apdu The incoming APDU object
   * @param commandData buffer holding the command data after any secure-messaging unwrap
   * @param commandDataOffset first command-data octet
   * @param length The incoming APDU command-data length
   */
  private void processPIV_CHANGE_REFERENCE_DATA(
      APDU apdu, byte[] commandData, short commandDataOffset, short length) {

    final byte CONST_P1 = (byte) 0x00;

    byte[] buffer = apdu.getBuffer();

    boolean proprietaryPinUpdate =
        (isPlainProprietaryClass(buffer[ISO7816.OFFSET_CLA])
                || (buffer[ISO7816.OFFSET_CLA] & (byte) 0xEF) == (byte) 0x84)
            && buffer[ISO7816.OFFSET_P1] == (byte) 0x01;
    if (proprietaryPinUpdate) {
      if (buffer[ISO7816.OFFSET_P1] != (byte) 0x01
          || (buffer[ISO7816.OFFSET_P2] != PIV.ID_CVM_LOCAL_PIN
              && buffer[ISO7816.OFFSET_P2] != PIV.ID_CVM_PUK)) {
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      }
      piv.changeReferenceDataAdmin(
          buffer[ISO7816.OFFSET_P2], commandData, commandDataOffset, length);
      return;
    }

    // A protected issuer key import uses the algorithm in P1 and a non-CVM key reference in P2.
    // Keep this SCP-only form separate from the SP 800-73-5 CHANGE REFERENCE DATA syntax below.
    boolean protectedKeyUpdate =
        (buffer[ISO7816.OFFSET_CLA] & (byte) 0xEF) == (byte) 0x84
            && buffer[ISO7816.OFFSET_P2] != PIV.ID_CVM_GLOBAL_PIN
            && buffer[ISO7816.OFFSET_P2] != PIV.ID_CVM_LOCAL_PIN
            && buffer[ISO7816.OFFSET_P2] != PIV.ID_CVM_PUK;
    if (protectedKeyUpdate) {
      piv.changeReferenceDataAdmin(
          buffer[ISO7816.OFFSET_P2], commandData, commandDataOffset, length);
      return;
    }

    /*
     * PRE-CONDITIONS
     */

    // SP 800-73-5 Part 2, Section 3.2.2 command syntax: "P1 '00'."
    // Issuer replacement uses the proprietary P1=01 form handled above.
    if (buffer[ISO7816.OFFSET_P1] != CONST_P1) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    // The command syntax permits only the Global PIN, PIV Card Application PIN, and PUK.
    if (buffer[ISO7816.OFFSET_P2] != PIV.ID_CVM_GLOBAL_PIN
        && buffer[ISO7816.OFFSET_P2] != PIV.ID_CVM_LOCAL_PIN
        && buffer[ISO7816.OFFSET_P2] != PIV.ID_CVM_PUK) {
      ISOException.throwIt(PIV.SW_REFERENCE_NOT_FOUND);
    }

    /*
     * EXECUTION STEPS
     */

    // STEP 1 - Change the selected standard reference data.
    piv.changeReferenceData(buffer[ISO7816.OFFSET_P2], commandData, commandDataOffset, length);
  }

  /**
   * Replaces an issuer-managed key value through the proprietary administrative command.
   *
   * @param apdu incoming APDU
   * @param commandData buffer holding the command data after any secure-messaging unwrap
   * @param commandDataOffset first command-data octet
   * @param length command-data length
   */
  private void processADMIN_UPDATE_KEY(
      APDU apdu, byte[] commandData, short commandDataOffset, short length) {
    byte[] buffer = apdu.getBuffer();
    if (buffer[ISO7816.OFFSET_P1] != (byte) 0x01) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    // The administrative interface rule is enforced inside changeReferenceDataAdmin.
    piv.changeReferenceDataAdmin(buffer[ISO7816.OFFSET_P2], commandData, commandDataOffset, length);
  }

  /**
   * Process the PIV 'RESET RETRY COUNTER' command
   *
   * @param apdu The incoming APDU object
   * @param commandData buffer holding the command data after any secure-messaging unwrap
   * @param commandDataOffset first command-data octet
   * @param length The incoming APDU command-data length
   */
  private void processPIV_RESET_RETRY_COUNTER(
      APDU apdu, byte[] commandData, short commandDataOffset, short length) {

    final byte CONST_P1 = (byte) 0x00;
    final byte CONST_LC = (byte) 0x10;

    byte[] buffer = apdu.getBuffer();

    /*
     * PRE-CONDITIONS
     */

    // PRE-CONDITION 1 - The P1 value must be equal to the constant CONST_P1
    if (buffer[ISO7816.OFFSET_P1] != CONST_P1) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    // PRE-CONDITION 2 - The LC (length) value must be equal to the constant CONST_LC
    if (length != CONST_LC) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    /*
     * EXECUTION STEPS
     */

    piv.resetRetryCounter(buffer[ISO7816.OFFSET_P2], commandData, commandDataOffset, length);
  }

  /**
   * Process the PIV 'GENERAL AUTHENTICATE' command
   *
   * @param apdu The incoming APDU object
   * @param length The incoming APDU command-data length
   */
  private void processPIV_GENERAL_AUTHENTICATE(
      APDU apdu, byte[] commandData, short commandDataOffset, short length) {

    /*
     * PRE-CONDITIONS
     */

    // NONE

    /*
     * EXECUTION STEPS
     */

    // STEP 1 - Call the PIV GENERAL AUTHENTICATE method
    length = piv.generalAuthenticate(commandData, commandDataOffset, length);

    // STEP 2 - Process the first frame of the chainBuffer for this response, if any
    if (length > 0) piv.processOutgoing(apdu);
  }

  /**
   * Process the PIV 'GENERATE ASYMMETRIC KEYPAIR' command
   *
   * @param apdu The incoming APDU object
   * @param commandData buffer holding the command data after any secure-messaging unwrap
   * @param commandDataOffset first command-data octet
   * @param length The incoming APDU command-data length
   */
  private void processPIV_GENERATE_ASYMMETRIC_KEYPAIR(
      APDU apdu, byte[] commandData, short commandDataOffset, short length) {

    final byte CONST_P1 = (byte) 0x00;

    byte[] buffer = apdu.getBuffer();

    // SP 800-73-5 Part 2 Section 3, Table 2: "The PIV Card Application shall return the status
    // word of '6A 81' (Function not supported) when it receives a card command on the contactless
    // interface marked "No" in the Contactless Interface column in Table 2", unless "the card
    // command can be performed over the contactless interface in support of card management".
    // Contactless card management is an issuer opt-in that the FIPS profile never allows. Under
    // that opt-in GENERATE proceeds to its administrative access check.
    if (FipsPolicy.ENABLED && piv.isContactless()) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }
    piv.requireAdministrativeInterface(ISO7816.SW_FUNC_NOT_SUPPORTED);

    // SP 800-73-5 Part 2 Section 3.3.2 limits the interindustry command to these key
    // references. Proprietary administration may generate extension slots such as retired keys.
    byte baseCla = (byte) (buffer[ISO7816.OFFSET_CLA] & (byte) 0xEF);
    if ((baseCla == (byte) 0x00 || baseCla == (byte) 0x0C)
        && !isGenerateKeyReference(buffer[ISO7816.OFFSET_P2])) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    /*
     * PRE-CONDITIONS
     */

    // PRE-CONDITION 1 - The P1 value must be equal to the constant CONST_P1
    if (buffer[ISO7816.OFFSET_P1] != CONST_P1) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    /*
     * EXECUTION STEPS
     */

    // STEP 1 - Call the PIV GENERATE ASYMMETRIC KEY command
    length = piv.generateAsymmetricKeyPair(commandData, commandDataOffset, length);

    // STEP 2 - Process the first frame of the chainBuffer for this response
    if (length > 0) piv.processOutgoing(apdu);
  }

  private static boolean isGenerateKeyReference(byte keyReference) {
    return keyReference == PIV.ID_KEY_SECURE_MESSAGING || PIV.isStandardAsymmetricKey(keyReference);
  }

  // #if ATTESTATION_ENABLED
  /**
   * Processes INS F9.
   *
   * <ul>
   *   <li>{@code P1=F9 P2=01}: PROVE, signs the F9 proof-of-possession message over the nonce in
   *       the command data.
   *   <li>{@code P1=F9 P2=00}: returns the stored F9 certificate.
   *   <li>{@code P1=<slot> P2=00}: returns an attestation certificate for the slot.
   * </ul>
   *
   * @param apdu the incoming APDU
   * @param commandData buffer holding the command data
   * @param offset first command-data octet
   * @param length command-data length after any secure-channel unwrap
   */
  private void processPIV_ATTEST(APDU apdu, byte[] commandData, short offset, short length) {
    byte[] buffer = apdu.getBuffer();
    byte p1 = buffer[ISO7816.OFFSET_P1];
    byte p2 = buffer[ISO7816.OFFSET_P2];

    if (p1 == PIV.ID_KEY_ATTESTATION && p2 == P2_ATTEST_PROVE) {
      piv.proveAttestationAuthority(commandData, offset, length);
      piv.processOutgoing(apdu);
      return;
    }

    if (p2 != (byte) 0x00) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    // The certificate forms are no-body commands. Reject unexpected command data after any SCP
    // unwrap instead of silently ignoring it.
    if (length != ZERO_SHORT) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    if (p1 == PIV.ID_KEY_ATTESTATION) {
      piv.getAttestationAuthorityCertificate();
    } else {
      piv.attest(p1);
    }
    piv.processOutgoing(apdu);
  }

  /**
   * Returns whether the command is the plain interindustry ATTEST certificate form over T=0.
   *
   * <p>JC 3.0.5 {@code APDU.setIncomingAndReceive()}: &quot;This method should only be called on a
   * case 3 or case 4 command&quot; and &quot;In T=0 ( Case 3&amp;4 ) protocol, the P3 param is
   * assumed to be Lc.&quot; {@code 00 F9 <ref> 00 [Le]} is case 2, so over T=0 its P3 is Le and no
   * command data is received.
   */
  private static boolean isCase2AttestOverT0(byte[] buffer) {
    return buffer[ISO7816.OFFSET_INS] == INS_PIV_ATTEST
        && buffer[ISO7816.OFFSET_CLA] == (byte) 0x00
        && buffer[ISO7816.OFFSET_P2] == (byte) 0x00
        && (byte) (APDU.getProtocol() & APDU.PROTOCOL_TYPE_MASK) == APDU.PROTOCOL_T0;
  }
  // #endif
}
