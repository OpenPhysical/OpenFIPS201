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
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Implements the PIV card application for FIPS 201-2 and FIPS 201-3 deployments using the NIST SP
 * 800-73-4 and SP 800-73-5 interfaces.
 *
 * <p>The applet targets Java Card 3.0.5 and provides configurable data and key stores, RSA and
 * elliptic-curve mechanisms, virtual contact interface support, OPACITY secure messaging, optional
 * key attestation, and administration through either GlobalPlatform SCP or the PIV management key.
 *
 * <p>Biometric on-card comparison (OCC) is outside this implementation's scope.
 */
final class PIV {

  //
  // The most important constant of all
  //
  static final byte ZERO = (byte) 0;
  // GlobalPlatform Table 11-4 reserves 0x0F as an application-specific lifecycle value.
  static final byte APP_STATE_PERSONALIZED = (byte) 0x0F;

  //
  // Persistent Objects
  //

  // Transient buffer allocation
  // RSA-3072 pairwise testing keeps input and output in separate 384-byte regions.
  static final short LENGTH_SCRATCH = (short) 768;

  //
  // Static PIV identifiers
  //

  // Data Objects
  static final byte ID_DATA_DISCOVERY = (byte) 0x7E;
  private static final byte INS_PUT_DATA = (byte) 0xDB;
  static final byte[] ID_DATA_PAIRING_CODE_REFERENCE = {(byte) 0x5F, (byte) 0xC1, (byte) 0x23};

  // PIV Secure Messaging key reference.
  static final byte ID_KEY_SECURE_MESSAGING = (byte) 0x04;
  // Optional attestation authority key reference.
  static final byte ID_KEY_ATTESTATION = (byte) 0xF9;

  // Keys
  static final byte ID_ALG_DEFAULT = (byte) 0x00; // This maps to TDEA_3KEY
  static final byte ID_ALG_TDEA_3KEY = (byte) 0x03;
  static final byte ID_ALG_RSA_1024 = (byte) 0x06;
  static final byte ID_ALG_RSA_2048 = (byte) 0x07;
  static final byte ID_ALG_RSA_3072 = (byte) 0x05;
  static final byte ID_ALG_AES_128 = (byte) 0x08;
  static final byte ID_ALG_AES_192 = (byte) 0x0A;
  static final byte ID_ALG_AES_256 = (byte) 0x0C;
  static final byte ID_ALG_ECC_P256 = (byte) 0x11;
  static final byte ID_ALG_ECC_P384 = (byte) 0x14;
  static final byte ID_ALG_ECC_CS2 = (byte) 0x27; // Secure Messaging - ECCP256+SHA256
  static final byte ID_ALG_ECC_CS7 = (byte) 0x2E; // Secure Messaging - ECCP384+SHA384
  // #if VCI_CS2
  static final byte ID_ALG_ECC_SM = ID_ALG_ECC_CS2;
  static final byte OPACITY_KDF_ALG_ID = (byte) 0x09;
  static final short LENGTH_SM_RESPONSE = (short) 320;
  static final short OPACITY_HASH_TMP = (short) 160;
  // #else
  static final byte ID_ALG_ECC_SM = ID_ALG_ECC_CS7;
  static final byte OPACITY_KDF_ALG_ID = (byte) 0x0D;
  static final short LENGTH_SM_RESPONSE = (short) 448;
  static final short OPACITY_HASH_TMP = (short) 400;
  // #endif

  // Cardholder Verification Methods
  static final byte ID_CVM_GLOBAL_PIN = (byte) 0x00;
  static final byte ID_CVM_LOCAL_PIN = (byte) 0x80;
  static final byte ID_CVM_PUK = (byte) 0x81;
  static final byte ID_CVM_OCC_PRI = (byte) 0x96;
  static final byte ID_CVM_OCC_SEC = (byte) 0x97;
  static final byte ID_CVM_PAIRING_CODE = (byte) 0x98;

  // General Authenticate Tags
  static final byte CONST_TAG_DATA = (byte) 0x53;
  static final byte CONST_TAG_AUTH_TEMPLATE = (byte) 0x7C;
  static final byte CONST_TAG_AUTH_WITNESS = (byte) 0x80;
  static final byte CONST_TAG_AUTH_CHALLENGE = (byte) 0x81;
  static final byte CONST_TAG_AUTH_CHALLENGE_RESPONSE = (byte) 0x82;
  static final byte CONST_TAG_AUTH_EXPONENTIATION = (byte) 0x85;

  //
  // PIV-specific ISO 7816 STATUS WORD (SW12) responses
  //
  static final short SW_RETRIES_REMAINING = (short) 0x63C0;
  static final short SW_AUTHENTICATION_METHOD_BLOCKED = (short) 0x6983;
  static final short SW_VERIFICATION_FAILED = (short) 0x6300;

  /*
   * PIV APPLICATION CONSTANTS
   */
  static final short SW_REFERENCE_NOT_FOUND = (short) 0x6A88;

  static final short SW_PUT_DATA_COMMAND_MISSING = (short) 0x6E10;
  static final short SW_PUT_DATA_COMMAND_INVALID_LENGTH = (short) 0x6E11;
  static final short SW_PUT_DATA_OP_MISSING = (short) 0x6E12;
  static final short SW_PUT_DATA_OP_INVALID_LENGTH = (short) 0x6E13;
  static final short SW_PUT_DATA_OP_INVALID_VALUE = (short) 0x6E14;
  static final short SW_PUT_DATA_ID_MISSING = (short) 0x6E15;
  static final short SW_PUT_DATA_ID_INVALID_LENGTH = (short) 0x6E16;
  static final short SW_PUT_DATA_MODE_CONTACT_MISSING = (short) 0x6E17;
  static final short SW_PUT_DATA_MODE_CONTACT_INVALID_LENGTH = (short) 0x6E18;
  static final short SW_PUT_DATA_MODE_CONTACT_INVALID_VALUE = (short) 0x6E19;
  static final short SW_PUT_DATA_MODE_CONTACTLESS_MISSING = (short) 0x6E1A;
  static final short SW_PUT_DATA_MODE_CONTACTLESS_INVALID_LENGTH = (short) 0x6E1B;
  static final short SW_PUT_DATA_MODE_CONTACTLESS_INVALID_VALUE = (short) 0x6E1C;
  static final short SW_PUT_DATA_MODE_ADMIN_KEY_INVALID_LENGTH = (short) 0x6E1D;
  static final short SW_PUT_DATA_KEY_MECHANISM_MISSING = (short) 0x6E1E;
  static final short SW_PUT_DATA_KEY_MECHANISM_INVALID_LENGTH = (short) 0x6E1F;
  static final short SW_PUT_DATA_KEY_ROLE_MISSING = (short) 0x6E20;
  static final short SW_PUT_DATA_KEY_ROLE_INVALID_LENGTH = (short) 0x6E21;
  static final short SW_PUT_DATA_KEY_ATTR_MISSING = (short) 0x6E22;
  static final short SW_PUT_DATA_KEY_ATTR_INVALID_LENGTH = (short) 0x6E23;
  static final short SW_PUT_DATA_CONFIG_MISSING = (short) 0x6E24;
  static final short SW_PUT_DATA_CONFIG_WRONG_LENGTH = (short) 0x6E25;
  static final short SW_PUT_DATA_CONFIG_INVALID_VALUE = (short) 0x6E26;
  static final short SW_PUT_DATA_OBJECT_EXISTS = (short) 0x6E27;

  // The current authentication stage
  static final short OFFSET_AUTH_STATE = ZERO;

  // The key id used in the current authentication
  static final short OFFSET_AUTH_ID = (short) 1;

  // The key mechanism used in the current authentication
  static final short OFFSET_AUTH_MECHANISM = (short) 2;

  // The GENERAL AUTHENTICATE challenge buffer
  static final short OFFSET_AUTH_CHALLENGE = (short) 3;

  //
  // Cryptographic Mechanism Identifiers
  // SP800-73-4 Part 1: 5.3 - Table 5 and
  // SP800-78-4 5.3 - Table 6-2
  //
  // The length to allocate for holding CHALLENGE or WITNESS data for general authenticate
  // NOTE: Since RSA is only involved in INTERNAL AUTHENTICATE, we only need to cater for
  //		 up to an AES block size
  static final short LENGTH_CHALLENGE = (short) 16;
  static final short LENGTH_AUTH_STATE = (short) (5 + LENGTH_CHALLENGE);

  // GENERAL AUTHENTICATE is in its initial state
  // A CHALLENGE has been requested by the client application (Basic Authentication)
  static final short AUTH_STATE_EXTERNAL = (short) 1;
  // A WITNESS has been requested by the client application (Mutual Authentication)
  static final short AUTH_STATE_MUTUAL = (short) 2;

  // PERSISTENT - Command Chaining Handler
  private final ChainBuffer chainBuffer;
  // PERSISTENT - Cryptography Service Provider
  private final PIVSecurityProvider cspPIV;
  // PERSISTENT - Configuration Store
  private final Config config;
  // #if ATTESTATION_ENABLED
  // PERSISTENT - Attestation authority state
  private final PIVAttestation attestation;
  // #endif
  // TRANSIENT - PIV secure messaging and VCI state
  private final PIVSecureMessaging secureMessaging;
  // PERSISTENT - Data Store
  private final PIVDataStore dataStore;
  private final PIVDataCommandHandler dataCommands;
  private final PIVPinCommandHandler pinCommands;
  private final PIVAuthenticationCommandHandler authenticationCommands;
  private final PIVAdministrationCommandHandler administrationCommands;
  private final PIVOpacity opacity;

  // TRANSIENT - A working area to hold intermediate data and outgoing buffers
  private final byte[] scratch;
  // TRANSIENT - Per-applet workspace for EC public-point validation
  private final ECPointValidator ecPointValidator;
  private final ECCurveRegistry curves;
  // TRANSIENT - Holds any authentication related intermediary state
  private final PIVAuthenticationContext authenticationContext;
  // TRANSIENT - Reusable response/work buffer for OPACITY (CS2/CS7) establishment.
  private final byte[] smResponse;
  // TRANSIENT - Reassembled secure-messaging command data.
  private final byte[] smCommand;
  // TRANSIENT - Current APDU response state: non-zero means return under PIV secure messaging.
  private final byte[] secureMessagingCommand;
  private final FipsPowerUpSelfTests fipsSelfTest;
  /** Constructor */
  PIV() {

    //
    // Data Allocation
    //

    // Create our transient buffers
    scratch = JCSystem.makeTransientByteArray(LENGTH_SCRATCH, JCSystem.CLEAR_ON_DESELECT);
    curves = new ECCurveRegistry();
    ecPointValidator = new ECPointValidator();
    authenticationContext = new PIVAuthenticationContext(LENGTH_AUTH_STATE);
    smResponse = JCSystem.makeTransientByteArray(LENGTH_SM_RESPONSE, JCSystem.CLEAR_ON_DESELECT);
    smCommand = JCSystem.makeTransientByteArray(LENGTH_SM_RESPONSE, JCSystem.CLEAR_ON_DESELECT);
    secureMessagingCommand = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
    fipsSelfTest = FipsPolicy.ENABLED ? new FipsPowerUpSelfTests(curves, ecPointValidator) : null;

    // Create our configuration provider
    config = new Config();

    // Allocate the object directory at installation; command processing only mutates its entries.
    dataStore = new PIVDataStore();

    // Create our chainBuffer reference and make sure its state is cleared
    chainBuffer = new ChainBuffer();

    // Create our PIV Security Provider
    cspPIV = new PIVSecurityProvider(curves);
    dataCommands = new PIVDataCommandHandler(config, cspPIV, dataStore, chainBuffer, scratch);

    // #if ATTESTATION_ENABLED
    // Attestation authority state, certificate container, and response buffer are allocated at
    // install time; strict JavaCard platforms may reject transient allocations during APDU
    // processing.
    attestation = new PIVAttestation();
    // #endif

    secureMessaging = new PIVSecureMessaging();
    opacity = new PIVOpacity(scratch, smResponse);
    pinCommands =
        new PIVPinCommandHandler(this, config, cspPIV, dataStore, secureMessaging, scratch);
    authenticationCommands =
        new PIVAuthenticationCommandHandler(
            this,
            cspPIV,
            chainBuffer,
            secureMessaging,
            authenticationContext,
            ecPointValidator,
            scratch,
            smCommand,
            smResponse,
            opacity
            // #if ATTESTATION_ENABLED
            ,
            attestation
            // #endif
            );
    administrationCommands =
        new PIVAdministrationCommandHandler(
            this,
            config,
            cspPIV,
            dataStore,
            chainBuffer,
            secureMessaging,
            scratch,
            smCommand
            // #if ATTESTATION_ENABLED
            ,
            attestation
            // #endif
            );
    // Create our TLV objects (we don't care about the result, this is just to allocate)
    TLVReader.getInstance();
    TLVWriter.getInstance();
    DERWriter.initialize();

    // NOTE:
    // - Javacard does not specify the behaviour of an OwnerPIN that has not ever been
    //   initialised with a value, so we explicitly set one to prevent usage.
    //

    // Generate a random PIN value to initialise it
    PIVCrypto.doGenerateRandom(scratch, ZERO, Config.LIMIT_PIN_MAX_LENGTH);
    cspPIV.updatePIN(ID_CVM_LOCAL_PIN, scratch, ZERO, Config.LIMIT_PIN_MAX_LENGTH, ZERO);
    PIVSecurityProvider.zeroise(scratch, ZERO, Config.LIMIT_PIN_MAX_LENGTH);

    // Generate a random PUK value to initialise it
    PIVCrypto.doGenerateRandom(scratch, ZERO, Config.LIMIT_PUK_MAX_LENGTH);
    cspPIV.updatePIN(ID_CVM_PUK, scratch, ZERO, Config.LIMIT_PUK_MAX_LENGTH, ZERO);
    PIVSecurityProvider.zeroise(scratch, ZERO, Config.LIMIT_PUK_MAX_LENGTH);
    cspPIV.clearBootstrapCvmProvisioningState();

    //
    // NOTE: We do not initialise the Global PIN as this may have been managed externally.
    //
  }

  boolean runFipsSelfTests() {
    if (!FipsPolicy.ENABLED) return true;
    try {
      return fipsSelfTest.run(scratch) && opacity.runCryptographicAlgorithmSelfTest();
    } finally {
      PIVSecurityProvider.zeroise(scratch, ZERO, FipsPowerUpSelfTests.LENGTH_SCRATCH);
    }
  }

  /**
   * Starts or continues processing of an incoming data stream, which will be written directly to a
   * buffer
   *
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset to read from
   * @param length The length of the data to read
   */
  void processIncomingObject(byte[] buffer, short offset, short length) {
    chainBuffer.checkIncomingAPDU(buffer);
    chainBuffer.processIncomingObject(buffer, offset, length, currentProtection());
  }

  void abortAuthenticationExchange() {
    authenticationContext.reset();
  }

  private byte currentProtection() {
    byte protection = ChainBuffer.PROTECTION_PLAIN;
    if (cspPIV.getIsSecureChannel()) {
      protection = ChainBuffer.PROTECTION_SCP;
    } else if (isSecureMessagingCommand()) {
      protection = ChainBuffer.PROTECTION_PIV_SM;
    }
    return protection;
  }

  boolean isSecureMessagingCLA(byte cla) {
    return secureMessaging.isSecureMessagingCla(cla);
  }

  boolean isSecureMessagingEstablished() {
    return secureMessaging.isEstablished();
  }

  boolean isSecureMessagingResponseActive() {
    return chainBuffer.isSecureOutgoingActive() || secureMessaging.isResponseStreamActive();
  }

  boolean isSecureMessagingCommand() {
    return secureMessagingCommand[ZERO] != (byte) 0;
  }

  void clearSecureMessagingCommand() {
    secureMessagingCommand[ZERO] = (byte) 0;
  }

  /**
   * Destroys the session and unpublished work after a transport or establishment failure. Protected
   * application-error statuses retain the session and must not take this path.
   */
  void clearSecureMessaging() {
    clearSecureMessagingCommand();
    secureMessaging.clear();
    chainBuffer.abort();
    dataStore.abortPendingUpdates();
    authenticationContext.reset();
    PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
    PIVSecurityProvider.zeroise(smCommand, ZERO, (short) smCommand.length);
    PIVSecurityProvider.zeroise(smResponse, ZERO, (short) smResponse.length);
  }

  /** Discards an incomplete protected logical command; the session and its MCVs are kept. */
  void abandonSecureMessagingCommandStream() {
    secureMessaging.clearRejectedCommandStream();
  }

  /**
   * Abandons any pending command or response chain and its staged object update, as a command that
   * interrupts ISO/IEC 7816-4 chaining does.
   */
  void abandonChains() {
    abortOutgoingResponse();
    chainBuffer.abort();
    dataStore.abortPendingUpdates();
  }

  void abortOutgoingResponse() {
    if (secureMessaging.isResponseStreamActive()) {
      secureMessaging.abortResponseStream();
    }
    chainBuffer.abortOutgoing();
    clearSecureMessagingCommand();
  }

  short unwrapSecureMessagingCommand(byte[] buffer, short offset, short length) {
    try {
      return unwrapSecureMessagingCommandChecked(buffer, offset, length);
    } catch (ISOException ex) {
      short reason = ex.getReason();
      if (reason == ISO7816.SW_NO_ERROR) throw ex;
      // SP 800-73-5 Part 2 Section 4.2.7: an unsuccessful secure messaging exchange SHALL return
      // '68 82', '69 82', '69 87' or '69 88' "without performing further secure messaging".
      // Reassembly failures from the shared chain buffer are incorrect secure messaging data.
      clearSecureMessaging();
      ISOException.throwIt(PIVSecureMessaging.toProcessingStatus(reason));
      return ZERO;
    } catch (javacard.security.CryptoException ex) {
      clearSecureMessaging();
      ISOException.throwIt(PIVSecureMessaging.SW_SM_OBJECTS_INCORRECT);
      return ZERO;
    } catch (RuntimeException ex) {
      // SP 800-73-5 Part 2 Section 4.3 zeroizes the session keys when "an error occurs in secure
      // messaging"; a runtime fault is such an error whatever status the JCRE reports for it.
      clearSecureMessaging();
      throw ex;
    }
  }

  private short unwrapSecureMessagingCommandChecked(byte[] buffer, short offset, short length) {
    // ISO/IEC 7816-4 command chaining discards an incomplete logical command when another command
    // arrives. Abort that state before secure-messaging reassembly uses the shared chain buffer.
    chainBuffer.checkIncomingAPDU(buffer);
    boolean commandChaining = (buffer[ISO7816.OFFSET_CLA] & (byte) 0x10) != (byte) 0;

    if (secureMessaging.isRejectedCommandStreamActive()
        && !secureMessaging.rejectedCommandStreamMatches(buffer)) {
      // Discard only the incomplete logical command. Keep the authenticated session so the next
      // protected command can use the current command MCV.
      secureMessaging.clearRejectedCommandStream();
    }

    boolean streamRejectedPutData =
        secureMessaging.isRejectedCommandStreamActive()
            || (mustRejectContactlessPutData()
                && commandChaining
                && buffer[ISO7816.OFFSET_INS] == INS_PUT_DATA);
    if (streamRejectedPutData) {
      // Section 4.2.4 says the card "reconstructs and processes the entire command." Authenticate
      // and decrypt every frame before Table 2 supplies protected status 6A81. The bounded parser
      // keeps one plaintext block and does not place rejected data in the command chain buffer.
      boolean complete =
          secureMessaging.processRejectedCommandFragment(
              buffer, offset, length, !commandChaining, smResponse, ZERO);
      if (!complete) ISOException.throwIt(ISO7816.SW_NO_ERROR);
      secureMessagingCommand[ZERO] = (byte) 1;
      buffer[ISO7816.OFFSET_CLA] = (byte) (buffer[ISO7816.OFFSET_CLA] & (byte) 0xF3);
      return ZERO;
    }

    Util.arrayCopyNonAtomic(buffer, ZERO, smCommand, ZERO, (short) 5);
    if (buffer[ISO7816.OFFSET_INS] == OpenFIPS201.INS_GP_GET_RESPONSE
        && chainBuffer.isSecureOutgoingActive()) {
      // SP 800-73-5 Part 2 Section 4.2.6: GET RESPONSE retrieves the next part of the pending
      // protected response. The chain buffer holds that response, so a protected GET RESPONSE is
      // a single-frame command unwrapped directly from the APDU buffer.
      if (commandChaining || length > (short) (smCommand.length - 5)) {
        ISOException.throwIt(PIVSecureMessaging.SW_SM_OBJECTS_INCORRECT);
      }
      Util.arrayCopyNonAtomic(buffer, offset, smCommand, (short) 5, length);
    } else {
      length = chainBuffer.processIncomingAPDU(buffer, offset, length, smCommand, (short) 5);
    }
    if (length == ZERO && commandChaining) ISOException.throwIt(ISO7816.SW_NO_ERROR);

    length = secureMessaging.unwrapCommand(smCommand, (short) 5, length, smResponse, ZERO);
    secureMessagingCommand[ZERO] = (byte) 1;
    // chainBuffer has reconstructed the complete protected command. Do not expose the first
    // transport frame's chaining bit to command handlers, or they will start a second logical
    // command chain from the already-reassembled plaintext.
    smCommand[ISO7816.OFFSET_CLA] =
        (byte) (smCommand[ISO7816.OFFSET_CLA] & (byte) ~ChainBuffer.CLA_CHAINING);
    Util.arrayCopyNonAtomic(smCommand, ZERO, buffer, ZERO, (short) 5);
    if (length > ZERO && (short) (offset + length) <= (short) buffer.length) {
      Util.arrayCopyNonAtomic(smCommand, (short) 5, buffer, offset, length);
    }
    return length;
  }

  byte[] getSecureMessagingCommandBuffer() {
    return smCommand;
  }

  /**
   * Starts or continues processing for an outgoing buffer being transmitted to the host
   *
   * @param apdu The current APDU buffer to transmit with
   */
  void processOutgoing(APDU apdu) {
    processOutgoing(apdu, ISO7816.SW_NO_ERROR);
  }

  void processOutgoing(APDU apdu, short sw) {
    if (isSecureMessagingCommand()) {
      processOutgoingSecure(apdu, sw);
      return;
    }

    if (sw != ISO7816.SW_NO_ERROR) {
      ISOException.throwIt(sw);
    }

    boolean getResponse = apdu.getBuffer()[ISO7816.OFFSET_INS] == OpenFIPS201.INS_GP_GET_RESPONSE;
    if (getResponse && isSecureMessagingResponseActive()) {
      // SP 800-73-5 Part 2 Section 4.2.6 continues a response under PIV secure messaging with GET
      // RESPONSE (Figure 7: "an APDU of '00 C0 00 00 00' will be sent to request the second
      // response"). The dispatcher routes that plaintext form and the protected form to the
      // secure-messaging continuation, so a GET RESPONSE reaching this path carries GP SCP
      // protection and must not release the response outside secure messaging.
      abortOutgoingResponse();
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    if (getResponse && !chainBuffer.isOutgoingActive()) {
      // An idle GET RESPONSE cannot continue an incoming command. Roll back its staging
      // just like any other command that interrupts ISO/IEC 7816-4 command chaining.
      chainBuffer.abort();
      dataStore.abortPendingUpdates();
    }
    chainBuffer.processOutgoing(apdu, currentProtection());
  }

  void processOutgoingSecure(APDU apdu, short sw) {
    try {
      chainBuffer.processOutgoingSecure(apdu, secureMessaging, smResponse, sw);
    } catch (ISOException ex) {
      if (secureMessaging.isResponseStreamComplete() && !chainBuffer.isSecureOutgoingActive()) {
        clearSecureMessagingCommand();
      }
      if (ex.getReason() != ISO7816.SW_NO_ERROR
          && (short) (ex.getReason() & (short) 0xFF00) != ISO7816.SW_BYTES_REMAINING_00) {
        clearSecureMessaging();
      }
      throw ex;
    } catch (javacard.security.CryptoException ex) {
      clearSecureMessaging();
      ISOException.throwIt(PIVSecureMessaging.SW_SM_OBJECTS_INCORRECT);
    } catch (RuntimeException ex) {
      // SP 800-73-5 Part 2 Section 4.3: any status other than '61 XX' or '90 00' is an error in
      // secure messaging, after which the session keys SHALL be zeroized.
      clearSecureMessaging();
      throw ex;
    }
  }

  void processOutgoingSecureContinuation(APDU apdu) {
    if (!chainBuffer.isSecureOutgoingActive() && !secureMessaging.isResponseStreamActive()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    processOutgoingSecure(apdu, ISO7816.SW_NO_ERROR);
  }

  /**
   * Called when this applet is selected. Places the APT in the outgoing response chain.
   *
   * <p>SP 800-73-5 Part 2 Section 3.1.1: "Upon selection, the PIV Card Application SHALL return the
   * application property template described in Table 3." A response longer than Ne is continued
   * with '61 XX' and GET RESPONSE (ISO/IEC 7816-4 Section 5.3.4), not truncated.
   *
   * @return The length of the APT object
   */
  short select() {

    //
    // PRE-CONDITIONS
    //

    // NONE

    //
    // EXECUTION STEPS
    //

    // Recover persistent staging that can outlive transient ChainBuffer state after an implicit
    // reset, where the JCRE does not call deselect().
    chainBuffer.abort();
    dataStore.abortPendingUpdates();
    // #if ATTESTATION_ENABLED
    completeAttestationActivation();
    // #endif

    // STEP 1 - Evaluate whether any PIV state needs to be updated as a result of
    //          configuration changes

    // STEP 1a) Local PIN try limit
    PIVPIN localPin = cspPIV.getPIN(PIV.ID_CVM_LOCAL_PIN);
    if (config.readValue(Config.CONFIG_PIN_RETRIES_CONTACT) != localPin.getTryLimit()) {
      localPin.setTryLimit(config.readValue(Config.CONFIG_PIN_RETRIES_CONTACT));
    }

    // STEP 1b) PUK try limit
    PIVPIN puk = cspPIV.getPIN(PIV.ID_CVM_PUK);
    if (config.readValue(Config.CONFIG_PUK_RETRIES_CONTACT) != puk.getTryLimit()) {
      puk.setTryLimit(config.readValue(Config.CONFIG_PUK_RETRIES_CONTACT));
    }

    // STEP 2 - Return the APT
    short length = buildApplicationPropertyTemplate(scratch, ZERO);
    chainBuffer.setOutgoing(scratch, ZERO, length, false);
    return length;
  }

  private short buildApplicationPropertyTemplate(byte[] buffer, short offset) {
    short length = (short) Config.TEMPLATE_APT.length;
    Util.arrayCopyNonAtomic(Config.TEMPLATE_APT, ZERO, buffer, offset, length);

    if (!isSecureMessagingAdvertised()) {
      return length;
    }

    short acOffset = findChildTlv(buffer, offset, (byte) 0xAC);
    if (acOffset < (short) 0) {
      return length;
    }
    short end = (short) (offset + length);

    PIVKeyObject smKey = getSecureMessagingKey();
    if (smKey == null) {
      return length;
    }

    short insertOffset =
        (short)
            (TLVReader.getDataOffset(buffer, acOffset)
                + (short) (buffer[(short) (acOffset + 1)] & 0xFF));
    Util.arrayCopyNonAtomic(
        buffer, insertOffset, buffer, (short) (insertOffset + 3), (short) (end - insertOffset));
    buffer[insertOffset++] = (byte) 0x80;
    buffer[insertOffset++] = (byte) 0x01;
    // NIST SP 800-73-5 Part 2, Section 3.1.1 and Table 5: advertise 0x27 or 0x2E
    // only when the application possesses an initialized SM key for that cipher suite.
    buffer[insertOffset] = smKey.getMechanism();

    buffer[(short) (offset + 2)] += (byte) 3;
    buffer[(short) (acOffset + 1)] += (byte) 3;
    return (short) (length + 3);
  }

  private short findChildTlv(byte[] buffer, short parentOffset, byte tag) {
    short cursor = TLVReader.getDataOffset(buffer, parentOffset);
    short end = (short) (cursor + TLVReader.getLength(buffer, parentOffset));
    while (cursor < end) {
      if (buffer[cursor] == tag) {
        return cursor;
      }
      short valueOffset = TLVReader.getDataOffset(buffer, cursor);
      cursor = (short) (valueOffset + TLVReader.getLength(buffer, cursor));
    }
    return (short) -1;
  }

  private boolean isSecureMessagingAdvertised() {
    return getSecureMessagingKey() != null;
  }

  /**
   * Returns the initialised SM key (CS2 or CS7), or null when key 04 or its CVC is not ready.
   *
   * <p>Secure messaging is available whenever key 04 holds key material and its CVC, independent of
   * the VCI configuration, so the APT advertisement follows the key alone. SP 800-73-5 Part 2
   * Section 3.1.1: "Tag 0xAC SHALL be present and indicate algorithm identifier 0x27 or 0x2E (but
   * not both) when the PIV Card Application supports secure messaging."
   */
  private PIVKeyObject getSecureMessagingKey() {
    PIVKeyObject key = cspPIV.selectKey(ID_KEY_SECURE_MESSAGING, ID_ALG_ECC_SM);
    return (key != null && key.isInitialised()) ? key : null;
  }

  /**
   * Handles the PIV requirements for deselection of the application. Although this is not
   * explicitly stated as a PIV card command, its functionality is implied in the SELECT
   */
  void deselect() {

    // If the currently selected application is the PIV Card Application when the SELECT command is
    // given and the AID in the data field of the SELECT command is either the AID of the PIV Card
    // Application or the right-truncated version thereof, then the PIV Card Application shall
    // continue to be the currently selected card application and the setting of all security status
    // indicators in the PIV Card Application shall be unchanged.

    // If the currently selected application is the PIV Card Application when the SELECT command is
    // given and the AID in the data field of the SELECT command is not the PIV Card Application (or
    // the right truncated version thereof), but a valid AID supported by the ICC, then the PIV Card
    // Application shall be deselected and all the PIV Card Application security status indicators
    // in the PIV Card Application shall be set to FALSE.

    // Reset all security conditions in the security provider
    cspPIV.clearAuthenticatedKey();
    cspPIV.clearPINAlways();
    cspPIV.clearApplicationVerification();
    chainBuffer.abort();
    dataStore.abortPendingUpdates();
    secureMessaging.clear();
  }

  // #if ATTESTATION_ENABLED
  /**
   * Completes an interrupted attestation-authority activation before command processing resumes.
   *
   * <p>The ACTIVATING state is persistent. Repeating the data and key clearing operations is safe,
   * so selection can finish a power-interrupted activation before F9 becomes active.
   */
  void completeAttestationActivation() {
    if (!attestation.isAuthorityActivationPending()) return;
    // Clearing is intentionally idempotent and outside a transaction. If power is lost, the
    // persistent ACTIVATING state survives and selection resumes before F9 can become active.
    dataStore.clearContents();
    cspPIV.clearKeyMaterialExcept(ID_KEY_ATTESTATION);
    attestation.completeAuthorityActivation();
  }
  // #endif

  private boolean isVciConfigured() {
    return config.readValue(Config.CONFIG_VCI_MODE) != Config.VCI_MODE_DISABLED;
  }

  boolean isVciSatisfied() {
    return PIVDataCommandHandler.hasPolicyBits(
            dataCommands.getDiscoveryPolicy(), PIVDataCommandHandler.PIN_POLICY_VCI)
        && isSecureMessagingCommand()
        && secureMessaging.isVciEstablished();
  }

  boolean isDiscoveryPairingRequired() {
    return !PIVDataCommandHandler.hasPolicyBits(
        dataCommands.getDiscoveryPolicy(), PIVDataCommandHandler.PIN_POLICY_VCI_WITHOUT_PAIRING);
  }

  boolean isPairingCodeReferenceEnabled() {
    short policy = dataCommands.getDiscoveryPolicy();
    return isPairingCodeReferenceEnabled(config.readValue(Config.CONFIG_VCI_MODE), policy);
  }

  static boolean isPairingCodeReferenceEnabled(byte vciMode, short policy) {
    return vciMode == Config.VCI_MODE_PAIRING_CODE
        && PIVDataCommandHandler.hasPolicyBits(policy, PIVDataCommandHandler.PIN_POLICY_VCI)
        && !PIVDataCommandHandler.hasPolicyBits(
            policy, PIVDataCommandHandler.PIN_POLICY_VCI_WITHOUT_PAIRING);
  }

  boolean isPairingCodeVerified() {
    return secureMessaging.isVciEstablished();
  }

  boolean isGlobalPinAdvertised() {
    return dataCommands.isGlobalPinAdvertised();
  }

  boolean isFipsPersonalizationReady() {
    // SP 800-73-5 Part 1, Table 1 requires these seven data objects. The
    // certification profile also requires its PIN, PUK, 9A, and 9E material
    // to be issuer-provisioned before the lifecycle becomes irreversible.
    // FIPS 201-3 Section 4.2.2.1: "This key SHALL be generated on the PIV Card." (PIV
    // authentication key) and Section 4.2.2.4: "The PIV digital signature key SHALL be generated
    // on the PIV Card." The optional 9C key is checked only when present.
    if (!cspPIV.areMandatoryCvmsProvisioned()
        || !cspPIV.hasGeneratedAsymmetricKey((byte) 0x9A)
        || (cspPIV.hasUsableAsymmetricKey((byte) 0x9C)
            && !cspPIV.hasGeneratedAsymmetricKey((byte) 0x9C))
        || !cspPIV.hasUsableAsymmetricKey((byte) 0x9E)
        || !hasStructurallyValidMandatoryObject((byte) 0x07)
        || !hasStructurallyValidMandatoryObject((byte) 0x02)
        || !hasStructurallyValidMandatoryObject((byte) 0x05)
        || !hasStructurallyValidMandatoryObject((byte) 0x01)
        || !hasStructurallyValidMandatoryObject((byte) 0x03)
        || !hasStructurallyValidMandatoryObject((byte) 0x08)
        || !hasStructurallyValidMandatoryObject((byte) 0x06)) {
      return false;
    }
    // SP 800-73-5 Part 1 Section 3.3.2: "PIV Card Applications that implement the VCI or for
    // which the Global PIN or OCC satisfy the PIV ACRs for PIV data object access and command
    // execution SHALL implement the Discovery Object." A stored Discovery Object must use a Table 1
    // value and advertise only the PIN, Global PIN, OCC and VCI features this card provides.
    byte vciMode = config.readValue(Config.CONFIG_VCI_MODE);
    boolean discoveryStored = hasInitialisedDataObject(ID_DATA_DISCOVERY, (byte) 0, (byte) 0);
    if ((discoveryStored || isVciConfigured())
        && !PIVDataCommandHandler.isDiscoveryPolicyConsistent(
            dataCommands.getDiscoveryPolicy(),
            config.readFlag(Config.CONFIG_PIN_ENABLE_GLOBAL),
            vciMode)) {
      return false;
    }
    if (isVciConfigured()) {
      // SP 800-73-5 Part 2, Section 4 requires the SM key and CVC for VCI.
      PIVKeyObject smKey = getSecureMessagingKey();
      if (!(smKey instanceof PIVKeyObjectECC)
          || ((PIVKeyObjectECC) smKey).getSmCvcLength() == (short) 0
          // SP 800-73-5 Part 1 Section 3.3.7 requires 5FC122 when SM protects
          // non-card-management operations.
          || !hasInitialisedDataObject((byte) 0x5F, (byte) 0xC1, (byte) 0x22)) {
        return false;
      }
      // SP 800-73-5 Part 1 Section 3.3.8 requires the Pairing Code Reference Data Container when
      // the pairing code is used. VERIFY 98 compares against it, so its Table 44 structure is
      // checked before the irreversible transition.
      if (vciMode == Config.VCI_MODE_PAIRING_CODE
          && !PIVDataCommandHandler.isValidPairingCodeContainer(
              dataStore.find(ID_DATA_PAIRING_CODE_REFERENCE, ZERO, (short) 3))) {
        return false;
      }
    }
    // SP 800-73-5 Part 1 Section 3.3.3: "The Key History object SHALL be present in the PIV Card
    // Application if the PIV Card Application contains any retired key management private keys".
    if (hasRetiredKeyManagementKey() && !hasStructurallyValidMandatoryObject((byte) 0x0C)) {
      return false;
    }
    // #if ATTESTATION_ENABLED
    if (!attestation.isAuthorityActive()) return false;
    // #endif
    return true;
  }

  private boolean hasInitialisedDataObject(byte first, byte second, byte third) {
    short length;
    if (first == (byte) 0x7E) {
      scratch[ZERO] = first;
      length = (short) 1;
    } else {
      scratch[ZERO] = first;
      scratch[(short) 1] = second;
      scratch[(short) 2] = third;
      length = (short) 3;
    }
    PIVDataObject object = dataStore.find(scratch, ZERO, length);
    return object != null && object.isInitialised();
  }

  /** Returns whether any retired key management reference '82' to '95' holds a private key. */
  private boolean hasRetiredKeyManagementKey() {
    for (byte id = (byte) 0x82; id <= (byte) 0x95; id++) {
      if (cspPIV.hasUsableAsymmetricKey(id)) return true;
    }
    return false;
  }

  private boolean hasStructurallyValidMandatoryObject(byte suffix) {
    scratch[ZERO] = (byte) 0x5F;
    scratch[(short) 1] = (byte) 0xC1;
    scratch[(short) 2] = suffix;
    PIVDataObject object = dataStore.find(scratch, ZERO, (short) 3);
    return PIVDataCommandHandler.isStructurallyValidMandatoryObject(object, suffix);
  }

  void rejectUnsupportedOccAccessMode(byte mode) {
    if (mode != PIVObject.ACCESS_MODE_ALWAYS
        && (mode & PIVObject.ACCESS_MODE_OCC) == PIVObject.ACCESS_MODE_OCC) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }
  }

  /**
   * The GET DATA card command retrieves the data content of the single data object whose tag is
   * given in the data field.
   *
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset of the CDATA section
   * @return The length of the entire data object
   */
  /**
   * The PUT DATA card command completely replaces the data content of a single data object in the
   * PIV Card Application with new content.
   *
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset of the CDATA section
   * @param length The length of the CDATA section
   */
  short getData(byte[] buffer, short offset, short length) throws ISOException {
    // #if ATTESTATION_ENABLED
    if (isAttestationAuthorityObject(buffer, offset, length)) {
      return getAttestationAuthorityContainer();
    }
    // #endif
    return dataCommands.getData(buffer, offset, length, isVciSatisfied());
  }

  // #if ATTESTATION_ENABLED
  /** Returns whether a GET DATA tag list names the read-only F9 certificate object 5FFF01. */
  private static boolean isAttestationAuthorityObject(byte[] buffer, short offset, short length) {
    return length == (short) 5
        && buffer[offset] == (byte) 0x5C
        && buffer[(short) (offset + 1)] == (byte) 0x03
        && buffer[(short) (offset + 2)] == (byte) 0x5F
        && buffer[(short) (offset + 3)] == (byte) 0xFF
        && buffer[(short) (offset + 4)] == (byte) 0x01;
  }

  /**
   * Serves the F9 certificate container as virtual read-only data object 5FFF01.
   *
   * <p>The object is the public attestation-authority certificate in the PIV X.509 certificate
   * container layout (tags 70, 71, and FE). It exists only once the authority is ACTIVE and is
   * readable without authentication on every interface; PUT DATA and CREATE OBJECT cannot reach it.
   *
   * @return container length
   */
  private short getAttestationAuthorityContainer() {
    if (!attestation.isAuthorityActive()) ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    short length = attestation.getAuthorityContainerLength();
    chainBuffer.setOutgoing(attestation.getAuthorityContainer(), ZERO, length, false);
    return length;
  }

  /**
   * Returns the stored F9 certificate for {@code 00 F9 F9 00}.
   *
   * <p>The certificate is public and needs no access control, but exists only once the authority is
   * ACTIVE.
   *
   * @throws ISOException with {@link ISO7816#SW_CONDITIONS_NOT_SATISFIED} before activation
   */
  void getAttestationAuthorityCertificate() {
    if (!attestation.isAuthorityActive()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    chainBuffer.setOutgoing(
        attestation.getAuthorityContainer(),
        PIVAttestation.CERT_STORE_OFFSET,
        attestation.getCertificateLength(),
        false);
  }

  /**
   * Signs the F9 proof-of-possession message for the issuer nonce in the command data.
   *
   * @param buffer command data buffer
   * @param offset first nonce octet
   * @param length nonce length
   */
  void proveAttestationAuthority(byte[] buffer, short offset, short length) {
    authenticationCommands.proveAuthority(buffer, offset, length);
  }
  // #endif

  void putData(byte[] buffer, short offset, short length) throws ISOException {
    dataCommands.putData(buffer, offset, length, isVciSatisfied(), currentProtection());
  }

  /**
   * The VERIFY card command initiates the comparison in the card of the reference data indicated by
   * the key reference with authentication data in the data field of the command.
   *
   * @param id The requested PIN reference
   * @param buffer The incoming APDU buffer
   * @param offset The starting offset of the CDATA element
   * @param length The length of the CDATA element
   */
  void verify(byte id, byte[] buffer, short offset, short length) throws ISOException {
    pinCommands.verify(id, buffer, offset, length);
  }

  void verifyGetStatus(byte id) throws ISOException {
    pinCommands.verifyGetStatus(id);
  }

  void verifyResetStatus(byte id) throws ISOException {
    pinCommands.verifyResetStatus(id);
  }

  void changeReferenceData(byte id, byte[] buffer, short offset, short length) throws ISOException {
    pinCommands.changeReferenceData(id, buffer, offset, length);
  }

  void resetRetryCounter(byte id, byte[] buffer, short offset, short length) throws ISOException {
    pinCommands.resetRetryCounter(id, buffer, offset, length);
  }

  void setIsContactless(boolean value) {

    // This can be overriden by configuration to ignore the contactless interface
    if (config.readFlag(Config.OPTION_IGNORE_CONTACTLESS_ACL)) {
      value = false;
    }
    cspPIV.setIsContactless(value);
  }

  boolean isContactless() {
    return cspPIV.getIsContactless();
  }

  boolean isInterfacePermitted() {
    return !isContactless() || !config.readFlag(Config.OPTION_RESTRICT_CONTACTLESS_GLOBAL);
  }

  /***
   * Indicates whether administration is allowed over the current communications media.
   * Note that this DOES NOT mean there is a valid administrative session!
   * @return True if administrative commands are permitted in the current context.
   */
  boolean isInterfacePermittedForAdmin() {

    // Administration is always permitted over the contact interface
    if (!cspPIV.getIsContactless()) return true;

    // Administration is only allowed over the contactless interface if the
    // OPTION_RESTRICT_CONTACTLESS_ADMIN flag is NOT SET
    return !config.readFlag(Config.OPTION_RESTRICT_CONTACTLESS_ADMIN);
  }

  /**
   * Returns true when Table 2 requires PUT DATA to fail on the contactless interface.
   *
   * <p>Contactless card management is an issuer configuration. Secure-messaging parsing does not
   * depend on the build profile.
   */
  boolean mustRejectContactlessPutData() {
    return isContactless() && !isInterfacePermittedForAdmin();
  }

  /**
   * Allows the applet to provide security state information to PIV for access control
   *
   * @param value Sets whether the current command was issued over a GlobalPlatform Secure Channel
   */
  void setIsSecureChannel(boolean value) {
    cspPIV.setIsSecureChannel(value);
  }

  /** Clears any intermediate authentication status used by 'GENERAL AUTHENTICATE' */
  short generalAuthenticate(byte[] buffer, short offset, short length) throws ISOException {
    return authenticationCommands.generalAuthenticate(buffer, offset, length);
  }

  short generateAsymmetricKeyPair(byte[] buffer, short offset, short length) throws ISOException {
    return authenticationCommands.generateAsymmetricKeyPair(buffer, offset, length);
  }

  boolean verifyPinRules(byte[] buffer, short offset, short length) {
    return pinCommands.verifyPinRules(buffer, offset, length);
  }

  boolean verifyPinFormat(byte[] buffer, short offset, short length) throws ISOException {
    return pinCommands.verifyPinFormat(buffer, offset, length);
  }

  static final byte CONST_TAG_COMPATIBILITY_OPERATION = (byte) 0x8A;
  static final byte CONST_TAG_ID = (byte) 0x8B;
  static final byte CONST_TAG_MODE_CONTACT = (byte) 0x8C;
  static final byte CONST_TAG_MODE_CONTACTLESS = (byte) 0x8D;
  static final byte CONST_TAG_ADMIN_KEY = (byte) 0x91;
  static final byte CONST_TAG_CAPACITY = (byte) 0x92;
  static final byte CONST_TAG_KEY_MECHANISM = (byte) 0x8E;
  static final byte CONST_TAG_KEY_ROLE = (byte) 0x8F;
  static final byte CONST_TAG_KEY_ATTRIBUTE = (byte) 0x90;
  static final byte CONST_TAG_COMPATIBILITY = (byte) 0x30;
  static final byte CONST_TAG_CREATE_OBJECT = (byte) 0x64;
  static final byte CONST_TAG_DELETE_OBJECT = (byte) 0x65;
  static final byte CONST_TAG_CREATE_KEY = (byte) 0x66;
  static final byte CONST_TAG_DELETE_KEY = (byte) 0x67;
  static final byte CONST_TAG_UPDATE_CONFIG = (byte) 0x68;
  static final byte CONST_TAG_PERSONALIZE_APPLET = (byte) 0x69;
  static final byte CONST_TAG_BULK_REQUEST = (byte) 0x6A;

  // #if ATTESTATION_ENABLED
  void attest(byte slot) {
    authenticationCommands.attest(slot);
  }
  // #endif

  void putDataAdmin(byte[] buffer, short offset, short length) throws ISOException {
    administrationCommands.putDataAdmin(buffer, offset, length);
  }

  void changeReferenceDataAdmin(byte id, byte[] buffer, short offset, short length)
      throws ISOException {
    administrationCommands.changeReferenceDataAdmin(id, buffer, offset, length);
  }

  short getDataExtended(byte[] buffer, short offset, short length) throws ISOException {
    return administrationCommands.getDataExtended(buffer, offset, length);
  }
}
