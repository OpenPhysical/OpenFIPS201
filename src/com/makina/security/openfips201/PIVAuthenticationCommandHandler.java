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
import javacard.framework.Util;

/** Handles GENERAL AUTHENTICATE, OPACITY dispatch, and asymmetric key generation. */
final class PIVAuthenticationCommandHandler {
  private final PIV owner;
  private final Config config;
  private final PIVSecurityProvider cspPIV;
  private final ChainBuffer chainBuffer;
  private final PIVSecureMessaging secureMessaging;
  private final PIVAuthenticationContext authenticationContext;
  private final ECPointValidator ecPointValidator;
  private final byte[] scratch;
  private final byte[] smCommand;
  private final byte[] smResponse;
  private final PIVOpacity opacity;
  // #if ATTESTATION_ENABLED
  private final PIVAttestation attestation;
  private final byte[] attestationResponse;
  // #endif

  PIVAuthenticationCommandHandler(
      PIV owner,
      Config config,
      PIVSecurityProvider cspPIV,
      ChainBuffer chainBuffer,
      PIVSecureMessaging secureMessaging,
      PIVAuthenticationContext authenticationContext,
      ECPointValidator ecPointValidator,
      byte[] scratch,
      byte[] smCommand,
      byte[] smResponse,
      PIVOpacity opacity
      // #if ATTESTATION_ENABLED
      , PIVAttestation attestation,
      byte[] attestationResponse
      // #endif
      ) {
    this.owner = owner;
    this.config = config;
    this.cspPIV = cspPIV;
    this.chainBuffer = chainBuffer;
    this.secureMessaging = secureMessaging;
    this.authenticationContext = authenticationContext;
    this.ecPointValidator = ecPointValidator;
    this.scratch = scratch;
    this.smCommand = smCommand;
    this.smResponse = smResponse;
    this.opacity = opacity;
    // #if ATTESTATION_ENABLED
    this.attestation = attestation;
    this.attestationResponse = attestationResponse;
    // #endif
  }

  private void authenticateReset() throws ISOException {
    authenticationContext.reset();
  }

  /**
   * The GENERAL AUTHENTICATE card command performs a cryptographic operation, such as an
   * authentication protocol, using the data provided in the data field of the command and returns
   * the result of the cryptographic operation in the response data field.
   *
   * @param buffer The incoming APDU buffer
   * @param offset The offset of the CDATA element
   * @param length The length of the CDATA element
   * @return The length of the return data
   */
  short generalAuthenticate(byte[] buffer, short offset, short length) throws ISOException {

    //
    // COMMAND CHAIN HANDLING
    //

    // Pass the APDU to the chainBuffer instance first. It will return zero if there is more
    // of the chain to process, otherwise it will return the length of the large CDATA buffer
    length = chainBuffer.processIncomingAPDU(buffer, offset, length, scratch, ZERO);

    // If the length is zero, just return so the caller can keep sending
    if (length == 0) return length;

    // If we got this far, the scratch buffer now contains the incoming DATA. Keep in mind that the
    // original buffer still contains the APDU header.

    // Set up our TLV reader
    TLVReader reader = TLVReader.getInstance();
    reader.init(scratch, ZERO, length);

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The key reference and mechanism must point to an existing key.
    if ((buffer[ISO7816.OFFSET_P2] == ID_KEY_SECURE_MESSAGING
            || buffer[ISO7816.OFFSET_P1] == ID_ALG_ECC_SM)
        && (buffer[ISO7816.OFFSET_P2] != ID_KEY_SECURE_MESSAGING
            || buffer[ISO7816.OFFSET_P1] != ID_ALG_ECC_SM)) {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      return ZERO; // Keep compiler happy
    }

    // PRE-CONDITION 2 - The key reference and mechanism must point to an existing key.
    // F9 is the attestation authority and is not valid for GENERAL AUTHENTICATE operations; it is
    // deliberately handled as 'not found' so its presence is not observable through this command.
    PIVKeyObject key = cspPIV.selectKey(buffer[ISO7816.OFFSET_P2], buffer[ISO7816.OFFSET_P1]);
    if (key == null || buffer[ISO7816.OFFSET_P2] == ID_KEY_ATTESTATION) {
      // If any key reference value is specified that is not supported by the card, the PIV Card
      // Application shall return the status word '6A 88'.
      cspPIV.clearPINAlways();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
      return ZERO; // Keep compiler happy
    }

    // PRE-CONDITION 3 - The access rules must be satisfied for the requested key
    // NOTE: A call to this method automatically clears the PIN ALWAYS status.
    if (!cspPIV.checkAccessModeObject(key, owner.isVciSatisfied())) {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      return ZERO; // Keep compiler happy
    }

    // PRE-CONDITION 4 - The key's private or secret values must have been set
    if (!key.isInitialised()) {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      return ZERO; // Keep compiler happy
    }

    // PRE-CONDITION 5 - The Dynamic Authentication Template tag must be present in the data
    if (!reader.find(CONST_TAG_AUTH_TEMPLATE)) {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return ZERO; // Keep compiler happy
    }

    // Move into the content of the template
    reader.moveInto();

    //
    // EXECUTION STEPS
    //

    //
    // STEP 1 - Traverse the TLV to determine what combination of elements exist
    //
    short challengeOffset = ZERO;
    short witnessOffset = ZERO;
    short responseOffset = ZERO;
    short exponentiationOffset = ZERO;

    short challengeLength = ZERO;
    short witnessLength = ZERO;
    short responseLength = ZERO;
    short exponentiationLength = ZERO;

    // Save the offset in the TLV object
    offset = reader.getOffset();

    // Loop through all tags
    do {
      if (reader.match(CONST_TAG_AUTH_CHALLENGE)) {
        challengeOffset = reader.getDataOffset();
        challengeLength = reader.getLength();
      } else if (reader.match(CONST_TAG_AUTH_CHALLENGE_RESPONSE)) {
        responseOffset = reader.getDataOffset();
        responseLength = reader.getLength();
      } else if (reader.match(CONST_TAG_AUTH_WITNESS)) {
        witnessOffset = reader.getDataOffset();
        witnessLength = reader.getLength();
      } else if (reader.match(CONST_TAG_AUTH_EXPONENTIATION)) {
        exponentiationOffset = reader.getDataOffset();
        exponentiationLength = reader.getLength();
      } else {
        // We have come across an unknown tag value. Other implementations ignore these and so shall
        // we.
      }
    } while (reader.moveNext());

    // Restore the offset in the TLV object
    reader.setOffset(offset);

    //
    // STEP 2 - Process the appropriate GENERAL AUTHENTICATE case
    //

    //
    // IMPLEMENTATION NOTES
    // --------------------
    // There are 6 authentication cases that make up all of the GENERAL AUTHENTICATE functionality.
    // The first case (Internal Authenticate) has 4 different mode variants depending on the key
    // type
    // and attributes.
    //
    // CASE 1 - INTERNAL AUTHENTICATE
    //
    // Description:
    // The CLIENT presents a CHALLENGE to the CARD, which then returns the encrypted/signed
    // CHALLENGE RESPONSE. This is handled in 3 different mode variants, depending on the keys.
    //	  a. TDEA/AES keys with the AUTHENTICATE role will encipher the challenge.
    //    b. RSA/ECC keys with the SIGNATURE role will perform signing operations
    //       (on already padded data).
    //    c. SM keys with the KEY_ESTABLISH role will perform the Opacity-ZKM key agreement
    //    All other cases are invalid
    //
    // Pre-conditions:
    // 1) A CHALLENGE is present with data; AND
    // 2) A RESPONSE is present but empty; AND
    // 3) If the key type is ECC and the key has the SECURE_MESSAGE role, it is Variant A
    // 4) If the key type is RSA or ECC and the key has the SIGNATURE role, it is Variant B
    // 5) If the key type is RSA and the key has the KEY_ESTABLISH role, it is Variant C
    // 6) If the key type is TDEA or AES and the key has the AUTHENTICATE role, it is Variant D
    if (challengeOffset != 0
        && challengeLength != 0
        && responseOffset != 0
        && responseLength == 0) {
      // Variant A - Secure Messaging
      if (isSecureMessagingAuthenticateKey(key)) {
        return generalAuthenticateCase1A((PIVKeyObjectECC) key, challengeOffset, challengeLength);
      }
      // Variant B - Digital Signatures
      else if (key.hasRole(PIVKeyObject.ROLE_SIGN)) {
        if (key instanceof PIVKeyObjectPKI) {
          return generalAuthenticateCase1B((PIVKeyObjectPKI) key, challengeOffset, challengeLength);
        } else {
          authenticateReset();
          PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
          ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
        }
      }
      // Variant C - RSA Key Transport
      else if (key instanceof PIVKeyObjectRSA && key.hasRole(PIVKeyObject.ROLE_KEY_ESTABLISH)) {
        return generalAuthenticateCase1C((PIVKeyObjectRSA) key, challengeOffset, challengeLength);
      } else if (key.hasRole(PIVKeyObject.ROLE_KEY_ESTABLISH)) {
        authenticateReset();
        PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
      }
      // Variant D - Symmetric Internal Authentication
      else if (key.hasRole(PIVKeyObject.ROLE_AUTHENTICATE)) {
        if (key instanceof PIVKeyObjectSYM) {
          return generalAuthenticateCase1D((PIVKeyObjectSYM) key, challengeOffset, challengeLength);
        } else {
          authenticateReset();
          PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
          ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
        }
      }
      // Invalid case
      else {
        authenticateReset();
        PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
    } // Continued below

    //
    // CASE 2 - EXTERNAL AUTHENTICATE REQUEST
    //
    // Description:
    // The client presents a CHALLENGE RESPONSE to the CARD, which then verifies it.
    //
    // Pre-conditions:
    // 1) A CHALLENGE is present but empty; AND
    // 2) The key type is SYMMETRIC
    // 3) The key has the AUTHENTICATE role set; AND
    // 4) The key attribute MUTUAL ONLY is not set

    // The client requests a CHALLENGE from the CARD, which returns the CHALLENGE in plaintext
    else if (challengeOffset != 0 && challengeLength == 0) {
      if (key instanceof PIVKeyObjectSYM) {
        return generalAuthenticateCase2((PIVKeyObjectSYM) key);
      } else {
        authenticateReset();
        PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
      }
    } // Continued below

    //
    // CASE 3 - EXTERNAL AUTHENTICATE RESPONSE
    //
    // Description:
    // The client presents a CHALLENGE RESPONSE to the CARD, which then verifies it.
    // NOTE: This mode does NOT authenticate the card, just the client.
    //
    // Pre-conditions:
    // 1) A RESPONSE is present with data; AND
    // 2) The key type is SYMMETRIC
    // 3) The key has the AUTHENTICATE role set; AND
    // 4) The key attribute MUTUAL ONLY is not set; AND
    // 5) A successful EXTERNAL AUTHENTICATE REQUEST has immediately preceded this command
    else if (responseOffset != 0 && responseLength != 0) {
      if (key instanceof PIVKeyObjectSYM) {
        return generalAuthenticateCase3((PIVKeyObjectSYM) key, responseOffset, responseLength);
      } else {
        authenticateReset();
        PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
      }
    } // Continued below

    //
    // CASE 4 - MUTUAL AUTHENTICATE REQUEST
    //
    // Description:
    // The client requests a WITNESS (a proof of key posession) from the CARD. The card generates
    // the WITNESS, encrypts it and returns it as ciphertext.
    //
    // Pre-Conditions:
    // 1) A WITNESS is present but empty
    // 2) The key has the AUTHENTICATE role set
    //
    else if (witnessOffset != 0 && witnessLength == 0) {
      if (key instanceof PIVKeyObjectSYM) {
        return generalAuthenticateCase4((PIVKeyObjectSYM) key);
      } else {
        authenticateReset();
        PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
      }
    } // Continued below

    //
    // CASE 5 - MUTUAL AUTHENTICATE RESPONSE
    //
    // Description:
    // The client decrypts the received WITNESS, generates a CHALLENGE REQUEST and presents both to
    // the CARD. The card verifies the decrypted WITNESS and encrypts the CHALLENGE, which it then
    // returns as the CHALLENGE RESPONSE.
    //
    // Pre-Conditions:
    // 1) A WITNESS is present with data; AND
    // 2) A CHALLENGE is present with data; AND
    // 3) The key type is SYMMETRIC
    // 4) A successful MUTUAL AUTHENTICATE REQUEST has immediately preceded this command
    else if ((witnessOffset != 0)
        && (witnessLength != 0)
        && (challengeOffset != 0)
        && (challengeLength != 0)) {
      if (key instanceof PIVKeyObjectSYM) {
        return generalAuthenticateCase5(
            (PIVKeyObjectSYM) key, witnessOffset, witnessLength, challengeOffset, challengeLength);
      } else {
        authenticateReset();
        PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
      }
    }

    //
    // CASE 6 - KEY ESTABLISHMENT SCHEME
    //
    // Description:
    // The client supplies a valid ECC public key and the CARD generates a shared secret key.
    //
    // Pre-Conditions:
    // 1) An EXPONENTIATION parameter is present with data
    // 2) The key type is ECC
    // 3) The key has the KEY_ESTABLISH role
    else if (exponentiationOffset != 0 && (exponentiationLength != 0)) {
      if (key instanceof PIVKeyObjectECC) {
        return generalAuthenticateCase6(
            (PIVKeyObjectECC) key, exponentiationOffset, exponentiationLength);
      } else {
        authenticateReset();
        PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
      }
    } // Continued below

    // If any other tag combination is present in the first element of data, it is an invalid case.
    //
    else {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Done
    return ZERO; // Keep compiler happy
  }

  private boolean isSecureMessagingAuthenticateKey(PIVKeyObject key) {
    return key instanceof PIVKeyObjectECC
        && key.getId() == ID_KEY_SECURE_MESSAGING
        && key.getMechanism() == ID_ALG_ECC_SM
        && key.hasRole(PIVKeyObject.ROLE_KEY_ESTABLISH);
  }

  // Variant A - Secure Messaging
  /**
   * OPACITY ZKM key establishment (Part 2 Section 4.1, steps C1–C11).
   *
   * <p>CS2 and CS7 share one path. Sizes follow the ECC field length of the SM key (32-byte field →
   * CS2 / AES-128 / SHA-256; 48-byte field → CS7 / AES-256 / SHA-384) per Section 4.1.4 Table 18.
   */
  private short generalAuthenticateCase1A(
      PIVKeyObjectECC key, short challengeOffset, short challengeLength) {
    authenticateReset();
    secureMessaging.clear();

    if (key.getMechanism() != ID_ALG_ECC_SM) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    // Suite geometry from field length (Table 18).
    final short field = key.getKeyLengthBytes(); // 32 (CS2) or 48 (CS7)
    final short pointLen = (short) (1 + field + field); // uncompressed Q_eH
    final short nLen = (short) (field / 2); // N_ICC
    final short sessionKeyLen = (short) (field - 16); // AES-128 or AES-256
    final short xyLen = (short) (field + field); // Q_eH without leading 0x04

    // Witness: CB_H(1,0x00) || ID_sH(8) || Q_eH
    if (challengeLength != (short) (9 + pointLen)
        || scratch[challengeOffset] != (byte) 0
        || scratch[(short) (challengeOffset + 9)] != PIVCrypto.CONST_EC_POINT_UNCOMPRESSED) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    final short offIdH = ZERO;
    final short offQeh = (short) 8;
    final short offZ = (short) (offQeh + pointLen);
    final short offN = (short) (offZ + field);
    final short offIdSicc = (short) (offN + nLen);

    Util.arrayCopyNonAtomic(scratch, (short) (challengeOffset + 1), smResponse, offIdH, (short) 8);
    Util.arrayCopyNonAtomic(scratch, (short) (challengeOffset + 9), smResponse, offQeh, pointLen);

    if (!key.validatePublicPoint(smResponse, offQeh, pointLen, smResponse, offZ)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    key.keyAgreement(smResponse, offQeh, pointLen, smResponse, offZ, ecPointValidator); // C5
    PIVCrypto.doGenerateRandom(smResponse, offN, nLen); // C6

    // C1: ID_sICC = T_8(SHA-256(C_ICC)) — always SHA-256, both suites
    short cvcLen = key.getSmCvcLength();
    // #if VCI_CS2
    key.getSmCvc(scratch, ZERO);
    PIVCrypto.doSha256(scratch, ZERO, cvcLen, smResponse, offIdSicc);
    // #else
    // CS7 permits SM CVCs larger than the 284-byte scratch buffer. Use the APDU work buffer for
    // this transient copy and clear it immediately after hashing.
    key.getSmCvc(smCommand, ZERO);
    PIVCrypto.doSha256(smCommand, ZERO, cvcLen, smResponse, offIdSicc);
    PIVSecurityProvider.zeroise(smCommand, ZERO, cvcLen);
    // #endif

    // C7: session keys → scratch[0..]; C9: cryptogram overwrites scratch after AESKey load
    opacity.deriveSessionKeys(
        field,
        sessionKeyLen,
        OPACITY_KDF_ALG_ID,
        OPACITY_HASH_TMP,
        offZ,
        offN,
        nLen,
        offIdH,
        offQeh,
        offIdSicc);
    secureMessaging.setSessionKeys(scratch, ZERO, sessionKeyLen);
    PIVSecurityProvider.zeroise(scratch, ZERO, (short) (sessionKeyLen * 4));
    PIVSecurityProvider.zeroise(smResponse, offZ, field);

    short authLen = opacity.buildConfirmationInput(offIdH, offQeh, offIdSicc, xyLen);
    secureMessaging.computeConfirmationMac(scratch, ZERO, authLen, scratch, ZERO);
    secureMessaging.clearConfirmationKey();

    // C11: CB_ICC || N_ICC || AuthCryptogram_ICC(16) || C_ICC
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(smResponse, ZERO, LENGTH_SM_RESPONSE, CONST_TAG_AUTH_TEMPLATE);
    writer.writeTag(CONST_TAG_AUTH_CHALLENGE_RESPONSE);
    writer.writeLength((short) (1 + nLen + 16 + cvcLen));
    short out = writer.getOffset();
    smResponse[out++] = (byte) 0;
    out = Util.arrayCopyNonAtomic(smResponse, offN, smResponse, out, nLen);
    out = Util.arrayCopyNonAtomic(scratch, ZERO, smResponse, out, (short) 16);
    out = key.getSmCvc(smResponse, out);
    writer.setOffset(out);
    short length = writer.finish();

    secureMessaging.markEstablished(
        config.readValue(Config.CONFIG_VCI_MODE) == Config.VCI_MODE_PAIRING_CODE);
    chainBuffer.setOutgoing(smResponse, ZERO, length, true);
    return length;
  }

  // Variant B - Digital Signatures
  private short generalAuthenticateCase1B(
      PIVKeyObjectPKI key, short challengeOffset, short challengeLength) {

    // Reset any other authentication intermediate state prior to any processing
    authenticateReset();

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The CHALLENGE tag length must be the same as our block length
    if (challengeLength != key.getBlockLength()) {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    //
    // IMPLEMENTATION NOTE:
    //
    // Since our input and output data is structured the same way, we make use of the same
    // scratch buffer and perform the cipher in-place. This saves us from using the APDU
    // buffer as a temporary working space and performing an extra copy.
    // We don't know the exact length of the signature until we do it. Since we could be writing
    // a short-form length (ECC) or long-form (RSA), the TLV header could be either 4 or 8 bytes
    // long.
    //
    // The approach is to leave 8 bytes free for the long-form header, then once we know what
    // the actual length is, we go back by the right length to write the header.
    //
    // NOTE:
    // You might be thinking "but if you know the algorithm and key size, you know the length!".
    // You would be right, but unfortunately some implementations put a leading '00' byte in front
    // of their signature data and some don't, so we just wait until we know exactly. It might
    // seem like a pain but it does save an array copy and prevents use of the APDU buffer, so
    // we think it's worth it.
    //

    //
    // MECHANISM CASES:
    // ECC256  - Challenge block is 32 bytes and Signature is 64-70 bytes (single-byte length)
    // ECC384  - Challenge block is 48 bytes and Signature is 96-102 bytes (single-byte length)
    // RSA1024 - Challenge block is 128 bytes and Signature is 128 bytes (double-byte length)
    // RSA2048 - Challenge block is 256 bytes and Signature is 256 bytes (triple-byte length)
    //
    // NOTES:
    // - In all cases, the challenge length must be equal to the key/block length
    // - Given the above cases, if the challenge length is less than 127, we can categorise it
    //   as a TLV short form length.
    // - RSA1024 should not be permitted for this operation, but that should be restricted
    //   using key roles rather than here.

    // DER ECDSA signatures can be a little over twice the digest size because each INTEGER may
    // need a leading zero. RSA signatures remain exactly one block.
    short maximumResponseLength = challengeLength;
    if (key instanceof PIVKeyObjectECC) {
      maximumResponseLength = (short) ((short) (challengeLength * (short) 2) + (short) 8);
    }

    // Construct the TLV response and RESPONSE tag
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(
        scratch,
        ZERO,
        TLVWriter.encodedLength(CONST_TAG_AUTH_CHALLENGE_RESPONSE, maximumResponseLength),
        CONST_TAG_AUTH_TEMPLATE);
    writer.writeTag(CONST_TAG_AUTH_CHALLENGE_RESPONSE);

    short offset = writer.getOffset();
    if (challengeLength <= TLV.LENGTH_1BYTE_MAX) {
      // Single-byte form
      offset += TLV.LENGTH_1BYTE;
    } else if (challengeLength <= TLV.LENGTH_2BYTE_MAX) {
      // Double-byte form
      offset += TLV.LENGTH_2BYTE;
    } else {
      // Triple-byte form
      offset += TLV.LENGTH_3BYTE;
    }

    // Sign the CHALLENGE data to the location specified by 'offset'
    short length;
    try {
      length = key.sign(scratch, challengeOffset, challengeLength, scratch, offset);
    } catch (RuntimeException e) {
      authenticateReset();
      // Presume that we have a problem with the input data, instead of throwing 6F00.
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return ZERO; // Keep static analyser happy
    }

    //
    // The writer object is still pointing to where the length needs to be written, so
    // we can write the length
    //

    writer.writeLength(length);

    // Sanity check that the writer offset is now at the same point we wrote our data. If not,
    // something went wrong in our length estimation! This shouldn't happen.
    if (writer.getOffset() != offset) {
      authenticateReset();
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return ZERO; // Keep static analyser happy
    }

    // Now we can move past the signature data
    writer.move(length);

    // Finalise the TLV object and get the entire data object length
    length = writer.finish();

    // Set up the outgoing command chain
    chainBuffer.setOutgoing(scratch, ZERO, length, true);

    // Done, return the length of data we are sending
    return length;
  }

  // Variant C - RSA Key Transport
  private short generalAuthenticateCase1C(
      PIVKeyObjectRSA key, short challengeOffset, short challengeLength) throws ISOException {

    // Reset any other authentication intermediate state prior to any processing
    authenticateReset();

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The CHALLENGE tag length must be the same as our block length
    if (challengeLength != key.getBlockLength()) {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    //
    // IMPLEMENTATION NOTE:
    //
    // Since our input and output data is structured the same way, we make use of the same
    // scratch buffer and perform the cipher in-place. This saves us from using the APDU
    // buffer as a temporary working space and performing an extra copy.
    // We don't know the exact length of the data until we do it. Since we could be writing
    // a short-form length (ECC) or long-form (RSA), the TLV header could be either 4 or 8 bytes
    // long.
    //
    // The approach is to leave 8 bytes free for the long-form header, then once we know what
    // the actual length is, we go back by the right length to write the header.
    //
    // NOTE:
    // You might be thinking "but if you know the algorithm and key size, you know the length!".
    // You would be right, but unfortunately some implementations put a leading '00' byte in front
    // of their signature data and some don't, so we just wait until we know exactly. It might
    // seem like a pain but it does save an array copy and prevents use of the APDU buffer, so
    // we think it's worth it.
    //

    //
    // MECHANISM CASES:
    // RSA1024 - Challenge block is 128 bytes and Signature is 128 bytes (double-byte length)
    // RSA2048 - Challenge block is 256 bytes and Signature is 256 bytes (triple-byte length)
    //
    // NOTES:
    // - In all cases, the challenge length must be equal to the key/block length
    // - ECC keys are not valid for this case

    // Construct the TLV response and RESPONSE tag
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(
        scratch,
        ZERO,
        TLVWriter.encodedLength(CONST_TAG_AUTH_CHALLENGE_RESPONSE, challengeLength),
        CONST_TAG_AUTH_TEMPLATE);
    writer.writeTag(CONST_TAG_AUTH_CHALLENGE_RESPONSE);

    short offset = writer.getOffset();
    if (challengeLength <= TLV.LENGTH_1BYTE_MAX) {
      // Single-byte form
      offset += TLV.LENGTH_1BYTE;
    } else if (challengeLength <= TLV.LENGTH_2BYTE_MAX) {
      // Double-byte form
      offset += TLV.LENGTH_2BYTE;
    } else {
      // Triple-byte form
      offset += TLV.LENGTH_3BYTE;
    }

    // Decrypt the CHALLENGE data
    short length;
    try {
      length = key.keyAgreement(scratch, challengeOffset, challengeLength, scratch, offset, null);
    } catch (Exception e) {
      authenticateReset();
      // Presume that we have a problem with the input data, instead of throwing 6F00.
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return ZERO; // Keep static analyser happy
    }

    if (length <= ZERO || isAllZero(scratch, offset, length)) {
      authenticateReset();
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return ZERO; // Keep static analyser happy
    }

    //
    // The writer object is still pointing to where the length needs to be written, so
    // we can write the length
    //
    writer.writeLength(length);

    // Sanity check that the writer offset is now at the same point we wrote our data. If not,
    // something went wrong in our length estimation! This shouldn't happen.
    if (writer.getOffset() != offset) {
      authenticateReset();
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return ZERO; // Keep static analyser happy
    }

    // Now we can move past the decrypted data
    writer.move(length);

    // Finalise the TLV object and get the entire data object length
    length = writer.finish();

    // Set up the outgoing command chain
    chainBuffer.setOutgoing(scratch, ZERO, length, true);

    // Done, return the length of data we are sending
    return length;
  }

  private boolean isAllZero(byte[] buffer, short offset, short length) {
    for (short cursor = offset; cursor < (short) (offset + length); cursor++) {
      if (buffer[cursor] != (byte) 0) return false;
    }
    return true;
  }

  // Variant E - Symmetric Internal Authentication
  private short generalAuthenticateCase1D(
      PIVKeyObjectSYM key, short challengeOffset, short challengeLength) throws ISOException {

    // Reset any other authentication intermediate state prior to any processing
    authenticateReset();

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The key MUST have the PERMIT INTERNAL attribute set
    if (!key.hasAttribute(PIVKeyObject.ATTR_PERMIT_INTERNAL)) {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - The CHALLENGE tag length must be the same as our block length
    if (challengeLength != key.getBlockLength()) {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    //
    // IMPLEMENTATION NOTE:
    //
    // Since our input and output data is structured the same way, we make use of the same
    // scratch buffer and perform the cipher in-place. This saves us from using the APDU
    // buffer as a temporary working space and performing an extra copy.
    //

    // Write out the response TLV, passing through the challenge length as an indicative maximum
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(
        scratch,
        ZERO,
        TLVWriter.encodedLength(CONST_TAG_AUTH_CHALLENGE_RESPONSE, challengeLength),
        CONST_TAG_AUTH_TEMPLATE);

    // Create the RESPONSE tag
    writer.writeTag(CONST_TAG_AUTH_CHALLENGE_RESPONSE);
    writer.writeLength(challengeLength);

    // Encrypt the CHALLENGE data
    short offset = writer.getOffset();
    try {
      offset += key.encrypt(scratch, challengeOffset, challengeLength, scratch, offset);
    } catch (RuntimeException e) {
      authenticateReset();

      // Presume that we have a problem with the input data, instead of throwing 6F00.
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Finalise the TLV object and get the entire data object length
    writer.setOffset(offset);
    short length = writer.finish();

    // Set up the outgoing command chain
    chainBuffer.setOutgoing(scratch, ZERO, length, true);

    // Done, return the length of data we are sending
    return length;
  }

  private short generalAuthenticateCase2(PIVKeyObjectSYM key) throws ISOException {

    //
    // CASE 2 - EXTERNAL AUTHENTICATE REQUEST
    // Authenticates the HOST to the CARD
    //

    // > Client application requests a challenge from the PIV Card Application.

    // Reset any other authentication intermediate state
    authenticateReset();

    // Clear any existing authentication state
    cspPIV.clearAuthenticatedKey();

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The key must have the AUTHENTICATE role
    if (!key.hasRole(PIVKeyObject.ROLE_AUTHENTICATE)) {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - The key MUST have the PERMIT EXTERNAL attribute set
    if (!key.hasAttribute(PIVKeyObject.ATTR_PERMIT_EXTERNAL)) {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    short length = key.getBlockLength();

    // Write out the response TLV, passing through the block length as an indicative maximum
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(
        scratch,
        ZERO,
        TLVWriter.encodedLength(CONST_TAG_AUTH_CHALLENGE, length),
        CONST_TAG_AUTH_TEMPLATE);

    // Create the CHALLENGE tag
    writer.writeTag(CONST_TAG_AUTH_CHALLENGE);
    writer.writeLength(key.getBlockLength());

    // Generate the CHALLENGE data and write it to the output buffer
    short offset = writer.getOffset();
    PIVCrypto.doGenerateRandom(scratch, offset, length);

    try {
      // Generate and store the encrypted CHALLENGE in our context, so we can compare it without
      // the key reference later.
      offset +=
          key.encrypt(
              scratch, offset, length, authenticationContext.buffer(), OFFSET_AUTH_CHALLENGE);
    } catch (Exception e) {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);

      // Presume that we have a problem with the input data, instead of throwing 6F00.
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Update the TLV offset value
    writer.setOffset(offset);

    // Finalise the TLV object and get the entire data object length
    length = writer.finish();

    // Set our authentication state to EXTERNAL
    authenticationContext.buffer()[OFFSET_AUTH_STATE] = AUTH_STATE_EXTERNAL;
    authenticationContext.buffer()[OFFSET_AUTH_ID] = key.getId();
    authenticationContext.buffer()[OFFSET_AUTH_MECHANISM] = key.getMechanism();

    // Set up the outgoing command chain
    chainBuffer.setOutgoing(scratch, ZERO, length, true);

    // Done, return the length of data we are sending
    return length;
  }

  private short generalAuthenticateCase3(
      PIVKeyObjectSYM key, short responseOffset, short responseLength) throws ISOException {

    //
    // CASE 3 - EXTERNAL AUTHENTICATE RESPONSE
    //

    // > Client application responds to a challenge from the PIV Card Application.

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - This operation is only valid if the authentication state is EXTERNAL
    if (authenticationContext.buffer()[OFFSET_AUTH_STATE] != AUTH_STATE_EXTERNAL) {
      // Invalid state for this command
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - This operation is only valid if the key and mechanism have not changed
    if (authenticationContext.buffer()[OFFSET_AUTH_ID] != key.getId()
        || authenticationContext.buffer()[OFFSET_AUTH_MECHANISM] != key.getMechanism()) {
      // Invalid state for this command
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 3 - The RESPONSE tag length must be the same as our block length
    if (responseLength != key.getBlockLength()) {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Compare the authentication statuses
    if (!PIVSecurityProvider.arrayEqualsConstantTime(
        scratch,
        responseOffset,
        authenticationContext.buffer(),
        OFFSET_AUTH_CHALLENGE,
        responseLength)) {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // We are now authenticated. Set the key's security status
    cspPIV.setAuthenticatedKey(key.getId());

    // Reset our authentication state
    authenticateReset();
    PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);

    // Done, no data to return
    return ZERO;
  }

  private short generalAuthenticateCase4(PIVKeyObjectSYM key) throws ISOException {

    //
    // CASE 4 - MUTUAL AUTHENTICATE REQUEST
    //

    // > Client application requests a WITNESS from the PIV Card Application.

    // Reset any other authentication intermediate state
    authenticateReset();

    // Clear any existing authentication state
    cspPIV.clearAuthenticatedKey();

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The key must have the correct role
    if (!key.hasRole(PIVKeyObject.ROLE_AUTHENTICATE)) {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - The key MUST have the PERMIT MUTUAL attribute set
    if (!key.hasAttribute(PIVKeyObject.ATTR_PERMIT_MUTUAL)) {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    //
    // EXECUTION STEPS
    //

    // < PIV Card Application returns a WITNESS that is created by generating random
    //   data and encrypting it using the referenced key

    // Generate a block length worth of WITNESS data
    short length = key.getBlockLength();
    PIVCrypto.doGenerateRandom(authenticationContext.buffer(), OFFSET_AUTH_CHALLENGE, length);

    // Write out the response TLV, passing through the block length as an indicative maximum
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(
        scratch,
        ZERO,
        TLVWriter.encodedLength(CONST_TAG_AUTH_WITNESS, length),
        CONST_TAG_AUTH_TEMPLATE);

    // Create the WITNESS tag
    writer.writeTag(CONST_TAG_AUTH_WITNESS);
    writer.writeLength(length);

    // Encrypt the WITNESS data and write it to the output buffer
    short offset = writer.getOffset();
    offset +=
        key.encrypt(authenticationContext.buffer(), OFFSET_AUTH_CHALLENGE, length, scratch, offset);
    writer.setOffset(offset); // Update the TLV offset value

    // Finalise the TLV object and get the entire data object length
    length = writer.finish();

    // Update our authentication status, id and mechanism
    authenticationContext.buffer()[OFFSET_AUTH_STATE] = AUTH_STATE_MUTUAL;
    authenticationContext.buffer()[OFFSET_AUTH_ID] = key.getId();
    authenticationContext.buffer()[OFFSET_AUTH_MECHANISM] = key.getMechanism();

    // Set up the outgoing command chain
    chainBuffer.setOutgoing(scratch, ZERO, length, true);

    // Done, return the length of data we are sending
    return length;
  }

  private short generalAuthenticateCase5(
      PIVKeyObjectSYM key,
      short witnessOffset,
      short witnessLength,
      short challengeOffset,
      short challengeLength)
      throws ISOException {

    //
    // CASE 5 - MUTUAL AUTHENTICATE RESPONSE
    //

    //
    // PRE-CONDITIONS
    //

    // < PIV Card Application authenticates the client application by verifying the decrypted
    // witness.

    // PRE-CONDITION 1 - This operation is only valid if the authentication state is MUTUAL
    if (authenticationContext.buffer()[OFFSET_AUTH_STATE] != AUTH_STATE_MUTUAL) {
      // Invalid state for this command
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - This operation is only valid if the key and mechanism have not changed
    if (authenticationContext.buffer()[OFFSET_AUTH_ID] != key.getId()
        || authenticationContext.buffer()[OFFSET_AUTH_MECHANISM] != key.getMechanism()) {
      // Invalid state for this command
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 3 - The WITNESS tag length must be the same as our block length
    if (witnessLength != key.getBlockLength()) {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 4 - The CHALLENGE tag length must be equal to the witness length
    if (challengeLength != witnessLength) {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Compare the authentication statuses
    if (!PIVSecurityProvider.arrayEqualsConstantTime(
        scratch,
        witnessOffset,
        authenticationContext.buffer(),
        OFFSET_AUTH_CHALLENGE,
        witnessLength)) {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // NOTE: The WITNESS is now verified, on to the CHALLENGE

    // > Client application requests encryption of CHALLENGE data from the card using the
    // > same key.

    // Write out the response TLV, passing through the block length as an indicative maximum
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(
        scratch,
        ZERO,
        TLVWriter.encodedLength(CONST_TAG_AUTH_CHALLENGE_RESPONSE, challengeLength),
        CONST_TAG_AUTH_TEMPLATE);

    // Create the RESPONSE tag
    writer.writeTag(CONST_TAG_AUTH_CHALLENGE_RESPONSE);
    writer.writeLength(challengeLength);
    short offset = writer.getOffset();

    // Encrypt the CHALLENGE data
    offset += key.encrypt(scratch, challengeOffset, challengeLength, scratch, offset);

    // Update the TLV offset value
    writer.setOffset(offset);

    // Finalise the TLV object and get the entire data object length
    short length = writer.finish();

    // Set this key's authentication state
    cspPIV.setAuthenticatedKey(key.getId());

    // Clear our authentication state
    authenticateReset();

    // Set up the outgoing command chain
    chainBuffer.setOutgoing(scratch, ZERO, length, true);

    // < PIV Card Application indicates successful authentication and sends back the encrypted
    // challenge.
    return length;
  }

  private short generalAuthenticateCase6(
      PIVKeyObjectECC key, short exponentiationOffset, short exponentiationLength)
      throws ISOException {

    //
    // CASE 6 - EXPONENTIATION AUTHENTICATE RESPONSE
    //

    // > Client application returns the ECDH derived shared secret

    // Reset any other authentication intermediate state
    authenticateReset();

    // PRE-CONDITION 1 - The key must have the correct role
    if (!key.hasRole(PIVKeyObject.ROLE_KEY_ESTABLISH)) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - The EXPONENTIATION tag length must be the same as our block length
    // TODO: Should put this into the PIVKeyObjectECC class
    short length = (short) (key.getBlockLength() * (short) 2 + (short) 1);
    if (exponentiationLength != length) {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Write out the response TLV, passing through the block length as an indicative maximum
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(
        scratch,
        ZERO,
        TLVWriter.encodedLength(CONST_TAG_AUTH_CHALLENGE_RESPONSE, key.getKeyLengthBytes()),
        CONST_TAG_AUTH_TEMPLATE);

    // Create the RESPONSE tag
    writer.writeTag(CONST_TAG_AUTH_CHALLENGE_RESPONSE);
    writer.writeLength(key.getKeyLengthBytes());

    // Compute the shared secret
    length =
        key.keyAgreement(
            scratch,
            exponentiationOffset,
            exponentiationLength,
            scratch,
            writer.getOffset(),
            ecPointValidator);

    // Move to the end of the key agreement output data
    writer.move(length);

    // Finalise the TLV object and get the entire data object length
    length = writer.finish();

    // Set up the outgoing command chain
    chainBuffer.setOutgoing(scratch, ZERO, length, true);

    // < PIV Card Application indicates successful authentication and sends back the encrypted
    // challenge.
    return length;
  }

  /**
   * The GENERATE ASYMMETRIC KEY PAIR card command initiates the generation and storing in the card
   * of the reference data of an asymmetric key pair, i.e., a public key and a private key. The
   * public key of the generated key pair is returned as the response to the command. If there is
   * reference data currently associated with the key reference, it is replaced in full by the
   * generated data.
   *
   * @param buffer The incoming APDU buffer
   * @param offset The offset of the CDATA element
   * @return The length of the return data
   */
  short generateAsymmetricKeyPair(byte[] buffer, short offset) throws ISOException {

    // Request Elements
    final byte CONST_TAG_TEMPLATE = (byte) 0xAC;
    final byte CONST_TAG_MECHANISM = (byte) 0x80;

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The 'TEMPLATE' tag must be present in the supplied buffer
    if (buffer[offset++] != CONST_TAG_TEMPLATE) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Skip the length byte
    offset++;

    // PRE-CONDITION 2 - The 'MECHANISM' tag must be present in the supplied buffer
    if (buffer[offset++] != CONST_TAG_MECHANISM) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 3 - The 'MECHANISM' tag must have a length of 1
    if (buffer[offset++] != (short) 1) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    //
    // NOTE: We ignore the existence of the 'PARAMETER' tag, because according to SP800-78-4 the
    // RSA public exponent is now fixed to 65537 (Section 3.1 PIV Cryptographic Keys).
    // ECC keys have no parameter.

    // PRE-CONDITION 4A - F9 is the imported attestation authority and must never be generated.
    if (buffer[ISO7816.OFFSET_P2] == ID_KEY_ATTESTATION) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    // PRE-CONDITION 4B - The key reference and mechanism must exist (key test)
    if (!cspPIV.keyExists(buffer[ISO7816.OFFSET_P2])) {
      // The key reference is bad
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    // PRE-CONDITION 4C - The key reference and mechanism must exist (mechanism test)
    PIVKeyObject key = cspPIV.selectKey(buffer[ISO7816.OFFSET_P2], buffer[offset]);
    if (key == null) {
      // NOTE: The error message we return here is different dependant on whether the key is bad
      // (6A86), or the mechanism is bad (6A80) (See SP800-73-4 3.3.2 Generate Asymmetric Key pair).
      // The mechanism is bad
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 5 - The key must be an asymmetric key (key pair)
    if (!(key instanceof PIVKeyObjectPKI)) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      return ZERO; // Keep static analyser happy
    }

    // PRE-CONDITION 6 - The access rules must be satisfied for administrative access
    if (!cspPIV.checkAccessModeAdmin(key, owner.isVciSatisfied())) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    //
    // EXECUTION STEPS
    //

    // STEP 1 - Generate the key pair
    PIVKeyObjectPKI keyPair = (PIVKeyObjectPKI) key;
    short length = keyPair.generate(scratch, ZERO);
    keyPair.markGenerated();

    chainBuffer.setOutgoing(scratch, ZERO, length, true);

    // Done, return the length of the object we are writing back
    return length;
  }

  // #if ATTESTATION_ENABLED
  /**
   * Builds an attestation certificate for an on-card generated key.
   *
   * <p>Pre-conditions:
   *
   * <p>- {@code slot} must be one of the standard PIV authentication/signature/key-management slots
   * or retired key-management slots.
   *
   * <p>- F9 must be an active imported P-256 attestation authority.
   *
   * <p>- The target key must exist, be generated on-card, and satisfy its configured contact or
   * contactless access policy. This intentionally makes ATTEST obey the same interface restrictions
   * as ordinary object use, even though some vendor implementations expose attestation
   * unauthenticated.
   *
   * <p>Status words: {@code 6A86} for invalid attestation slots, {@code 6985} when the authority or
   * target state is incomplete, {@code 6A88} when the target key does not exist, and {@code 6982}
   * when target access policy is not satisfied.
   *
   * @param slot The PIV key reference to attest
   */
  void attest(byte slot) {
    if (!isAttestableSlot(slot)) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    PIVKeyObjectECC authority =
        (PIVKeyObjectECC) cspPIV.selectKey(ID_KEY_ATTESTATION, ID_ALG_ECC_P256);
    if (authority == null || !attestation.isAuthorityActive()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    PIVKeyObjectPKI target = selectAttestableTarget(slot);
    if (target == null) {
      ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
    }
    if (!cspPIV.checkAccessModeObject(target, owner.isVciSatisfied())) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PIVAttestation enforces generated-key origin. Imported keys may be valid PIV keys, but the
    // applet cannot truthfully attest that it generated or protected their origin.
    short length =
        attestation.buildCertificate(authority, target, slot, scratch, attestationResponse, ZERO);
    chainBuffer.setOutgoing(attestationResponse, ZERO, length, true);
  }

  private PIVKeyObjectPKI selectAttestableTarget(byte slot) {
    PIVKeyObject target = cspPIV.selectKey(slot);
    if (target instanceof PIVKeyObjectPKI) return (PIVKeyObjectPKI) target;
    return null;
  }

  /**
   * Returns true for PIV slots that may carry generated PKI keys eligible for attestation.
   *
   * <p>F9 is deliberately excluded because it is the attestation authority itself, not an
   * attestable target.
   */
  private static boolean isAttestableSlot(byte slot) {
    if (slot == (byte) 0x9A || slot == (byte) 0x9C || slot == (byte) 0x9D || slot == (byte) 0x9E) {
      return true;
    }
    return slot >= (byte) 0x82 && slot <= (byte) 0x95;
  }
  // #endif
}
