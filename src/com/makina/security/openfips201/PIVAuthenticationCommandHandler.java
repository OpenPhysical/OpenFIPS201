/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2017 Commonwealth of Australia
 ******************************************************************************/

package com.makina.security.openfips201;

import static com.makina.security.openfips201.PIV.*;

import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.CryptoException;

/** Handles GENERAL AUTHENTICATE, OPACITY dispatch, and asymmetric key generation. */
final class PIVAuthenticationCommandHandler {
  private final PIV owner;
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
          ,
      PIVAttestation attestation
      // #endif
      ) {
    this.owner = owner;
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
    this.attestationResponse = attestation.getResponseBuffer();
    // #endif
  }

  private void authenticateReset() throws ISOException {
    authenticationContext.reset();
  }

  /** Clears all authentication state and scratch data before returning a failing status word. */
  private void failAuthentication(short statusWord) {
    authenticateReset();
    PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
    ISOException.throwIt(statusWord);
  }

  /**
   * Abandons a failed GENERAL AUTHENTICATE: discards any pending challenge or witness, sets the
   * security status of the referenced key to FALSE, and wipes the scratch buffer.
   *
   * @param keyReference The key reference (P2) of the failed command
   */
  private void abandonAuthentication(byte keyReference) {
    authenticateReset();
    cspPIV.clearAuthenticatedKey(keyReference);
    PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
  }

  /**
   * The GENERAL AUTHENTICATE card command performs a cryptographic operation, such as an
   * authentication protocol, using the data provided in the data field of the command and returns
   * the result of the cryptographic operation in the response data field.
   *
   * <p>SP 800-73-5 Part 2 Section 2.4.2: "An aborted or failed execution of an authentication
   * protocol SHALL set the security status indicator associated with the credential used in the
   * protocol to FALSE." Every failing command therefore abandons the exchange through {@link
   * #abandonAuthentication(byte)}, so a pending challenge or witness is accepted only by the
   * command that immediately follows its request, and an earlier authentication of the same key
   * does not survive a failed step. A provider {@code CryptoException} is reported as {@code 6A80},
   * the only data-field error status Section 3.2.4 defines for this command.
   *
   * @param buffer The incoming APDU buffer
   * @param offset The offset of the CDATA element
   * @param length The length of the CDATA element
   * @return The length of the return data
   */
  short generalAuthenticate(byte[] buffer, short offset, short length) throws ISOException {
    try {
      return processGeneralAuthenticate(buffer, offset, length);
    } catch (CryptoException e) {
      abandonAuthentication(buffer[ISO7816.OFFSET_P2]);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return ZERO; // Keep compiler happy
    } catch (CardRuntimeException e) {
      abandonAuthentication(buffer[ISO7816.OFFSET_P2]);
      throw e;
    }
  }

  private short processGeneralAuthenticate(byte[] buffer, short offset, short length)
      throws ISOException {

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
      // NIST SP 800-73-5 Part 2, Section 3.2.4 and its response table define an unsupported P2 or
      // algorithm/key-reference combination as 6A86 for GENERAL AUTHENTICATE. VERIFY has a
      // different command-specific 6A88 rule; it does not apply here.
      cspPIV.clearPINAlways();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      return ZERO; // Keep compiler happy
    }

    // PRE-CONDITION 3 - The access rules must be satisfied for the requested key
    // NOTE: A call to this method automatically clears the PIN ALWAYS status.
    if (!cspPIV.checkAccessModeObject(key, owner.isVciSatisfied(), owner.isGlobalPinAdvertised())) {
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

    // PRE-CONDITION 5 - SP 800-73-5 Part 2 Section 3.2.4 defines the data field as the dynamic
    // authentication template, "See Table 7", and Table 7 lists its only data objects: Witness
    // '80', Challenge '81', Response '82' and Exponentiation '85'. The template must occupy the
    // whole data field, and each Table 7 object may appear at most once, so that one byte string
    // has exactly one interpretation. Anything else is "Incorrect parameter in command data field".
    if (scratch[ZERO] != CONST_TAG_AUTH_TEMPLATE
        || TLV.objectEnd(scratch, ZERO, length, false) != length) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return ZERO; // Keep compiler happy
    }

    //
    // EXECUTION STEPS
    //

    //
    // STEP 1 - Record the offset and length of each Table 7 object. Every child value starts after
    // the template header, so an offset of zero means the object is absent.
    //
    short challengeOffset = ZERO;
    short witnessOffset = ZERO;
    short responseOffset = ZERO;
    short exponentiationOffset = ZERO;

    short challengeLength = ZERO;
    short witnessLength = ZERO;
    short responseLength = ZERO;
    short exponentiationLength = ZERO;

    offset = TLV.dataOffset(scratch, ZERO, length, false);
    while (offset < length) {
      short valueOffset = TLV.dataOffset(scratch, offset, length, false);
      short valueLength = TLV.readLength(scratch, offset, length, false);
      switch (scratch[offset]) {
        case CONST_TAG_AUTH_WITNESS:
          if (witnessOffset != ZERO) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
          witnessOffset = valueOffset;
          witnessLength = valueLength;
          break;
        case CONST_TAG_AUTH_CHALLENGE:
          if (challengeOffset != ZERO) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
          challengeOffset = valueOffset;
          challengeLength = valueLength;
          break;
        case CONST_TAG_AUTH_CHALLENGE_RESPONSE:
          if (responseOffset != ZERO) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
          responseOffset = valueOffset;
          responseLength = valueLength;
          break;
        case CONST_TAG_AUTH_EXPONENTIATION:
          if (exponentiationOffset != ZERO) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
          exponentiationOffset = valueOffset;
          exponentiationLength = valueLength;
          break;
        default:
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
      offset = TLV.objectEnd(scratch, offset, length, false);
    }

    // Presence of each object, for the exact combinations that select an authentication case.
    final boolean witness = witnessOffset != ZERO;
    final boolean challenge = challengeOffset != ZERO;
    final boolean response = responseOffset != ZERO;
    final boolean exponentiation = exponentiationOffset != ZERO;

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
    // 7) No WITNESS or EXPONENTIATION is present (a WITNESS with data selects Case 5)
    if (challenge
        && challengeLength != 0
        && response
        && responseLength == 0
        && !witness
        && !exponentiation) {
      // Variant A - Secure Messaging
      if (isSecureMessagingAuthenticateKey(key)) {
        return generalAuthenticateCase1A((PIVKeyObjectECC) key, challengeOffset, challengeLength);
      }
      // Variant B - Digital Signatures
      else if (key.hasRole(PIVKeyObject.ROLE_SIGN)) {
        if (key instanceof PIVKeyObjectPKI) {
          return generalAuthenticateCase1B((PIVKeyObjectPKI) key, challengeOffset, challengeLength);
        } else {
          failAuthentication(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
        }
      }
      // Variant C - RSA Key Transport
      else if (key instanceof PIVKeyObjectRSA && key.hasRole(PIVKeyObject.ROLE_KEY_ESTABLISH)) {
        return generalAuthenticateCase1C((PIVKeyObjectRSA) key, challengeOffset, challengeLength);
      } else if (key.hasRole(PIVKeyObject.ROLE_KEY_ESTABLISH)) {
        failAuthentication(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
      }
      // Variant D - Symmetric Internal Authentication
      else if (key.hasRole(PIVKeyObject.ROLE_AUTHENTICATE)) {
        if (key instanceof PIVKeyObjectSYM) {
          return generalAuthenticateCase1D((PIVKeyObjectSYM) key, challengeOffset, challengeLength);
        } else {
          failAuthentication(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
        }
      }
      // Invalid case
      else {
        failAuthentication(ISO7816.SW_WRONG_DATA);
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
    // 4) The key attribute MUTUAL ONLY is not set; AND
    // 5) No other object is present

    // The client requests a CHALLENGE from the CARD, which returns the CHALLENGE in plaintext
    else if (challenge && challengeLength == 0 && !witness && !response && !exponentiation) {
      if (key instanceof PIVKeyObjectSYM) {
        return generalAuthenticateCase2((PIVKeyObjectSYM) key);
      } else {
        failAuthentication(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
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
    // 5) A successful EXTERNAL AUTHENTICATE REQUEST has immediately preceded this command; AND
    // 6) No other object is present
    else if (response && responseLength != 0 && !witness && !challenge && !exponentiation) {
      if (key instanceof PIVKeyObjectSYM) {
        return generalAuthenticateCase3((PIVKeyObjectSYM) key, responseOffset, responseLength);
      } else {
        failAuthentication(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
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
    // 2) The key has the AUTHENTICATE role set; AND
    // 3) No RESPONSE or EXPONENTIATION is present, and any CHALLENGE is empty
    //
    else if (witness
        && witnessLength == 0
        && !response
        && !exponentiation
        && (!challenge || challengeLength == 0)) {
      if (key instanceof PIVKeyObjectSYM) {
        return generalAuthenticateCase4((PIVKeyObjectSYM) key);
      } else {
        failAuthentication(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
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
    // 4) A successful MUTUAL AUTHENTICATE REQUEST has immediately preceded this command; AND
    // 5) Any RESPONSE is empty and no EXPONENTIATION is present. SP 800-73-5 Part 2 Appendix A.2,
    //    Table 23 sends this step as '7C … 80 … 81 … 82 00'; the empty Response requests the
    //    encrypted challenge.
    else if (witness
        && witnessLength != 0
        && challenge
        && challengeLength != 0
        && (!response || responseLength == 0)
        && !exponentiation) {
      if (key instanceof PIVKeyObjectSYM) {
        return generalAuthenticateCase5(
            (PIVKeyObjectSYM) key, witnessOffset, witnessLength, challengeOffset, challengeLength);
      } else {
        failAuthentication(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
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
    // 3) The key has the KEY_ESTABLISH role; AND
    // 4) Any RESPONSE is empty and no WITNESS or CHALLENGE is present
    else if (exponentiation
        && exponentiationLength != 0
        && (!response || responseLength == 0)
        && !witness
        && !challenge) {
      if (key instanceof PIVKeyObjectECC) {
        return generalAuthenticateCase6(
            (PIVKeyObjectECC) key, exponentiationOffset, exponentiationLength);
      } else {
        failAuthentication(ISO7816.SW_INCORRECT_P1P2); // The supplied key is incorrect
      }
    } // Continued below

    // If any other tag combination is present in the first element of data, it is an invalid case.
    //
    else {
      failAuthentication(ISO7816.SW_WRONG_DATA);
    }

    // Done
    return ZERO; // Keep compiler happy
  }

  /**
   * Returns whether the identifier names an asymmetric key-pair mechanism of SP 800-78-5 Table 9
   * (RSA '05', '06', '07'; ECC '11', '14'; secure-messaging cipher suites '27', '2E').
   */
  private static boolean isAsymmetricMechanism(byte mechanism) {
    switch (mechanism) {
      case ID_ALG_RSA_1024:
      case ID_ALG_RSA_2048:
      case ID_ALG_RSA_3072:
      case ID_ALG_ECC_P256:
      case ID_ALG_ECC_P384:
      case ID_ALG_ECC_CS2:
      case ID_ALG_ECC_CS7:
        return true;
      default:
        return false;
    }
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
    boolean completed = false;
    try {
      short length = establishOpacity(key, challengeOffset, challengeLength);
      completed = true;
      return length;
    } finally {
      // SP 800-73-5 Part 2 Table 16 C8 and Section 4.3: failed establishment must
      // destroy Z, partial key bundles, and any keys loaded before the provider failed.
      if (!completed) owner.clearSecureMessaging();
    }
  }

  private short establishOpacity(
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

    // Challenge: CB_H(1) || ID_sH(8) || Q_eH. Table 16 C2: "CB_ICC = CB_H & 'F0'", which
    // indicates "that persistent binding has not been used in the transaction even if CB_H
    // indicates that the client application supports it"; C3: "Return an error ('6A 80') if
    // CB_ICC is not 0x00." The encoding of Q_eH is checked by the canonical point validator (C4).
    final byte hostControlByte = scratch[challengeOffset];
    if (challengeLength != (short) (9 + pointLen)
        || (byte) (hostControlByte & (byte) 0xF0) != (byte) 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    final short offIdH = ZERO;
    final short offQeh = (short) 8;
    final short offZ = (short) (offQeh + pointLen);
    final short offN = (short) (offZ + field);
    final short offIdSicc = (short) (offN + nLen);

    Util.arrayCopyNonAtomic(scratch, (short) (challengeOffset + 1), smResponse, offIdH, (short) 8);
    Util.arrayCopyNonAtomic(scratch, (short) (challengeOffset + 9), smResponse, offQeh, pointLen);

    // SP 800-73-5 Part 2 Section 4.1, step C4 is enforced by the single canonical validator
    // inside keyAgreement(). Keeping validation there prevents OPACITY and generic ECDH from
    // drifting into different curve checks.
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
        offIdSicc,
        hostControlByte);
    secureMessaging.setSessionKeys(scratch, ZERO, sessionKeyLen);
    PIVSecurityProvider.zeroise(scratch, ZERO, (short) (sessionKeyLen * 4));
    PIVSecurityProvider.zeroise(smResponse, offZ, field);

    short authLen = opacity.buildConfirmationInput(offIdH, offQeh, offIdSicc, xyLen);
    secureMessaging.computeConfirmationMac(scratch, ZERO, authLen, scratch, ZERO);
    secureMessaging.clearConfirmationKey();

    // C11: CB_ICC || N_ICC || AuthCryptogram_ICC(16) || C_ICC. The template length is exact so
    // that both lengths take the shortest form (ISO/IEC 7816-4 Section 6.3 recommends "the
    // shortest possible coding of the length field, according to DER encoding rules").
    final short responseLength = (short) (1 + nLen + 16 + cvcLen);
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(
        smResponse,
        ZERO,
        TLVWriter.encodedLength(CONST_TAG_AUTH_CHALLENGE_RESPONSE, responseLength),
        CONST_TAG_AUTH_TEMPLATE);
    writer.writeTag(CONST_TAG_AUTH_CHALLENGE_RESPONSE);
    writer.writeLength(responseLength);
    short out = writer.getOffset();
    smResponse[out++] = (byte) (hostControlByte & (byte) 0xF0); // CB_ICC, 0x00 by C3
    out = Util.arrayCopyNonAtomic(smResponse, offN, smResponse, out, nLen);
    out = Util.arrayCopyNonAtomic(scratch, ZERO, smResponse, out, (short) 16);
    out = key.getSmCvc(smResponse, out);
    writer.setOffset(out);
    short length = writer.finish();

    // SP 800-73-5 Part 1, Table 2 footnote 9 binds VCI pairing to the issuer's
    // stored Discovery policy, not merely to a mutable implementation setting.
    secureMessaging.markEstablished(owner.isDiscoveryPairingRequired());
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

    TLVWriter writer = TLVWriter.getInstance();
    short offset = beginChallengeResponse(writer, maximumResponseLength);

    // Sign the CHALLENGE data to the location specified by 'offset'
    short length;
    try {
      length = key.sign(scratch, challengeOffset, challengeLength, scratch, offset);
    } catch (ISOException e) {
      authenticateReset();
      throw e;
    } catch (CryptoException e) {
      authenticateReset();
      // A provider-level failure means the supplied cryptogram cannot be processed. Deliberate
      // ISOException status words from the key implementation are preserved by the prior catch.
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return ZERO; // Keep static analyser happy
    }

    length = finishChallengeResponse(writer, offset, length);

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

    // The raw RSA result is written in place after reserving its exact BER length field.
    TLVWriter writer = TLVWriter.getInstance();
    short offset = beginChallengeResponse(writer, challengeLength);

    // Decrypt the CHALLENGE data
    short length;
    try {
      length = key.keyAgreement(scratch, challengeOffset, challengeLength, scratch, offset, null);
    } catch (ISOException e) {
      authenticateReset();
      throw e;
    } catch (CryptoException e) {
      authenticateReset();
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return ZERO; // Keep static analyser happy
    }

    if (length <= ZERO || isAllZero(scratch, offset, length)) {
      authenticateReset();
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return ZERO; // Keep static analyser happy
    }

    length = finishChallengeResponse(writer, offset, length);

    // Set up the outgoing command chain
    chainBuffer.setOutgoing(scratch, ZERO, length, true);

    // Done, return the length of data we are sending
    return length;
  }

  /** Starts a dynamic-authentication response and reserves its BER length field. */
  private short beginChallengeResponse(TLVWriter writer, short maximumValueLength) {
    writer.init(
        scratch,
        ZERO,
        TLVWriter.encodedLength(CONST_TAG_AUTH_CHALLENGE_RESPONSE, maximumValueLength),
        CONST_TAG_AUTH_TEMPLATE);
    writer.writeTag(CONST_TAG_AUTH_CHALLENGE_RESPONSE);
    short valueOffset = writer.getOffset();
    if (maximumValueLength <= TLV.LENGTH_1BYTE_MAX) {
      return (short) (valueOffset + TLV.LENGTH_1BYTE);
    }
    if (maximumValueLength <= TLV.LENGTH_2BYTE_MAX) {
      return (short) (valueOffset + TLV.LENGTH_2BYTE);
    }
    return (short) (valueOffset + TLV.LENGTH_3BYTE);
  }

  /** Writes the actual value length and closes the dynamic-authentication template. */
  private short finishChallengeResponse(TLVWriter writer, short valueOffset, short valueLength) {
    writer.writeLength(valueLength);
    if (writer.getOffset() != valueOffset) {
      authenticateReset();
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return ZERO;
    }
    writer.move(valueLength);
    return writer.finish();
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

    // Respond with the enciphered CHALLENGE as 7C { 82 <block> }
    return sendEncipheredBlock(
        CONST_TAG_AUTH_CHALLENGE_RESPONSE, key, scratch, challengeOffset, challengeLength);
  }

  /**
   * Builds and queues the symmetric dynamic-authentication response {@code 7C { tag L E(K, in) }}
   * in the scratch buffer. Failures propagate to {@link #generalAuthenticate}, which abandons the
   * exchange.
   *
   * <p>JCAPI 3.0.5 {@code Cipher.doFinal}: "if inBuff and outBuff are the same array, then the
   * output data area must not partially overlap the input data area such that the input data is
   * modified before it is used". An input block held in scratch is therefore first moved to the
   * output position and enciphered in place.
   *
   * @param tag The response element tag
   * @param key The symmetric key to encipher with
   * @param in The buffer holding the single input block
   * @param inOffset The offset of the input block
   * @param inLength The length of the input block, equal to the key's block length
   * @return The length of the queued response
   */
  private short sendEncipheredBlock(
      byte tag, PIVKeyObjectSYM key, byte[] in, short inOffset, short inLength) {
    TLVWriter writer = TLVWriter.getInstance();
    writer.init(scratch, ZERO, TLVWriter.encodedLength(tag, inLength), CONST_TAG_AUTH_TEMPLATE);
    writer.writeTag(tag);
    writer.writeLength(inLength);
    short offset = writer.getOffset();
    if (in == scratch && inOffset != offset) {
      Util.arrayCopyNonAtomic(scratch, inOffset, scratch, offset, inLength);
      inOffset = offset;
    }
    writer.setOffset((short) (offset + key.encrypt(in, inOffset, inLength, scratch, offset)));
    short length = writer.finish();
    chainBuffer.setOutgoing(scratch, ZERO, length, true);
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
      failAuthentication(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
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
    } catch (ISOException e) {
      authenticateReset();
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      throw e;
    } catch (CryptoException e) {
      failAuthentication(ISO7816.SW_WRONG_DATA);
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
      failAuthentication(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - This operation is only valid if the key and mechanism have not changed
    if (authenticationContext.buffer()[OFFSET_AUTH_ID] != key.getId()
        || authenticationContext.buffer()[OFFSET_AUTH_MECHANISM] != key.getMechanism()) {
      // Invalid state for this command
      failAuthentication(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 3 - The RESPONSE tag length must be the same as our block length
    if (responseLength != key.getBlockLength()) {
      failAuthentication(ISO7816.SW_WRONG_DATA);
    }

    // Compare the authentication statuses
    if (!PIVSecurityProvider.arrayEqualsConstantTime(
        scratch,
        responseOffset,
        authenticationContext.buffer(),
        OFFSET_AUTH_CHALLENGE,
        responseLength)) {
      failAuthentication(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
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

    // Respond with the enciphered WITNESS as 7C { 80 <block> }
    length =
        sendEncipheredBlock(
            CONST_TAG_AUTH_WITNESS,
            key,
            authenticationContext.buffer(),
            OFFSET_AUTH_CHALLENGE,
            length);

    // Update our authentication status, id and mechanism
    authenticationContext.buffer()[OFFSET_AUTH_STATE] = AUTH_STATE_MUTUAL;
    authenticationContext.buffer()[OFFSET_AUTH_ID] = key.getId();
    authenticationContext.buffer()[OFFSET_AUTH_MECHANISM] = key.getMechanism();

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
      failAuthentication(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - This operation is only valid if the key and mechanism have not changed
    if (authenticationContext.buffer()[OFFSET_AUTH_ID] != key.getId()
        || authenticationContext.buffer()[OFFSET_AUTH_MECHANISM] != key.getMechanism()) {
      // Invalid state for this command
      failAuthentication(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 3 - The WITNESS tag length must be the same as our block length
    if (witnessLength != key.getBlockLength()) {
      failAuthentication(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 4 - The CHALLENGE tag length must be equal to the witness length
    if (challengeLength != witnessLength) {
      failAuthentication(ISO7816.SW_WRONG_DATA);
    }

    // Compare the authentication statuses
    if (!PIVSecurityProvider.arrayEqualsConstantTime(
        scratch,
        witnessOffset,
        authenticationContext.buffer(),
        OFFSET_AUTH_CHALLENGE,
        witnessLength)) {
      failAuthentication(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // NOTE: The WITNESS is now verified, on to the CHALLENGE

    // > Client application requests encryption of CHALLENGE data from the card using the
    // > same key.
    short length =
        sendEncipheredBlock(
            CONST_TAG_AUTH_CHALLENGE_RESPONSE, key, scratch, challengeOffset, challengeLength);

    // Set this key's authentication state
    cspPIV.setAuthenticatedKey(key.getId());

    // Clear our authentication state
    authenticateReset();

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

    // SP 800-73-5 Part 2 Section 4.1 assigns key 04 exclusively to OPACITY secure-messaging
    // establishment. The generic ECDH exponentiation form is for key-management keys.
    if (key.getId() == PIV.ID_KEY_SECURE_MESSAGING) {
      PIVSecurityProvider.zeroise(scratch, ZERO, LENGTH_SCRATCH);
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    // PRE-CONDITION 1 - The key must have the correct role
    if (!key.hasRole(PIVKeyObject.ROLE_KEY_ESTABLISH)) {
      failAuthentication(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION 2 - The EXPONENTIATION tag must carry an uncompressed point on the key's curve
    short length = ECPointValidator.encodedLength(key.getKeyLengthBytes());
    if (exponentiationLength != length) {
      failAuthentication(ISO7816.SW_WRONG_DATA);
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
   * @param length The length of the CDATA element
   * @return The length of the return data
   */
  short generateAsymmetricKeyPair(byte[] buffer, short offset, short length) throws ISOException {

    byte keyReference = buffer[ISO7816.OFFSET_P2];

    // Zero is also the chain buffer's "more frames expected" sentinel. Reject an actually empty
    // single-frame command before entering the chaining API so it cannot return a false success.
    if (length == ZERO
        && (buffer[ISO7816.OFFSET_CLA] & ChainBuffer.CLA_CHAINING) == ZERO
        && !chainBuffer.isIncomingApduActive()) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // SP 800-73-5 Part 2 Table 2 requires this command to support command chaining.
    length = chainBuffer.processIncomingAPDU(buffer, offset, length, scratch, ZERO);
    if (length == ZERO) return ZERO;
    buffer = scratch;
    offset = ZERO;

    // Request Elements
    final byte CONST_TAG_TEMPLATE = (byte) 0xAC;
    final byte CONST_TAG_MECHANISM = (byte) 0x80;

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1 - The command data must be exactly one well-formed TEMPLATE.
    TLVReader reader = TLVReader.getInstance();
    reader.init(buffer, offset, length);
    short limit = (short) (offset + length);
    if (buffer[offset] != CONST_TAG_TEMPLATE
        || TLV.objectEnd(buffer, offset, limit, false) != limit) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    short templateEnd = limit;
    offset = TLV.dataOffset(buffer, offset, limit, false);

    // PRE-CONDITION 2 - The 'MECHANISM' tag must be present in the supplied buffer
    if (offset >= templateEnd || buffer[offset] != CONST_TAG_MECHANISM) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 3 - The 'MECHANISM' tag must have a length of 1
    if (TLV.readLength(buffer, offset, templateEnd, false) != (short) 1) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    short mechanismOffset = TLV.dataOffset(buffer, offset, templateEnd, false);
    short next = TLV.objectEnd(buffer, offset, templateEnd, false);

    // Tag 81 is the only conditional element in the control reference template. Its value is
    // checked against the key's mechanism in PRE-CONDITION 5B.
    short parameterOffset = ZERO;
    if (next < templateEnd) {
      if (buffer[next] != (byte) 0x81
          || TLV.objectEnd(buffer, next, templateEnd, false) != templateEnd) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
      parameterOffset = next;
    }

    // PRE-CONDITION 4A - F9 is generated only under an encrypted and MACed GlobalPlatform secure
    // channel (prior 9B authentication is not sufficient) and only while the authority is still
    // provisionable: no certificate accepted and the applet not yet PERSONALIZED.
    // #if ATTESTATION_ENABLED
    if (keyReference == ID_KEY_ATTESTATION) {
      if (!cspPIV.getIsSecureChannel()) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }
      owner.completeAttestationActivation();
      attestation.requireAuthorityProvisionable();
    }
    // #else
    if (keyReference == ID_KEY_ATTESTATION) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    // #endif

    // PRE-CONDITION 4B - The key reference and mechanism must exist (key test)
    if (!cspPIV.keyExists(keyReference)) {
      // The key reference is bad
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    // PRE-CONDITION 4C - The key reference and mechanism must exist (mechanism test)
    PIVKeyObject key = cspPIV.selectKey(keyReference, buffer[mechanismOffset]);
    if (key == null) {
      // SP 800-73-5 Part 2 Section 3.3.2 status words: '6A 86' "Incorrect parameter P2; the
      // cryptographic mechanism of the reference data to be generated is different than the
      // cryptographic mechanism of the reference data of a given key reference", and '6A 80'
      // "Incorrect parameter in command data field (e.g., unrecognized cryptographic mechanism)".
      if (isAsymmetricMechanism(buffer[mechanismOffset])) {
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      }
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 5 - The key must be an asymmetric key (key pair)
    if (!(key instanceof PIVKeyObjectPKI)) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      return ZERO; // Keep static analyser happy
    }

    // PRE-CONDITION 5B - SP 800-73-5 Part 1 Section 5.3 Table 6 defines parameter '81' as
    // "Optional public exponent encoded big-endian" for RSA and "None" for ECC, and SP 800-78-5
    // Section 3.1 requires that "RSA keys must be generated using a public exponent of 65537". The
    // only parameter the card can honour is therefore the RSA exponent '01 00 01'; any other is an
    // "Incorrect parameter in command data field".
    if (parameterOffset != ZERO
        && !(key instanceof PIVKeyObjectRSA
            && PIVKeyObjectRSA.isPivPublicExponent(
                buffer,
                TLV.dataOffset(buffer, parameterOffset, templateEnd, false),
                TLV.readLength(buffer, parameterOffset, templateEnd, false)))) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // PRE-CONDITION 6 - The access rules must be satisfied for administrative access
    if (!cspPIV.checkAccessModeAdmin(key, owner.isVciSatisfied(), owner.isGlobalPinAdvertised())) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    //
    // EXECUTION STEPS
    //

    // STEP 1 - Generate the key pair. For F9 the authority is reset to NONE first and becomes
    // GENERATED only after the pair passed its pairwise consistency test and is marked generated,
    // so a tear at any point leaves either NONE or a complete generated pair.
    PIVKeyObjectPKI keyPair = (PIVKeyObjectPKI) key;
    // #if ATTESTATION_ENABLED
    if (keyReference == ID_KEY_ATTESTATION) attestation.beginAuthorityGeneration();
    // #endif
    length = keyPair.generate(scratch, ZERO);
    keyPair.markGenerated();
    // #if ATTESTATION_ENABLED
    if (keyReference == ID_KEY_ATTESTATION) attestation.completeAuthorityGeneration();
    // #endif

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
   * <p>- F9 must be an active, on-card generated P-256 attestation authority.
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
    if (!cspPIV.checkAccessModeObject(
        target, owner.isVciSatisfied(), owner.isGlobalPinAdvertised())) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PIVAttestation enforces generated-key origin. Imported keys may be valid PIV keys, but the
    // applet cannot truthfully attest that it generated or protected their origin.
    short length =
        attestation.buildCertificate(authority, target, slot, scratch, attestationResponse, ZERO);
    chainBuffer.setOutgoing(attestationResponse, ZERO, length, true);
  }

  /**
   * Signs the F9 proof-of-possession message {@code "OPF9POP" || N || F9pub}.
   *
   * <p>Status words, in check order: {@code 6982} without an encrypted and MACed GlobalPlatform
   * secure channel, {@code 6700} when the nonce is not 16 through 64 octets, {@code 6A88} when F9
   * is not defined, and {@code 6985} unless the authority is GENERATED, F9 holds a generated pair,
   * and the applet is still SELECTABLE. Proof is permanently unavailable once a certificate has
   * been accepted.
   *
   * @param buffer command data buffer
   * @param offset first nonce octet
   * @param length nonce length
   */
  void proveAuthority(byte[] buffer, short offset, short length) {
    if (!cspPIV.getIsSecureChannel()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
    if (length < PIVAttestation.LENGTH_POP_NONCE_MIN
        || length > PIVAttestation.LENGTH_POP_NONCE_MAX) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    PIVKeyObject key = cspPIV.selectKey(ID_KEY_ATTESTATION);
    if (!(key instanceof PIVKeyObjectECC)) {
      ISOException.throwIt(SW_REFERENCE_NOT_FOUND);
      return;
    }
    owner.completeAttestationActivation();
    attestation.requireAuthorityProvisionable();
    short signatureLength =
        attestation.signPossessionProof((PIVKeyObjectECC) key, buffer, offset, length, scratch);
    chainBuffer.setOutgoing(scratch, ZERO, signatureLength, true);
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
