/******************************************************************************
 * MIT License
 *
 * Project: OpenPhysical Issuer SAM
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

package dev.mistial.openphysical.sam;

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
 * OpenPhysical issuer SAM: the per-batch issuing CA (Root, SAM, card F9, leaf).
 *
 * <p>The SAM owns OPID allocation (a provisioned decimal LCG), metering (issued and quota) and the
 * audit hash chain, and advances all three in one transaction per issuance. The host never supplies
 * an OPID, a quota value or a serial number.
 *
 * <p>Access control:
 *
 * <ul>
 *   <li>BEGIN ISSUANCE, ISSUE, DECIPHER, VOID, CLOSE and TERMINATE require a GlobalPlatform secure
 *       channel on that APDU (AUTHENTICATED | C_DECRYPTION | C_MAC) and a verified operator PIN.
 *   <li>Personalization (including GENERATE TRANSPORT KEY), VERIFY PIN, CHANGE OPERATOR PIN and GET
 *       DATA PARAMS / LAST RESULT require the secure channel.
 *   <li>CLOSED refuses BEGIN ISSUANCE, ISSUE and TOP UP (6985) and keeps STATUS, the certificate,
 *       LAST ENTRY, DECIPHER, VOID, VERIFY and CHANGE OPERATOR PIN; TERMINATE moves it to
 *       TERMINATED.
 *   <li>TOP UP authenticates itself with a root ECDSA signature; the secure channel is optional.
 *   <li>GET DATA STATUS, SAM CERT and LAST ENTRY are plaintext.
 *   <li>The SAM is contact-only: {@link #select()} declines a contactless interface.
 * </ul>
 *
 * <p>Command conventions: CLA 80 is plaintext and 84 is secure-channel protected; the chaining bit
 * is accepted only on PUT PARAMETERS and LOAD SAM CERTIFICATE. Any command other than GET RESPONSE
 * abandons a pending outgoing response, and any command other than ISSUE and GET RESPONSE consumes
 * the issuance nonce.
 */
public final class IssuerSam extends Applet implements AppletEvent, ExtendedLength {
  private static final byte SC_MASK =
      SecureChannel.AUTHENTICATED | SecureChannel.C_DECRYPTION | SecureChannel.C_MAC;

  private static final short FLAG_SCP = (short) 0;
  private static final short FLAG_RESULT_VALID = (short) 1;
  private static final short LENGTH_FLAGS = (short) 2;
  private static final short RESULT_LENGTH = (short) 0;

  private final SamState state;
  private final SamCrypto crypto;
  private final SamLedger ledger;
  private final SamPersonalization personalization;
  private final ApduChain chain;
  private final DERWriter certificateWriter;
  private final byte[] io;
  private final byte[] scratch;
  private final byte[] nonce;
  private final byte[] flags;
  private final short[] result;

  IssuerSam() {
    io = JCSystem.makeTransientByteArray(SamConst.LENGTH_IO_BUFFER, JCSystem.CLEAR_ON_DESELECT);
    scratch = JCSystem.makeTransientByteArray(SamConst.LENGTH_SCRATCH, JCSystem.CLEAR_ON_DESELECT);
    nonce =
        JCSystem.makeTransientByteArray(
            (short) (SamConst.LENGTH_NONCE + 1), JCSystem.CLEAR_ON_DESELECT);
    flags = JCSystem.makeTransientByteArray(LENGTH_FLAGS, JCSystem.CLEAR_ON_DESELECT);
    result = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
    certificateWriter = new DERWriter();
    state = new SamState();
    crypto = new SamCrypto(io);
    ledger = new SamLedger(state, crypto, io, scratch, nonce);
    SamCertificateParser parser = new SamCertificateParser(state, crypto, scratch);
    personalization = new SamPersonalization(state, crypto, ledger, parser, scratch);
    chain = new ApduChain(io);
  }

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    byte aidLength = (bArray == null || bArray.length == 0) ? (byte) 0 : bArray[bOffset];
    new IssuerSam().register(bArray, (short) (bOffset + 1), aidLength);
  }

  @Override
  public boolean select() {
    byte media = (byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);
    return media != APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A
        && media != APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B;
  }

  @Override
  public void deselect() {
    GPSystem.getSecureChannel().resetSecurity();
    state.operatorPin.reset();
  }

  /**
   * Prepares for deletion. Nothing is required: every object this instance allocated, the DER
   * writer included, is referenced only from the instance itself, never from a static field, so
   * JCRE 3.0.5 Section 11.3.4.2 does not block the deletion and the objects are released with the
   * instance. JC 3.0.5 API AppletEvent states "The Java Card runtime environment will not rollback
   * state automatically if applet deletion fails"; leaving the state untouched keeps the instance
   * fully operational in that case.
   */
  @Override
  public void uninstall() {
    // Intentionally empty: there is no static reference to release.
  }

  @Override
  public void process(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    if (selectingApplet()) {
      chain.abortOutgoing();
      chain.abortIncoming();
      ledger.consumeNonce();
      flags[FLAG_RESULT_VALID] = (byte) 0;
      processSelect(apdu, buffer);
      return;
    }

    byte cla = buffer[ISO7816.OFFSET_CLA];
    byte ins = buffer[ISO7816.OFFSET_INS];
    byte p1 = buffer[ISO7816.OFFSET_P1];
    byte p2 = buffer[ISO7816.OFFSET_P2];

    if (ins != SamConst.INS_GET_RESPONSE) chain.abortOutgoing();
    // GET RESPONSE may still be delivering the BEGIN ISSUANCE nonce, so it does not consume it.
    if (ins != SamConst.INS_ISSUE && ins != SamConst.INS_GET_RESPONSE) ledger.consumeNonce();
    if (chain.isIncomingForOther(ins)) chain.abortIncoming();
    if (clearsLastResult(ins, p1, p2)) flags[FLAG_RESULT_VALID] = (byte) 0;

    validateClass(cla, ins);
    boolean secureMessaging = apdu.isSecureMessagingCLA();
    short length = (short) 0;
    short offset = ISO7816.OFFSET_CDATA;
    if (secureMessaging || expectsData(ins, p1)) {
      length = receiveAllIncomingData(apdu);
      offset = apdu.getOffsetCdata();
    }

    // The command counts as protected only if a fully authenticated session exists and this APDU
    // was unwrapped by it. An SM class without such a session is rejected outright.
    flags[FLAG_SCP] = (byte) 0;
    if (secureMessaging
        && ins != SamConst.INS_GP_INITIALIZE_UPDATE
        && ins != SamConst.INS_GP_EXTERNAL_AUTHENTICATE) {
      SecureChannel secureChannel = GPSystem.getSecureChannel();
      if ((secureChannel.getSecurityLevel() & SC_MASK) != SC_MASK) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }
      length =
          (short) (secureChannel.unwrap(buffer, (short) 0, (short) (offset + length)) - offset);
      flags[FLAG_SCP] = (byte) 1;
    }

    try {
      dispatch(apdu, buffer, cla, ins, p1, p2, offset, length);
    } catch (ISOException e) {
      throw e;
    } catch (Exception e) {
      ISOException.throwIt(SamConst.SW_UNEXPECTED);
    }
  }

  private void dispatch(
      APDU apdu, byte[] buffer, byte cla, byte ins, byte p1, byte p2, short offset, short length) {
    switch (ins) {
      case SamConst.INS_GP_INITIALIZE_UPDATE:
      case SamConst.INS_GP_EXTERNAL_AUTHENTICATE:
        processSecureChannel(apdu, ins);
        return;
      case SamConst.INS_GET_RESPONSE:
        requireP1P2(p1, p2, (byte) 0, (byte) 0);
        chain.sendNext(apdu);
        return;
      case SamConst.INS_PUT_PARAMETERS:
        try {
          processPutParameters(apdu, buffer, cla, p1, p2, offset, length);
        } catch (RuntimeException e) {
          // A rejected frame abandons the chain, so no later frame can complete it. The staged
          // packet carries the FF1 key and is zeroized.
          chain.abortIncoming();
          Util.arrayFillNonAtomic(
              io, SamConst.STAGE_PARAMETERS, SamConst.STAGE_PARAMETERS_MAX, (byte) 0);
          throw e;
        } finally {
          Util.arrayFillNonAtomic(buffer, offset, length, (byte) 0);
        }
        return;
      case SamConst.INS_SET_OPERATOR_PIN:
        requirePersonalization();
        requireP1P2(p1, p2, (byte) 0, SamConst.P2_OPERATOR_PIN);
        personalization.setOperatorPin(buffer, offset, length);
        return;
      case SamConst.INS_GENERATE_SAM_KEY:
        requirePersonalization();
        requireP1P2(p1, p2, (byte) 0, (byte) 0);
        if (state.lifecycle != SamConst.LC_PARAMS_SET
            && state.lifecycle != SamConst.LC_KEY_GENERATED
            && state.lifecycle != SamConst.LC_CERT_LOADED) {
          ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        send(apdu, personalization.generateKey(io, (short) 0));
        return;
      case SamConst.INS_LOAD_SAM_CERTIFICATE:
        try {
          processLoadCertificate(apdu, buffer, cla, p1, p2, offset, length);
        } catch (ISOException e) {
          chain.abortIncoming();
          throw e;
        }
        return;
      case SamConst.INS_LOCK:
        requirePersonalization();
        requireP1P2(p1, p2, (byte) 0, (byte) 0);
        if (state.lifecycle != SamConst.LC_CERT_LOADED) {
          ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        send(apdu, personalization.lock());
        return;
      case SamConst.INS_VERIFY_PIN:
        processVerifyPin(buffer, p1, p2, offset, length);
        return;
      case SamConst.INS_BEGIN_ISSUANCE:
        requireOperator();
        requireP1P2(p1, p2, (byte) 0, (byte) 0);
        if (!state.hasCapacity()) ISOException.throwIt(SamConst.SW_EXHAUSTED);
        ledger.beginIssuance();
        Util.arrayCopyNonAtomic(nonce, (short) 0, io, (short) 0, SamConst.LENGTH_NONCE);
        send(apdu, SamConst.LENGTH_NONCE);
        return;
      case SamConst.INS_ISSUE:
        // Step 1: lifecycle, secure channel and operator PIN.
        requireOperator();
        requireP1P2(p1, p2, (byte) 0, SamConst.P2_ISSUE_F9);
        short issued = ledger.issue(certificateWriter, buffer, offset, length);
        result[RESULT_LENGTH] = issued;
        flags[FLAG_RESULT_VALID] = (byte) 1;
        send(apdu, issued);
        return;
      case SamConst.INS_TOP_UP:
        requireP1P2(p1, p2, (byte) 0, (byte) 0);
        if (!state.isOperational()) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        send(apdu, ledger.topUp(buffer, offset, length));
        return;
      case SamConst.INS_GET_DATA:
        processGetData(apdu, buffer, p1, p2, offset, length);
        return;
      case SamConst.INS_TERMINATE:
        requireLiveOperator();
        requireP1P2(p1, p2, (byte) 0, (byte) 0);
        send(apdu, ledger.terminate());
        return;
      case SamConst.INS_DECIPHER:
        requireLiveOperator();
        requireP1P2(p1, p2, (byte) 0, (byte) 0);
        send(apdu, ledger.decipher(buffer, offset, length));
        return;
      case SamConst.INS_VOID:
        requireLiveOperator();
        requireP1P2(p1, p2, (byte) 0, (byte) 0);
        send(apdu, ledger.voidIssuance(buffer, offset, length));
        return;
      case SamConst.INS_CLOSE:
        requireLiveOperator();
        requireP1P2(p1, p2, (byte) 0, (byte) 0);
        send(apdu, ledger.close());
        return;
      case SamConst.INS_CHANGE_OPERATOR_PIN:
        requireSecureChannel();
        requireP1P2(p1, p2, (byte) 0, SamConst.P2_OPERATOR_PIN);
        if (!state.isLive()) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        personalization.changeOperatorPin(buffer, offset, length);
        return;
      case SamConst.INS_GENERATE_TRANSPORT_KEY:
        requirePersonalization();
        requireP1P2(p1, p2, (byte) 0, (byte) 0);
        if (state.lifecycle != SamConst.LC_INSTALLED && state.lifecycle != SamConst.LC_PARAMS_SET) {
          ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        send(apdu, personalization.generateTransportKey(io, (short) 0));
        return;
      default:
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
  }

  //
  // Personalization.
  //

  private void processPutParameters(
      APDU apdu, byte[] buffer, byte cla, byte p1, byte p2, short offset, short length) {
    requirePersonalization();
    requireP1P2(p1, p2, (byte) 0, (byte) 0);
    if (state.lifecycle != SamConst.LC_INSTALLED && state.lifecycle != SamConst.LC_PARAMS_SET) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short total =
        chain.append(
            SamConst.INS_PUT_PARAMETERS,
            Util.getShort(buffer, ISO7816.OFFSET_P1),
            true,
            (cla & SamConst.CLA_CHAIN_BIT) != 0,
            buffer,
            offset,
            length,
            SamConst.STAGE_PARAMETERS,
            SamConst.STAGE_PARAMETERS_MAX);
    if (total < (short) 0) return;
    personalization.putParameters(io, SamConst.STAGE_PARAMETERS, total);
    Util.arrayFillNonAtomic(io, SamConst.STAGE_PARAMETERS, total, (byte) 0);
  }

  private void processLoadCertificate(
      APDU apdu, byte[] buffer, byte cla, byte p1, byte p2, short offset, short length) {
    requirePersonalization();
    requireP1P2(p1, p2, (byte) 0, (byte) 0);
    if (state.lifecycle != SamConst.LC_KEY_GENERATED
        && state.lifecycle != SamConst.LC_CERT_LOADED) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short total =
        chain.append(
            SamConst.INS_LOAD_SAM_CERTIFICATE,
            Util.getShort(buffer, ISO7816.OFFSET_P1),
            true,
            (cla & SamConst.CLA_CHAIN_BIT) != 0,
            buffer,
            offset,
            length,
            SamConst.STAGE_CERTIFICATE,
            SamConst.STAGE_CERTIFICATE_MAX);
    if (total < (short) 0) return;
    short responseLength =
        personalization.loadCertificate(io, SamConst.STAGE_CERTIFICATE, total, buffer, (short) 0);
    apdu.setOutgoingAndSend((short) 0, responseLength);
  }

  /** Secure channel, then 6986 after LOCK. */
  private void requirePersonalization() {
    requireSecureChannel();
    if (state.isLocked()) ISOException.throwIt(SamConst.SW_LOCKED);
  }

  //
  // Operation.
  //

  private void processVerifyPin(byte[] buffer, byte p1, byte p2, short offset, short length) {
    requireSecureChannel();
    requireP1P2(p1, p2, (byte) 0, SamConst.P2_OPERATOR_PIN);
    if (!state.isLive()) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    byte tries = state.operatorPin.getTriesRemaining();
    if (length == (short) 0) {
      // ISO/IEC 7816-4 Section 11.5.6: an empty VERIFY returns the verification status.
      if (state.operatorPin.isValidated()) return;
      if (tries == (byte) 0) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
      ISOException.throwIt((short) (0x63C0 | tries));
    }
    if (tries == (byte) 0) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
    if (length < SamConst.LENGTH_PIN_MIN || length > SamConst.LENGTH_PIN_MAX) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    if (!state.operatorPin.check(buffer, offset, (byte) length)) {
      ISOException.throwIt((short) (0x63C0 | state.operatorPin.getTriesRemaining()));
    }
  }

  /** OPERATIONAL, secure channel and a verified operator PIN, in that order of precedence. */
  private void requireOperator() {
    requireSecureChannel();
    if (!state.operatorPin.isValidated()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
    if (!state.isOperational()) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
  }

  /** As {@link #requireOperator()}, but OPERATIONAL or CLOSED. */
  private void requireLiveOperator() {
    requireSecureChannel();
    if (!state.operatorPin.isValidated()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
    if (!state.isLive()) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
  }

  private void requireSecureChannel() {
    if (flags[FLAG_SCP] != (byte) 1) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
  }

  //
  // GET DATA.
  //

  private void processGetData(
      APDU apdu, byte[] buffer, byte p1, byte p2, short offset, short length) {
    if (p1 == (byte) 0x00) {
      if (length != (short) 0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      switch (p2) {
        case SamConst.GET_DATA_STATUS:
          send(apdu, writeStatus((short) 0));
          return;
        case SamConst.GET_DATA_SAM_CERTIFICATE:
          if (!state.hasCertificate()) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
          Util.arrayCopyNonAtomic(state.samCert, (short) 0, io, (short) 0, state.samCertLength);
          send(apdu, state.samCertLength);
          return;
        case SamConst.GET_DATA_LAST_ENTRY:
          if (state.isLive()) {
            send(apdu, ledger.appendSignedEntry((short) 0));
          } else if (state.lifecycle == SamConst.LC_TERMINATED) {
            // The SAM key is cleared after TERMINATE; the entry was signed in that response.
            send(apdu, ledger.appendEntry((short) 0));
          } else {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
          }
          return;
        case SamConst.GET_DATA_PARAMETERS:
          requireSecureChannel();
          if (!state.hasParameters()) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
          send(apdu, writeParameters());
          return;
        case SamConst.GET_DATA_LAST_RESULT:
          requireSecureChannel();
          if (!state.isOperational() || flags[FLAG_RESULT_VALID] != (byte) 1) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
          }
          send(apdu, result[RESULT_LENGTH]);
          return;
        default:
          ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      }
    }
    if (p1 == SamConst.GET_DATA_SIGNED && p2 == SamConst.GET_DATA_STATUS) {
      if (length < SamConst.LENGTH_STATUS_NONCE_MIN || length > SamConst.LENGTH_STATUS_NONCE_MAX) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
      if (!crypto.isSamKeyInitialized() || state.lifecycle == SamConst.LC_TERMINATED) {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }
      short statusLength = writeStatus((short) 0);
      // 9E signs "OPSAMSTAT1" | nonce | statusTLV.
      short sigOffset = (short) (statusLength + 2);
      short sigLength =
          crypto.signConcatenation(
              SamConst.PREFIX_STATUS,
              buffer,
              offset,
              length,
              io,
              (short) 0,
              statusLength,
              io,
              sigOffset);
      io[statusLength] = (byte) 0x9E;
      io[(short) (statusLength + 1)] = (byte) sigLength;
      send(apdu, (short) (sigOffset + sigLength));
      return;
    }
    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
  }

  /**
   * STATUS TLV: 80 lifecycle, 82 IIN (4 ASCII), 83 batch (4 ASCII), 85 issued, 86 quota, 87 m, 88
   * lastTopUpTs, 89 eventSeq, 8A chainHead, 8B samSki, 8C PIN state (set flag, tries remaining), 8E
   * version, 8F allocationSeq, 90 registryHead. The LCG state (a, c, x0, x) is secret and never
   * emitted.
   */
  private short writeStatus(short offset) {
    short cursor = offset;
    cursor = putByte(cursor, (byte) 0x80, state.lifecycle);
    cursor = putAscii(cursor, (byte) 0x82, state.issuerDigits, SamConst.ISSUER_DIGITS);
    cursor = putAscii(cursor, (byte) 0x83, state.batchDigits, SamConst.BATCH_DIGITS);
    cursor = put(cursor, (byte) 0x85, state.issued, SamConst.LENGTH_U32);
    cursor = put(cursor, (byte) 0x86, state.quota, SamConst.LENGTH_U32);
    cursor = put(cursor, (byte) 0x87, SamConst.MODULUS, SamConst.LENGTH_U32);
    cursor = put(cursor, (byte) 0x88, state.lastTopUpTs, SamConst.LENGTH_TIMESTAMP);
    cursor = put(cursor, (byte) 0x89, state.eventSeq, SamConst.LENGTH_U32);
    cursor = put(cursor, (byte) 0x8A, state.chainHead, SamConst.LENGTH_HASH);
    cursor = put(cursor, (byte) 0x8B, state.samSki, SamConst.LENGTH_SKI);
    io[cursor++] = (byte) 0x8C;
    io[cursor++] = (byte) 0x02;
    io[cursor++] = state.pinSet ? (byte) 0x01 : (byte) 0x00;
    io[cursor++] = state.operatorPin.getTriesRemaining();
    io[cursor++] = (byte) 0x8E;
    io[cursor++] = (byte) 0x02;
    io[cursor++] = SamConst.VERSION_MAJOR;
    io[cursor++] = SamConst.VERSION_MINOR;
    cursor = put(cursor, (byte) 0x8F, state.allocationSeq, SamConst.LENGTH_U32);
    cursor = put(cursor, (byte) 0x90, state.registryHead, SamConst.LENGTH_HASH);
    return (short) (cursor - offset);
  }

  /**
   * PARAMS (non-secret fields only): 82 IIN (4 ASCII), 83 batch (4 ASCII), 85 issued, 86 quota, 93
   * paramsDigest v3 (32). The multiplier, increment, seed, current value, jump maps and FF1 key are
   * never emitted; the issuance software that generated them verifies them through paramsDigest.
   */
  private short writeParameters() {
    short cursor = (short) 0;
    cursor = putAscii(cursor, (byte) 0x82, state.issuerDigits, SamConst.ISSUER_DIGITS);
    cursor = putAscii(cursor, (byte) 0x83, state.batchDigits, SamConst.BATCH_DIGITS);
    cursor = put(cursor, (byte) 0x85, state.issued, SamConst.LENGTH_U32);
    cursor = put(cursor, (byte) 0x86, state.quota, SamConst.LENGTH_U32);
    return put(cursor, (byte) 0x93, state.paramsDigest, SamConst.LENGTH_HASH);
  }

  private short putByte(short cursor, byte tag, byte value) {
    io[cursor++] = tag;
    io[cursor++] = (byte) 0x01;
    io[cursor++] = value;
    return cursor;
  }

  private short put(short cursor, byte tag, byte[] value, short length) {
    io[cursor++] = tag;
    io[cursor++] = (byte) length;
    return Util.arrayCopyNonAtomic(value, (short) 0, io, cursor, length);
  }

  /** Writes digit values (most significant first) as ASCII. */
  private short putAscii(short cursor, byte tag, byte[] digits, short count) {
    io[cursor++] = tag;
    io[cursor++] = (byte) count;
    for (short i = 0; i < count; i++) {
      io[cursor++] = (byte) (digits[i] + (byte) '0');
    }
    return cursor;
  }

  //
  // Transport.
  //

  private void processSelect(APDU apdu, byte[] buffer) {
    // FCI: 6F { 80 02 version, 81 01 lifecycle }
    buffer[0] = (byte) 0x6F;
    buffer[1] = (byte) 0x07;
    buffer[2] = (byte) 0x80;
    buffer[3] = (byte) 0x02;
    buffer[4] = SamConst.VERSION_MAJOR;
    buffer[5] = SamConst.VERSION_MINOR;
    buffer[6] = (byte) 0x81;
    buffer[7] = (byte) 0x01;
    buffer[8] = state.lifecycle;
    apdu.setOutgoingAndSend((short) 0, (short) 9);
  }

  private void processSecureChannel(APDU apdu, byte ins) {
    if (ins == SamConst.INS_GP_INITIALIZE_UPDATE) {
      // A new secure-channel session starts a new operator session.
      state.operatorPin.reset();
    }
    short length = GPSystem.getSecureChannel().processSecurity(apdu);
    apdu.setOutgoingAndSend(apdu.getOffsetCdata(), length);
  }

  private void send(APDU apdu, short length) {
    chain.send(apdu, (short) 0, length);
  }

  private static void requireP1P2(byte p1, byte p2, byte expectedP1, byte expectedP2) {
    if (p1 != expectedP1 || p2 != expectedP2) ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
  }

  /**
   * CLA rules: SELECT uses 00; INITIALIZE UPDATE 80 and EXTERNAL AUTHENTICATE 84; GET RESPONSE 00,
   * 80 or 84; PUT PARAMETERS and LOAD SAM CERTIFICATE 80/84 with or without the chaining bit; every
   * other command 80 or 84.
   */
  private static void validateClass(byte cla, byte ins) {
    boolean valid;
    if (ins == SamConst.INS_SELECT) {
      valid = cla == SamConst.CLA_ISO;
    } else if (ins == SamConst.INS_GP_INITIALIZE_UPDATE) {
      valid = cla == SamConst.CLA_PROPRIETARY;
    } else if (ins == SamConst.INS_GP_EXTERNAL_AUTHENTICATE) {
      valid = cla == SamConst.CLA_PROPRIETARY_SM;
    } else if (ins == SamConst.INS_GET_RESPONSE) {
      valid =
          cla == SamConst.CLA_ISO
              || cla == SamConst.CLA_PROPRIETARY
              || cla == SamConst.CLA_PROPRIETARY_SM;
    } else {
      byte base = cla;
      if (ins == SamConst.INS_PUT_PARAMETERS || ins == SamConst.INS_LOAD_SAM_CERTIFICATE) {
        base = (byte) (cla & (byte) ~SamConst.CLA_CHAIN_BIT);
      }
      valid = base == SamConst.CLA_PROPRIETARY || base == SamConst.CLA_PROPRIETARY_SM;
    }
    if (!valid) ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    if (ins == SamConst.INS_SELECT) ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
  }

  /**
   * Plaintext case 1 and case 2 commands carry no data field. They are not received, so that on a
   * T=0 transport P3 is never misread as Lc.
   */
  private static boolean expectsData(byte ins, byte p1) {
    if (ins == SamConst.INS_GET_RESPONSE) return false;
    if (ins == SamConst.INS_GET_DATA) return p1 != (byte) 0x00;
    if (ins == SamConst.INS_BEGIN_ISSUANCE
        || ins == SamConst.INS_GENERATE_SAM_KEY
        || ins == SamConst.INS_LOCK
        || ins == SamConst.INS_TERMINATE
        || ins == SamConst.INS_CLOSE
        || ins == SamConst.INS_GENERATE_TRANSPORT_KEY) {
      return false;
    }
    return true;
  }

  /**
   * Whether this command invalidates the ISSUE result held in the I/O buffer: every command that
   * may write the I/O buffer does.
   */
  private static boolean clearsLastResult(byte ins, byte p1, byte p2) {
    if (ins == SamConst.INS_GET_RESPONSE
        || ins == SamConst.INS_VERIFY_PIN
        || ins == SamConst.INS_GP_INITIALIZE_UPDATE
        || ins == SamConst.INS_GP_EXTERNAL_AUTHENTICATE) {
      return false;
    }
    return !(ins == SamConst.INS_GET_DATA
        && p1 == (byte) 0x00
        && p2 == SamConst.GET_DATA_LAST_RESULT);
  }

  /**
   * Receives the complete command data field into the APDU buffer.
   *
   * <p>Java Card 3.0.5 {@link APDU#receiveBytes} requires room for a full input block even when
   * fewer octets remain; when the tail of the APDU buffer is too short, the block is received at
   * CDATA, relocated, and the saved prefix restored from scratch.
   *
   * @return Nc
   */
  private short receiveAllIncomingData(APDU apdu) {
    short received = apdu.setIncomingAndReceive();
    short offset = apdu.getOffsetCdata();
    short total = apdu.getIncomingLength();
    byte[] buffer = apdu.getBuffer();
    if (received < (short) 0 || received > total || total > (short) (buffer.length - offset)) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    short writeOffset = (short) (offset + received);
    while (received < total) {
      short blockSize = APDU.getInBlockSize();
      short block;
      if ((short) (buffer.length - writeOffset) < blockSize) {
        if (blockSize > (short) scratch.length || blockSize > (short) (buffer.length - offset)) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short saved = received < blockSize ? received : blockSize;
        Util.arrayCopyNonAtomic(buffer, offset, scratch, (short) 0, saved);
        block = receiveBlock(apdu, offset, (short) (total - received));
        Util.arrayCopyNonAtomic(buffer, offset, buffer, writeOffset, block);
        Util.arrayCopyNonAtomic(scratch, (short) 0, buffer, offset, saved);
      } else {
        block = receiveBlock(apdu, writeOffset, (short) (total - received));
      }
      received += block;
      writeOffset += block;
    }
    return received;
  }

  private static short receiveBlock(APDU apdu, short offset, short remaining) {
    short length = apdu.receiveBytes(offset);
    if (length <= (short) 0 || length > remaining) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    return length;
  }
}
