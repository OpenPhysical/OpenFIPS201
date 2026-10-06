/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import dev.mistial.tools.openfips201.common.BerTlvReader;
import dev.mistial.tools.openfips201.common.BerTlvWriter;
import dev.mistial.tools.openfips201.common.ByteArrays;
import dev.mistial.tools.openfips201.common.CardSession;
import dev.mistial.tools.openfips201.common.HexUtil;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/**
 * {@link SamClient} over an APDU session on which the SAM applet is selected.
 *
 * <p>Over a GlobalPlatform secure-channel session every command is sent with CLA 84 and wrapped by
 * the session; over a plain session CLA 80 is used and only the plaintext commands (STATUS, SAM
 * CERT, LAST ENTRY, TOP UP) succeed. PUT PARAMETERS, LOAD SAM CERTIFICATE and ISSUE use ISO command
 * chaining (CLA bit 10). Outgoing responses longer than Le are collected with GET RESPONSE.
 */
public final class ApduSamClient implements SamClient {
  public static final byte[] SAM_PACKAGE_AID = HexUtil.parse("F04F50454E50485953414D");
  public static final byte[] SAM_AID = HexUtil.parse("F04F50454E50485953414D0001000000");

  private static final int CLA_CHAIN = 0x10;
  /** Frame payload limit: a 0xEF-octet frame still fits a short APDU after SCP03 wrapping. */
  private static final int MAX_FRAME = 0xEF;

  private static final int MAX_RESPONSE = 4096;

  private final CardSession session;
  private final int cla;
  private final int continuationCla;

  private ApduSamClient(CardSession session, int cla, int continuationCla) {
    this.session = session;
    this.cla = cla;
    this.continuationCla = continuationCla;
  }

  /** Commands over a secure-channel session (CLA 84). */
  public static ApduSamClient secure(CardSession session) {
    return new ApduSamClient(session, 0x84, 0x84);
  }

  /** Commands over a plain session (CLA 80). */
  public static ApduSamClient plain(CardSession session) {
    return new ApduSamClient(session, 0x80, 0x00);
  }

  /** Selects the SAM on {@code transport} and returns a plain client over it. */
  public static ApduSamClient selectPlain(
      dev.mistial.tools.openfips201.common.CardTransport transport) {
    final apdu4j.core.BIBO bibo = transport.bibo();
    dev.mistial.tools.openfips201.common.ApduSupport.selectApplication(bibo, SAM_AID, "SELECT SAM");
    return plain(
        new CardSession() {
          @Override
          public ResponseAPDU transmit(CommandAPDU command) {
            return bibo.transmit(command);
          }

          @Override
          public void close() {}
        });
  }

  @Override
  public SamStatus status() {
    return SamStatus.parse(send(0xCA, 0x00, 0x01, null, "GET DATA STATUS"));
  }

  @Override
  public byte[] signedStatus(byte[] nonce) {
    return send(0xCA, 0x01, 0x01, nonce, "GET DATA SIGNED STATUS");
  }

  @Override
  public void putParameters(byte[] parametersDer) {
    sendChained(0xD0, 0x00, 0x00, parametersDer, "PUT PARAMETERS");
  }

  @Override
  public void setOperatorPin(byte[] pin) {
    send(0xD2, 0x00, 0x81, pin, "SET OPERATOR PIN");
  }

  @Override
  public byte[] generateKey() {
    byte[] response = send(0x46, 0x00, 0x00, null, "GENERATE SAM KEY");
    BerTlvReader.Tlv point = BerTlvReader.read(response, 0);
    if (point.tag != 0x86
        || point.length != IssuanceCrypto.POINT_LENGTH
        || point.nextOffset != response.length) {
      throw new IllegalStateException("GENERATE SAM KEY did not return 86 41 <point>");
    }
    return Arrays.copyOfRange(response, point.valueOffset, point.nextOffset);
  }

  @Override
  public byte[] loadCertificate(byte[] certificate) {
    byte[] response = sendChained(0xD4, 0x00, 0x00, certificate, "LOAD SAM CERTIFICATE");
    BerTlvReader.Tlv ski = BerTlvReader.read(response, 0);
    if (ski.tag != 0x8B || ski.length != 20 || ski.nextOffset != response.length) {
      throw new IllegalStateException("LOAD SAM CERTIFICATE did not return 8B 14 <SKI>");
    }
    return Arrays.copyOfRange(response, ski.valueOffset, ski.nextOffset);
  }

  @Override
  public byte[] lock() {
    return send(0xD6, 0x00, 0x00, null, "LOCK");
  }

  @Override
  public void verifyPin(byte[] pin) {
    send(0x20, 0x00, 0x81, pin, "VERIFY OPERATOR PIN");
  }

  @Override
  public byte[] beginIssuance() {
    byte[] nonce = send(0x84, 0x00, 0x00, null, "BEGIN ISSUANCE");
    if (nonce.length != 32) {
      throw new IllegalStateException("BEGIN ISSUANCE returned " + nonce.length + " octets");
    }
    return nonce;
  }

  @Override
  public byte[] issue(
      byte[] f9Point,
      byte[] proofOfPossession,
      byte[] validityDer,
      byte[] capSha256,
      byte[] cplcSha256) {
    if (capSha256 == null || capSha256.length != 32) {
      throw new IllegalArgumentException("ISSUE needs the 32-octet CAP SHA-256");
    }
    if (cplcSha256 == null || cplcSha256.length != 32) {
      throw new IllegalArgumentException("ISSUE needs the 32-octet CPLC SHA-256");
    }
    byte[] data =
        ByteArrays.concat(
            BerTlvWriter.encode(0x86, f9Point),
            BerTlvWriter.encode(0x9E, proofOfPossession),
            BerTlvWriter.encode(0x93, validityDer),
            BerTlvWriter.encode(0x94, capSha256),
            BerTlvWriter.encode(0x95, cplcSha256));
    // About 245 octets: chained, so every frame still fits a short APDU after SCP03 wrapping.
    return sendChained(0x2A, 0x00, 0xF9, data, "ISSUE");
  }

  @Override
  public byte[] topUp(long timestamp, long add, byte[] rootSignature) {
    byte[] data =
        ByteArrays.concat(
            BerTlvWriter.encode(0x80, IssuanceCrypto.unsigned(timestamp, 8)),
            BerTlvWriter.encode(0x81, IssuanceCrypto.unsigned(add, 4)),
            BerTlvWriter.encode(0x9E, rootSignature));
    return send(0x32, 0x00, 0x00, data, "TOP UP");
  }

  @Override
  public byte[] samCertificate() {
    return send(0xCA, 0x00, 0x02, null, "GET DATA SAM CERTIFICATE");
  }

  @Override
  public byte[] lastEntry() {
    return send(0xCA, 0x00, 0x03, null, "GET DATA LAST ENTRY");
  }

  @Override
  public byte[] parameters() {
    return send(0xCA, 0x00, 0x04, null, "GET DATA PARAMS");
  }

  @Override
  public DecipherResult decipher(String opid) {
    return DecipherResult.parse(
        send(
            0x2C,
            0x00,
            0x00,
            BerTlvWriter.encode(0x80, opid.getBytes(java.nio.charset.StandardCharsets.US_ASCII)),
            "DECIPHER"));
  }

  @Override
  public byte[] terminate() {
    return send(0xE6, 0x00, 0x00, null, "TERMINATE");
  }

  @Override
  public byte[] generateTransportKey() {
    byte[] response = send(0x4A, 0x00, 0x00, null, "GENERATE TRANSPORT KEY");
    BerTlvReader.Tlv point = BerTlvReader.read(response, 0);
    if (point.tag != 0x86
        || point.length != IssuanceCrypto.POINT_LENGTH
        || point.nextOffset != response.length) {
      throw new IllegalStateException("GENERATE TRANSPORT KEY did not return 86 41 <point>");
    }
    return Arrays.copyOfRange(response, point.valueOffset, point.nextOffset);
  }

  @Override
  public void changeOperatorPin(byte[] oldPin, byte[] newPin) {
    byte[] data =
        ByteArrays.concat(BerTlvWriter.encode(0x80, oldPin), BerTlvWriter.encode(0x81, newPin));
    try {
      send(0x24, 0x00, 0x81, data, "CHANGE OPERATOR PIN");
    } finally {
      Arrays.fill(data, (byte) 0);
    }
  }

  @Override
  public byte[] voidIssuance(long seq, int reason) {
    return send(
        0x2E,
        0x00,
        0x00,
        ByteArrays.concat(
            BerTlvWriter.encode(0x80, IssuanceCrypto.unsigned(seq, 4)),
            BerTlvWriter.encode(0x81, new byte[] {(byte) reason})),
        "VOID");
  }

  @Override
  public byte[] close() {
    return send(0xE8, 0x00, 0x00, null, "CLOSE");
  }

  /** The 32-octet paramsDigest (tag 93) of a GET DATA PARAMS response. */
  public static byte[] paramsDigest(byte[] parameters) {
    BerTlvReader.Tlv digest = BerTlvReader.locate(parameters, 0, 0x93);
    if (digest == null || digest.length != 32) {
      throw new IllegalStateException("GET DATA PARAMS carries no 32-octet paramsDigest");
    }
    return Arrays.copyOfRange(parameters, digest.valueOffset, digest.nextOffset);
  }

  private byte[] send(int ins, int p1, int p2, byte[] data, String label) {
    CommandAPDU command =
        data == null || data.length == 0
            ? new CommandAPDU(cla, ins, p1, p2, 256)
            : new CommandAPDU(cla, ins, p1, p2, data, 256);
    return collect(session.transmit(command), label);
  }

  private byte[] sendChained(int ins, int p1, int p2, byte[] data, String label) {
    int offset = 0;
    while (data.length - offset > MAX_FRAME) {
      ResponseAPDU frame =
          session.transmit(
              new CommandAPDU(
                  cla | CLA_CHAIN,
                  ins,
                  p1,
                  p2,
                  Arrays.copyOfRange(data, offset, offset + MAX_FRAME)));
      if (frame.getSW() != 0x9000) {
        throw new SamApduException(label, frame.getSW());
      }
      offset += MAX_FRAME;
    }
    return collect(
        session.transmit(
            new CommandAPDU(cla, ins, p1, p2, Arrays.copyOfRange(data, offset, data.length), 256)),
        label);
  }

  private byte[] collect(ResponseAPDU first, String label) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ResponseAPDU current = first;
    while (current.getSW1() == 0x61) {
      byte[] fragment = current.getData();
      out.write(fragment, 0, fragment.length);
      if (out.size() > MAX_RESPONSE) {
        throw new IllegalStateException(label + " response exceeds " + MAX_RESPONSE + " octets");
      }
      int le = current.getSW2() == 0 ? 256 : current.getSW2();
      current = session.transmit(new CommandAPDU(continuationCla, 0xC0, 0x00, 0x00, le));
    }
    if (current.getSW() != 0x9000) {
      throw new SamApduException(label, current.getSW());
    }
    byte[] fragment = current.getData();
    out.write(fragment, 0, fragment.length);
    return out.toByteArray();
  }
}
