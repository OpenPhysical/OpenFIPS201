/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.attestation;

import static dev.mistial.tools.openfips201.common.ByteArrays.concat;

import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import dev.mistial.tools.openfips201.common.ApduSupport;
import dev.mistial.tools.openfips201.common.CardSession;
import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.CardTransport;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.common.LogicalResponseCollector;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public final class AttestationProofService {
  public static final byte DEFAULT_PROOF_SLOT = (byte) 0x9A;

  public Result prove(CardSession session, byte slot, boolean deleteProofKey) throws Exception {
    createAndGenerateProofKey(session, slot);
    boolean deleted = false;
    byte[] certificate = null;
    try {
      certificate = collectProtected(session, slot);
      parseCertificate(certificate);
    } finally {
      if (deleteProofKey) {
        deleted = deleteProofKey(session, slot);
      }
    }
    return new Result(certificate, deleted);
  }

  public void createAndGenerateProofKey(CardSession session, byte slot) {
    createProofKey(session, slot);
    try {
      ResponseAPDU generated =
          expect(
              session.transmit(
                  new CommandAPDU(
                      0x84,
                      0x47,
                      0x00,
                      slot & 0xFF,
                      new byte[] {
                        (byte) 0xAC, 0x03, (byte) 0x80, 0x01, AttestationSupport.ALG_ECC_P256
                      },
                      256)),
              "generate proof key");
      if (generated.getData().length == 0) {
        throw new IllegalStateException("proof key generation returned no public key");
      }
    } catch (RuntimeException e) {
      try {
        deleteProofKey(session, slot);
      } catch (RuntimeException cleanupFailure) {
        cleanupFailure.addSuppressed(e);
        throw cleanupFailure;
      }
      throw e;
    }
  }

  public void setProofPin(CardSession session, byte[] pin) {
    if (pin == null || pin.length != 8) {
      throw new IllegalArgumentException("proof PIN must use the eight-byte PIV wire format");
    }
    expect(session.transmit(new CommandAPDU(0x84, 0x24, 0x01, 0x80, pin)), "set proof PIN");
  }

  public Result collectAndDelete(
      CardTarget target,
      byte[] appletAid,
      GlobalPlatformSession cleanupSession,
      byte slot,
      boolean deleteProofKey)
      throws Exception {
    byte[] certificate = collectPlain(target, appletAid, slot);
    parseCertificate(certificate);
    boolean deleted = false;
    if (deleteProofKey) {
      deleted = deleteProofKey(cleanupSession, slot);
    }
    return new Result(certificate, deleted);
  }

  public boolean deleteCreatedProofKey(CardSession session, byte slot) {
    return deleteProofKey(session, slot);
  }

  public byte[] collectPlainProof(CardTarget target, byte[] appletAid, byte slot) throws Exception {
    try (CardTransport transport = target.openTransport()) {
      return collectPlainProof(transport, appletAid, slot);
    }
  }

  public byte[] collectPlainProof(CardTransport transport, byte[] appletAid, byte slot)
      throws Exception {
    byte[] certificate = collectPlain(transport, appletAid, slot);
    parseCertificate(certificate);
    return certificate;
  }

  public byte[] collectPlainProof(CardTransport transport, byte[] appletAid, byte slot, byte[] pin)
      throws Exception {
    byte[] certificate = collectPlain(transport, appletAid, slot, pin);
    parseCertificate(certificate);
    return certificate;
  }

  public static final class Result {
    public final byte[] certificate;
    public final boolean proofKeyDeleted;

    public Result(byte[] certificate, boolean proofKeyDeleted) {
      this.certificate = certificate;
      this.proofKeyDeleted = proofKeyDeleted;
    }
  }

  private static void createProofKey(CardSession session, byte slot) {
    AttestationAuthorityService.transmitExpect(
        session, new CommandAPDU(0x84, 0xDB, 0x3F, 0x00, proofKeyDefinition(slot)), false);
  }

  static byte[] proofKeyDefinition(byte slot) {
    byte contact = AttestationSupport.ACCESS_ALWAYS;
    byte contactless = AttestationSupport.ACCESS_ALWAYS;
    if (slot == (byte) 0x9A) {
      // SP 800-73-5 Part 1 Table 5 fixes the PIV Authentication slot access modes.
      contact = (byte) 0x01;
      contactless = (byte) 0x09;
    }
    return AttestationSupport.tlv(
        0x66,
        concat(
            AttestationSupport.tlv(0x8B, new byte[] {slot}),
            AttestationSupport.tlv(0x8C, new byte[] {contact}),
            AttestationSupport.tlv(0x8D, new byte[] {contactless}),
            AttestationSupport.tlv(0x8E, new byte[] {AttestationSupport.ALG_ECC_P256}),
            AttestationSupport.tlv(0x8F, new byte[] {AttestationSupport.ROLE_SIGN}),
            AttestationSupport.tlv(0x90, new byte[] {0x00})));
  }

  private static boolean deleteProofKey(CardSession session, byte slot) {
    byte[] payload = deleteProofKeyPayload(slot);
    ResponseAPDU response = session.transmit(new CommandAPDU(0x84, 0xDB, 0x3F, 0x00, payload));
    if (response.getSW() == 0x9000) {
      return true;
    }
    throw new IllegalStateException(
        "delete proof key failed SW=" + String.format("0x%04X", response.getSW()));
  }

  static byte[] deleteProofKeyPayload(byte slot) {
    return AttestationSupport.tlv(
        0x67,
        concat(
            AttestationSupport.tlv(0x8B, new byte[] {slot}),
            AttestationSupport.tlv(0x8E, new byte[] {AttestationSupport.ALG_ECC_P256})));
  }

  private static byte[] collectProtected(CardSession session, byte slot) {
    return LogicalResponseCollector.collect(
        session,
        session.transmit(new CommandAPDU(0x84, 0xF9, slot & 0xFF, 0x00, 0)),
        0x84,
        4096,
        "attestation proof");
  }

  private static byte[] collectPlain(CardTarget target, byte[] appletAid, byte slot)
      throws Exception {
    try (CardTransport transport = target.openTransport()) {
      return collectPlain(transport, appletAid, slot);
    }
  }

  private static byte[] collectPlain(CardTransport transport, byte[] appletAid, byte slot) {
    apdu4j.core.BIBO bibo = transport.bibo();
    ApduSupport.selectApplication(bibo, appletAid, "SELECT PIV");
    CardSession session = borrowed(bibo);
    return LogicalResponseCollector.collect(
        session,
        bibo.transmit(new CommandAPDU(0x00, 0xF9, slot & 0xFF, 0x00, 0)),
        0x00,
        4096,
        "attestation proof");
  }

  private static byte[] collectPlain(
      CardTransport transport, byte[] appletAid, byte slot, byte[] pin) {
    apdu4j.core.BIBO bibo = transport.bibo();
    ApduSupport.selectApplication(bibo, appletAid, "SELECT PIV");
    ResponseAPDU verified = bibo.transmit(new CommandAPDU(0x00, 0x20, 0x00, 0x80, pin));
    if (verified.getSW() != 0x9000) {
      throw new IllegalStateException(
          "VERIFY proof PIN failed SW=" + String.format("0x%04X", verified.getSW()));
    }
    CardSession session = borrowed(bibo);
    return LogicalResponseCollector.collect(
        session,
        bibo.transmit(new CommandAPDU(0x00, 0xF9, slot & 0xFF, 0x00, 0)),
        0x00,
        4096,
        "attestation proof");
  }

  private static CardSession borrowed(final apdu4j.core.BIBO bibo) {
    return new CardSession() {
      @Override
      public ResponseAPDU transmit(CommandAPDU command) {
        return bibo.transmit(command);
      }

      @Override
      public void close() {
        // The enclosing CardTransport owns this connection.
      }
    };
  }

  private static ResponseAPDU expect(ResponseAPDU response, String label) {
    if (response.getSW() != 0x9000) {
      throw new IllegalStateException(
          label + " failed SW=" + String.format("0x%04X", response.getSW()));
    }
    return response;
  }

  private static X509Certificate parseCertificate(byte[] der) throws Exception {
    return (X509Certificate)
        CertificateFactory.getInstance("X.509")
            .generateCertificate(new java.io.ByteArrayInputStream(der));
  }
}
