/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.attestation;

import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import dev.mistial.tools.openfips201.common.CardSession;
import java.io.ByteArrayOutputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public final class AttestationProofService {
  public Result prove(CardSession session, byte slot, boolean deleteProofKey) throws Exception {
    createProofKey(session, slot);
    ResponseAPDU generated =
        expect(
            session.transmit(
                new CommandAPDU(
                    0x84,
                    0x47,
                    0x00,
                    slot & 0xFF,
                    new byte[] {(byte) 0xAC, 0x03, (byte) 0x80, 0x01, AttestationSupport.ALG_ECC_P256},
                    256)),
            "generate proof key");
    if (generated.getData().length == 0) {
      throw new IllegalStateException("proof key generation returned no public key");
    }
    byte[] certificate = collect(session, session.transmit(new CommandAPDU(0x00, 0xF9, slot & 0xFF, 0x00, 0)));
    parseCertificate(certificate);
    boolean deleted = false;
    if (deleteProofKey) {
      deleted = deleteProofKey(session, slot);
    }
    return new Result(certificate, deleted);
  }

  public static final class Result {
    public final byte[] certificate;
    public final boolean proofKeyDeleted;

    Result(byte[] certificate, boolean proofKeyDeleted) {
      this.certificate = certificate;
      this.proofKeyDeleted = proofKeyDeleted;
    }
  }

  private static void createProofKey(CardSession session, byte slot) {
    byte[] definition =
        AttestationSupport.tlv(
            0x66,
            AttestationSupport.concat(
                AttestationSupport.tlv(0x8B, new byte[] {slot}),
                AttestationSupport.tlv(0x8C, new byte[] {AttestationSupport.ACCESS_ALWAYS}),
                AttestationSupport.tlv(0x8D, new byte[] {AttestationSupport.ACCESS_NEVER}),
                AttestationSupport.tlv(0x8E, new byte[] {AttestationSupport.ALG_ECC_P256}),
                AttestationSupport.tlv(0x8F, new byte[] {AttestationSupport.ROLE_SIGN}),
                AttestationSupport.tlv(0x90, new byte[] {0x00})));
    AttestationAuthorityService.transmitExpect(
        session, new CommandAPDU(0x84, 0xDB, 0x3F, 0x00, definition), true);
  }

  private static boolean deleteProofKey(CardSession session, byte slot) {
    byte[] payload = deleteProofKeyPayload(slot);
    ResponseAPDU response = session.transmit(new CommandAPDU(0x84, 0xDB, 0x3F, 0x00, payload));
    if (response.getSW() == 0x9000) {
      return true;
    }
    if (response.getSW() == 0x6985) {
      return false;
    }
    throw new IllegalStateException(
        "delete proof key failed SW=" + String.format("0x%04X", response.getSW()));
  }

  static byte[] deleteProofKeyPayload(byte slot) {
    return AttestationSupport.tlv(
        0x67,
        AttestationSupport.concat(
            AttestationSupport.tlv(0x8B, new byte[] {slot}),
            AttestationSupport.tlv(0x8E, new byte[] {AttestationSupport.ALG_ECC_P256})));
  }

  private static byte[] collect(CardSession session, ResponseAPDU initial) {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    ResponseAPDU current = initial;
    while ((current.getSW() & 0xFF00) == 0x6100) {
      output.write(current.getData(), 0, current.getData().length);
      int le = current.getSW() & 0xFF;
      current = session.transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00, le == 0 ? 256 : le));
    }
    if (current.getSW() != 0x9000) {
      throw new IllegalStateException("attestation proof failed SW=" + String.format("0x%04X", current.getSW()));
    }
    output.write(current.getData(), 0, current.getData().length);
    return output.toByteArray();
  }

  private static ResponseAPDU expect(ResponseAPDU response, String label) {
    if (response.getSW() != 0x9000) {
      throw new IllegalStateException(label + " failed SW=" + String.format("0x%04X", response.getSW()));
    }
    return response;
  }

  private static X509Certificate parseCertificate(byte[] der) throws Exception {
    return (X509Certificate)
        CertificateFactory.getInstance("X.509")
            .generateCertificate(new java.io.ByteArrayInputStream(der));
  }
}
