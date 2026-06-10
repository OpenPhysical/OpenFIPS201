/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
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

package dev.mistial.tools.openfips201.attestation;

import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;

final class OpenFips201Provisioner {
  private static final int SW_NO_ERROR = 0x9000;
  private static final int SW_PUT_DATA_OBJECT_EXISTS = 0x6E27;
  private static final int CLA_CHAINING = 0x10;
  private static final int MAX_SHORT_APDU_DATA = 0xEF;

  private OpenFips201Provisioner() {}

  static void provisionAuthority(
      CardSession session, F9Profile profile, byte[] issuerCertificateDer, byte[] issuerObjectId) {
    try {
      transmitExpect(
          session,
          new CommandAPDU(0x84, 0xDB, 0x3F, 0x00, AttestationSupport.createF9KeyDefinition()),
          true);

      // Reset F9 before importing the new profile. On an already-committed card this prevents
      // partial reprovisioning from activating a mixed new-key/old-profile authority.
      transmitExpect(
          session,
          new CommandAPDU(
              0x84,
              0x24,
              AttestationSupport.ALG_ECC_P256 & 0xFF,
              AttestationSupport.F9_AUTHORITY & 0xFF,
              AttestationSupport.clearReferenceDataElement()),
          false);

      // These CHANGE REFERENCE DATA elements match docs/ATTESTATION.md: public point (0x86),
      // private scalar (0x87), issuer subject DER (0x92), then issuer validity DER (0x93). The
      // applet commits only when all four staged elements are present.
      transmitExpect(
          session,
          new CommandAPDU(
              0x84,
              0x24,
              AttestationSupport.ALG_ECC_P256 & 0xFF,
              AttestationSupport.F9_AUTHORITY & 0xFF,
              AttestationSupport.changeReferenceDataElement((byte) 0x86, profile.publicPoint)),
          false);
      transmitExpect(
          session,
          new CommandAPDU(
              0x84,
              0x24,
              AttestationSupport.ALG_ECC_P256 & 0xFF,
              AttestationSupport.F9_AUTHORITY & 0xFF,
              AttestationSupport.changeReferenceDataElement((byte) 0x87, profile.privateScalar)),
          false);
      transmitExpect(
          session,
          new CommandAPDU(
              0x84,
              0x24,
              AttestationSupport.ALG_ECC_P256 & 0xFF,
              AttestationSupport.F9_AUTHORITY & 0xFF,
              AttestationSupport.changeReferenceDataElement((byte) 0x92, profile.subjectDer)),
          false);
      transmitExpect(
          session,
          new CommandAPDU(
              0x84,
              0x24,
              AttestationSupport.ALG_ECC_P256 & 0xFF,
              AttestationSupport.F9_AUTHORITY & 0xFF,
              AttestationSupport.changeReferenceDataElement((byte) 0x93, profile.validityDer)),
          false);

      transmitExpect(
          session,
          new CommandAPDU(
              0x84,
              0xDB,
              0x3F,
              0x00,
              AttestationSupport.createDataObjectDefinition(issuerObjectId)),
          true);
      byte[] body = AttestationSupport.certificateObject(issuerCertificateDer);
      sendChainedPutData(session, AttestationSupport.putDataPayload(issuerObjectId, body));
    } finally {
      profile.clearPrivateScalarCopy();
    }
  }

  private static void sendChainedPutData(CardSession session, byte[] payload) {
    int offset = 0;
    while (offset < payload.length) {
      int chunkLength = Math.min(MAX_SHORT_APDU_DATA, payload.length - offset);
      byte[] chunk = new byte[chunkLength];
      System.arraycopy(payload, offset, chunk, 0, chunkLength);
      offset += chunkLength;
      int cla = offset < payload.length ? CLA_CHAINING : 0x00;
      transmitExpect(session, new CommandAPDU(cla, 0xDB, 0x3F, 0xFF, chunk), false);
    }
  }

  private static void transmitExpect(
      CardSession session, CommandAPDU command, boolean allowAlreadyExists) {
    ResponseAPDU response = session.transmit(command);
    if (response.getSW() == SW_NO_ERROR) {
      return;
    }
    if (allowAlreadyExists && response.getSW() == SW_PUT_DATA_OBJECT_EXISTS) {
      return;
    }
    throw new IllegalStateException(
        "APDU failed, SW="
            + String.format("0x%04X", response.getSW())
            + " ("
            + statusMeaning(response.getSW())
            + ") command="
            + command.toLogString());
  }

  private static String statusMeaning(int sw) {
    switch (sw) {
      case 0x6982:
        return "security status not satisfied; check SCP and target access policy";
      case 0x6985:
        return "authority or target state is incomplete, or target key was not generated on-card";
      case 0x6A80:
        return "malformed authority data, malformed DER, unsupported authority field, or key-pair"
            + " mismatch";
      case 0x6A84:
        return "configured subject, validity, or generated object exceeds applet limits";
      case 0x6A86:
        return "invalid command parameters";
      case 0x6A88:
        return "target slot or key reference not found";
      case SW_PUT_DATA_OBJECT_EXISTS:
        return "object already exists";
      default:
        return "see docs/ATTESTATION.md status words";
    }
  }
}
