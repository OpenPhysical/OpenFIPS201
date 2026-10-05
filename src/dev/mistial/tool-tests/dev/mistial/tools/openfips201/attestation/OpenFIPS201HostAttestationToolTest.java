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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import dev.mistial.tools.openfips201.common.CardSession;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.crypto.Passphrases;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Host attestation proof flow: the temporary proof key's definition, generation, attestation under
 * SCP and cleanup. The F9 authority itself is generated on the card and certified by the Issuer SAM
 * (see the issuance package); the host never holds an F9 private key.
 */
class OpenFIPS201HostAttestationToolTest {
  @Test
  void proofKeyDeletePayloadNamesSlotAndMechanism() {
    assertArrayEquals(
        hex("67068B019A8E0111"),
        AttestationProofService.deleteProofKeyPayload(AttestationProofService.DEFAULT_PROOF_SLOT));
  }

  @Test
  void proofKeyDefinitionUsesPivAuthenticationAccessModesAndIsNotImportable() {
    // 90 01 00: ATTR_NONE, so FIPS builds (which refuse importable 9A) accept the proof key.
    assertArrayEquals(
        hex("66128B019A8C01018D01098E01118F0104900100"),
        AttestationProofService.proofKeyDefinition(AttestationProofService.DEFAULT_PROOF_SLOT));
  }

  @Test
  void proofKeyDefinitionForOtherSlotsIsAlwaysAccessible() {
    assertArrayEquals(
        hex("66128B01828C017F8D017F8E01118F0104900100"),
        AttestationProofService.proofKeyDefinition((byte) 0x82));
  }

  @Test
  void generatedKeyTemplateYieldsTheP256Point() {
    byte[] point = new byte[65];
    point[0] = 0x04;
    point[64] = 0x5A;
    byte[] template = AttestationSupport.tlv(0x7F49, AttestationSupport.tlv(0x86, point));
    assertArrayEquals(point, AttestationProofService.extractPublicPoint(template));
    assertThrows(
        IllegalStateException.class,
        () ->
            AttestationProofService.extractPublicPoint(
                AttestationSupport.tlv(0x7F49, hex("8600"))));
  }

  @Test
  void publicPointIsUncompressedAndFixedWidth() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair pair = generator.generateKeyPair();
    byte[] point = AttestationSupport.publicPoint(pair.getPublic());
    assertEquals(65, point.length);
    assertEquals(0x04, point[0]);
    assertThrows(
        IllegalArgumentException.class,
        () -> AttestationSupport.fixed(java.math.BigInteger.ONE.shiftLeft(0x108), 32));
  }

  @Test
  void autoScpLetsInitializeUpdateReportTheProtocol() {
    assertEquals(ScpConfig.Mode.AUTO, ScpConfig.parseMode("auto"));
  }

  @Test
  void explicitScpModesUseOneRequestedProtocol() {
    assertEquals(ScpConfig.Mode.SCP02, ScpConfig.parseMode("02"));
    assertEquals(ScpConfig.Mode.SCP03, ScpConfig.parseMode("03"));
  }

  @Test
  void reportedScpVersionIsExposedAfterAuthentication() {
    assertThrows(IllegalArgumentException.class, () -> ScpConfig.parseMode("scp01"));
  }

  @Test
  void emptyPassphraseIsRejected() {
    assertThrows(
        IllegalArgumentException.class, () -> Passphrases.requireNonEmpty(new char[0], "test"));
  }

  @Test
  void proofServiceDeletesTemporaryKeyWhenGenerationFails() throws Exception {
    ProofCleanupSession session = new ProofCleanupSession(0x6A80, 0x9000);

    IllegalStateException failure =
        assertThrows(
            IllegalStateException.class,
            () ->
                new AttestationProofService()
                    .prove(session, AttestationProofService.DEFAULT_PROOF_SLOT, true));

    assertTrue(failure.getMessage().contains("generate proof key failed SW=0x6A80"));
    assertEquals(1, session.deleteCommands, "Failed proof generation must still delete 9A");
  }

  @Test
  void proofServiceTreatsDeleteWarningAsCleanupFailure() throws Exception {
    ProofCleanupSession session = new ProofCleanupSession(0x6A80, 0x6985);

    IllegalStateException failure =
        assertThrows(
            IllegalStateException.class,
            () ->
                new AttestationProofService()
                    .prove(session, AttestationProofService.DEFAULT_PROOF_SLOT, true));

    assertTrue(failure.getMessage().contains("delete proof key failed SW=0x6985"));
    assertEquals(1, session.deleteCommands, "Cleanup failure must not be ignored");
  }

  @Test
  void proofServiceFailsWhenProofSlotAlreadyExists() throws Exception {
    ProofCleanupSession session = new ProofCleanupSession(0x9000, 0x9000);
    session.createStatus = 0x6E27;

    IllegalStateException failure =
        assertThrows(
            IllegalStateException.class,
            () ->
                new AttestationProofService()
                    .prove(session, AttestationProofService.DEFAULT_PROOF_SLOT, true));

    assertTrue(failure.getMessage().contains("APDU failed SW=0x6E27"));
    assertEquals(0, session.deleteCommands, "The tool must not delete a key it did not create");
  }

  @Test
  void proofServiceKeepsAttestationAndContinuationUnderScp() throws Exception {
    AttestationTestChains.Chain chain = AttestationTestChains.build();
    ProofTransportSession session = new ProofTransportSession(chain.leaf);

    new AttestationProofService().prove(session, AttestationProofService.DEFAULT_PROOF_SLOT, true);

    assertCommand(session.commands.get(0), 0x84, 0xDB, 0xFF, 0xFF);
    assertCommand(session.commands.get(1), 0x84, 0x47, 0x00, 0x9A);
    assertCommand(session.commands.get(2), 0x84, 0xF9, 0x9A, 0x00);
    assertCommand(session.commands.get(3), 0x84, 0xC0, 0x00, 0x00);
    assertCommand(session.commands.get(4), 0x84, 0xDB, 0xFF, 0xFF);
  }

  private static void assertCommand(CommandAPDU command, int cla, int ins, int p1, int p2) {
    assertEquals(cla, command.getCLA());
    assertEquals(ins, command.getINS());
    assertEquals(p1, command.getP1());
    assertEquals(p2, command.getP2());
  }

  private static byte[] hex(String value) {
    return dev.mistial.tools.openfips201.common.HexUtil.parse(value);
  }

  private static final class ProofCleanupSession implements CardSession {
    private final int generateStatus;
    private final int deleteStatus;
    int createStatus = 0x9000;
    int deleteCommands;

    ProofCleanupSession(int generateStatus, int deleteStatus) {
      this.generateStatus = generateStatus;
      this.deleteStatus = deleteStatus;
    }

    @Override
    public ResponseAPDU transmit(CommandAPDU command) {
      if (command.getINS() == 0xDB && command.getP1() == 0xFF && command.getP2() == 0xFF) {
        byte[] data = command.getData();
        if (data.length > 0 && data[0] == (byte) 0x67) {
          deleteCommands++;
          return sw(deleteStatus);
        }
        return sw(createStatus);
      }
      if (command.getINS() == 0x47) {
        return sw(generateStatus);
      }
      return ResponseAPDU.OK;
    }

    @Override
    public void close() {}
  }

  private static final class ProofTransportSession implements CardSession {
    private final byte[] certificate;
    private final byte[] generatedKey;
    final List<CommandAPDU> commands = new ArrayList<CommandAPDU>();

    ProofTransportSession(byte[] certificate) {
      this.certificate = certificate.clone();
      byte[] point = new byte[65];
      point[0] = 0x04;
      this.generatedKey = AttestationSupport.tlv(0x7F49, AttestationSupport.tlv(0x86, point));
    }

    @Override
    public ResponseAPDU transmit(CommandAPDU command) {
      commands.add(command);
      if (command.getINS() == 0x47) {
        return response(generatedKey, 0x9000);
      }
      if (command.getINS() == 0xF9) {
        return sw(0x6100 | Math.min(certificate.length, 0xFF));
      }
      if (command.getINS() == 0xC0) {
        return response(certificate, 0x9000);
      }
      return ResponseAPDU.OK;
    }

    @Override
    public void close() {}
  }

  private static ResponseAPDU sw(int statusWord) {
    return new ResponseAPDU(new byte[] {(byte) (statusWord >>> 8), (byte) statusWord});
  }

  private static ResponseAPDU response(byte[] data, int statusWord) {
    byte[] response = new byte[data.length + 2];
    System.arraycopy(data, 0, response, 0, data.length);
    response[response.length - 2] = (byte) (statusWord >>> 8);
    response[response.length - 1] = (byte) statusWord;
    return new ResponseAPDU(response);
  }
}
