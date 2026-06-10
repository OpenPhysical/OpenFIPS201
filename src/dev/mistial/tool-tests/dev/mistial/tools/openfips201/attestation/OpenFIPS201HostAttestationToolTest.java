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
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import pro.javacard.gp.GPSecureChannelVersion;

class OpenFIPS201HostAttestationToolTest {
  @Test
  void f9KeyDefinitionMatchesAppletAdminShape() {
    assertArrayEquals(
        hex("66128B01F98C01008D01008E01118F0104900110"),
        AttestationSupport.createF9KeyDefinition());
  }

  @Test
  void changeReferenceDataElementWrapsOneAuthorityElement() {
    assertArrayEquals(
        hex("300486020102"),
        AttestationSupport.changeReferenceDataElement(
            (byte) 0x86, new byte[] {(byte) 0x01, (byte) 0x02}));
  }

  @Test
  void clearReferenceDataElementWrapsF9ClearElement() {
    // E0, not FF: a tag byte with bits B5-B1 all set begins a BER multi-byte tag, which cannot
    // be parsed as a key element tag.
    assertArrayEquals(hex("3002E000"), AttestationSupport.clearReferenceDataElement());
  }

  @Test
  void issuerCertificateObjectUsesFullThreeByteObjectIdentifier() {
    byte[] objectId = hex("5FFF01");
    byte[] cert = hex("010203");
    assertArrayEquals(
        hex("5C035FFF01530A7003010203710100FE00"),
        AttestationSupport.putDataPayload(objectId, AttestationSupport.certificateObject(cert)));
    assertArrayEquals(
        hex("640E8B035FFF018C017F8D017F91019B"),
        AttestationSupport.createDataObjectDefinition(objectId));
  }

  @Test
  void f9IssuerValidationAcceptsDifferentSubjectNames() throws Exception {
    KeyPair keyPair = AttestationSupport.generateF9KeyPair();
    X509Certificate certificate =
        AttestationSupport.createIssuerCertificate(
            keyPair,
            new X500Name("CN=Factory Batch 42,O=Example Devices,C=AU"),
            utcDate("2026-01-01"),
            utcDate("2030-01-01"));

    AttestationSupport.validateF9Issuer(keyPair.getPrivate(), certificate);
    F9Profile profile = AttestationSupport.profileFromIssuer(keyPair.getPrivate(), certificate);
    assertEquals(0x41, profile.publicPoint.length, "P-256 public point should be uncompressed");
    assertEquals(0x20, profile.privateScalar.length, "P-256 private scalar should be fixed width");
    assertTrue(
        profile.subjectDer.length > 0,
        "Subject DER should be uploaded from the issuer certificate");
    assertTrue(
        profile.validityDer.length > 0,
        "Validity DER should be uploaded from the issuer certificate");
  }

  @Test
  void f9IssuerValidationRejectsMismatchedPrivateKey() throws Exception {
    KeyPair issuerKeyPair = AttestationSupport.generateF9KeyPair();
    KeyPair otherKeyPair = AttestationSupport.generateF9KeyPair();
    X509Certificate certificate =
        AttestationSupport.createIssuerCertificate(
            issuerKeyPair,
            new X500Name("CN=Example F9 Attestation"),
            utcDate("2026-01-01"),
            utcDate("2030-01-01"));

    assertThrows(
        Exception.class,
        () -> AttestationSupport.validateF9Issuer(otherKeyPair.getPrivate(), certificate));
  }

  @Test
  void provisionerSendsExpectedAdministrativeSequence() throws Exception {
    KeyPair keyPair = AttestationSupport.generateF9KeyPair();
    X509Certificate certificate =
        AttestationSupport.createIssuerCertificate(
            keyPair,
            new X500Name("CN=Example F9 Attestation,O=Example"),
            utcDate("2026-01-01"),
            utcDate("2030-01-01"));
    RecordingSession session = new RecordingSession();

    OpenFips201Provisioner.provisionAuthority(
        session,
        AttestationSupport.profileFromIssuer(keyPair.getPrivate(), certificate),
        AttestationSupport.der(certificate),
        hex("5FFF01"));

    assertTrue(
        session.commands.size() >= 0x08,
        "Provisioning should create F9, clear it, import four elements, create object, and store"
            + " cert");
    assertCommand(session.commands.get(0), 0x84, 0xDB, 0x3F, 0x00);
    assertArrayEquals(
        AttestationSupport.createF9KeyDefinition(), session.commands.get(0).getData());
    assertCommand(session.commands.get(1), 0x84, 0x24, 0x11, 0xF9);
    assertArrayEquals(
        AttestationSupport.clearReferenceDataElement(), session.commands.get(1).getData());
    assertCommand(session.commands.get(2), 0x84, 0x24, 0x11, 0xF9);
    assertEquals(
        (byte) 0x86,
        session.commands.get(2).getData()[0x02],
        "Public point should be uploaded first");
    assertCommand(session.commands.get(3), 0x84, 0x24, 0x11, 0xF9);
    assertEquals(
        (byte) 0x87,
        session.commands.get(3).getData()[0x02],
        "Private scalar should be uploaded second");
    assertCommand(session.commands.get(4), 0x84, 0x24, 0x11, 0xF9);
    assertEquals(
        (byte) 0x92, session.commands.get(4).getData()[0x02], "Subject should be uploaded third");
    assertCommand(session.commands.get(5), 0x84, 0x24, 0x11, 0xF9);
    assertEquals(
        (byte) 0x93, session.commands.get(5).getData()[0x02], "Validity should be uploaded last");
    assertCommand(session.commands.get(6), 0x84, 0xDB, 0x3F, 0x00);
    assertArrayEquals(
        AttestationSupport.createDataObjectDefinition(hex("5FFF01")),
        session.commands.get(6).getData());

    CommandAPDU firstPutData = session.commands.get(7);
    assertEquals(0xDB, firstPutData.getINS());
    assertEquals(0x3F, firstPutData.getP1());
    assertEquals(0xFF, firstPutData.getP2());
    assertArrayEquals(hex("5C035FFF01"), copy(firstPutData.getData(), 0, 5));
  }

  @Test
  void provisionerKeepsChainedPutDataInsideScp03ShortApduBudget() throws Exception {
    F9Profile profile = new F9Profile(new byte[0x41], new byte[0x20], hex("3000"), hex("3000"));
    // Size chosen to be representative of a full attestation certificate (near the applet's
    // response buffer limit) to exercise chained PUT DATA under SCP.
    byte[] largeCertificate = new byte[0x0300];
    RecordingSession session = new RecordingSession();

    OpenFips201Provisioner.provisionAuthority(
        session, profile, largeCertificate, AttestationSupport.DEFAULT_ISSUER_OBJECT_ID);

    for (CommandAPDU command : session.commands) {
      if (command.getINS() == 0xDB && command.getP2() == 0xFF) {
        assertTrue(
            command.getData().length <= 0xEF, "PUT DATA chunks must fit wrapped SCP03 APDUs");
      }
    }
  }

  @Test
  void autoScpLetsInitializeUpdateReportTheProtocol() {
    assertEquals(null, GlobalPlatformCardSession.ScpMode.AUTO.toSecureChannelVersion());
  }

  @Test
  void explicitScpModesUseOneRequestedProtocol() {
    assertEquals(
        GPSecureChannelVersion.SCP.SCP02,
        GlobalPlatformCardSession.ScpMode.SCP02.toSecureChannelVersion().scp);
    assertEquals(
        GPSecureChannelVersion.SCP.SCP03,
        GlobalPlatformCardSession.ScpMode.SCP03.toSecureChannelVersion().scp);
  }

  @Test
  void reportedScpVersionIsExposedAfterAuthentication() {
    assertEquals(
        GlobalPlatformCardSession.ScpMode.SCP02,
        GlobalPlatformCardSession.ScpMode.fromSecureChannelVersion(
            new GPSecureChannelVersion(GPSecureChannelVersion.SCP.SCP02, 0x00)));
    assertEquals(
        GlobalPlatformCardSession.ScpMode.SCP03,
        GlobalPlatformCardSession.ScpMode.fromSecureChannelVersion(
            new GPSecureChannelVersion(GPSecureChannelVersion.SCP.SCP03, 0x00)));
  }

  @Test
  void emptyPassphraseIsRejected() {
    assertThrows(
        IllegalArgumentException.class,
        () -> AttestationTool.requireNonEmptyPassphrase(new char[0], "test"));
  }

  @Test
  void oversizedFixedWidthIntegerIsRejected() {
    assertThrows(
        IllegalArgumentException.class,
        () -> AttestationSupport.privateScalar(new OversizedEcPrivateKey()));
  }

  @Test
  void failedApduIncludesStatusMeaning() {
    F9Profile profile = new F9Profile(new byte[0x41], new byte[0x20], hex("3000"), hex("3000"));
    FailingSession session = new FailingSession(0x6A80);

    IllegalStateException failure =
        assertThrows(
            IllegalStateException.class,
            () ->
                OpenFips201Provisioner.provisionAuthority(
                    session,
                    profile,
                    new byte[] {(byte) 0x01},
                    AttestationSupport.DEFAULT_ISSUER_OBJECT_ID));
    assertTrue(failure.getMessage().contains("malformed authority data"));
  }

  private static void assertCommand(CommandAPDU command, int cla, int ins, int p1, int p2) {
    assertEquals(cla, command.getCLA());
    assertEquals(ins, command.getINS());
    assertEquals(p1, command.getP1());
    assertEquals(p2, command.getP2());
  }

  private static Date utcDate(String value) {
    return Date.from(LocalDate.parse(value).atStartOfDay().toInstant(ZoneOffset.UTC));
  }

  private static byte[] copy(byte[] source, int offset, int length) {
    byte[] output = new byte[length];
    System.arraycopy(source, offset, output, 0, length);
    return output;
  }

  private static byte[] hex(String value) {
    return AttestationSupport.hex(value);
  }

  private static final class RecordingSession implements CardSession {
    final List<CommandAPDU> commands = new ArrayList<CommandAPDU>();

    @Override
    public ResponseAPDU transmit(CommandAPDU command) {
      commands.add(command);
      return ResponseAPDU.OK;
    }

    @Override
    public void close() {}
  }

  @Test
  void f9IssuerValidationRejectsNonP256Key() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp384r1"));
    KeyPair keyPair = generator.generateKeyPair();
    X509Certificate certificate =
        AttestationSupport.createIssuerCertificate(
            keyPair, new X500Name("CN=P384 Issuer"), utcDate("2026-01-01"), utcDate("2030-01-01"));

    assertThrows(
        Exception.class,
        () -> AttestationSupport.validateF9Issuer(keyPair.getPrivate(), certificate),
        "The F9 authority must be a P-256 key pair");
  }

  @Test
  void f9IssuerValidationRejectsExpiredCertificate() throws Exception {
    KeyPair keyPair = AttestationSupport.generateF9KeyPair();
    X509Certificate certificate =
        AttestationSupport.createIssuerCertificate(
            keyPair,
            new X500Name("CN=Expired Issuer"),
            utcDate("2020-01-01"),
            utcDate("2021-01-01"));

    assertThrows(
        Exception.class,
        () -> AttestationSupport.validateF9Issuer(keyPair.getPrivate(), certificate),
        "An issuer certificate outside its validity window must be rejected");
  }

  @Test
  void profileRejectsOversizeIssuerSubject() throws Exception {
    KeyPair keyPair = AttestationSupport.generateF9KeyPair();
    X509Certificate certificate =
        AttestationSupport.createIssuerCertificate(
            keyPair,
            new X500Name("CN=" + repeated('C', 80) + ",O=" + repeated('O', 60)),
            utcDate("2026-01-01"),
            utcDate("2030-01-01"));

    Exception failure =
        assertThrows(
            Exception.class,
            () -> AttestationSupport.profileFromIssuer(keyPair.getPrivate(), certificate),
            "Issuer subjects above the applet limit must fail before any card communication");
    assertTrue(
        failure.getMessage().contains("at most " + AttestationSupport.LENGTH_SUBJECT_MAX),
        "The failure must state the applet's subject limit");
  }

  private static String repeated(char value, int count) {
    char[] chars = new char[count];
    java.util.Arrays.fill(chars, value);
    return new String(chars);
  }

  @Test
  void f9IssuerValidationRejectsNonCaCertificate() throws Exception {
    KeyPair keyPair = AttestationSupport.generateF9KeyPair();
    X509Certificate certificate = endEntityCertificate(keyPair, new X500Name("CN=Not A CA"));

    assertThrows(
        Exception.class,
        () -> AttestationSupport.validateF9Issuer(keyPair.getPrivate(), certificate),
        "An issuer certificate without the CA basic constraint must be rejected");
  }

  @Test
  void provisionerToleratesExistingDefinitionsOnReprovision() throws Exception {
    KeyPair keyPair = AttestationSupport.generateF9KeyPair();
    X509Certificate certificate =
        AttestationSupport.createIssuerCertificate(
            keyPair,
            new X500Name("CN=Reprovision,O=Example"),
            utcDate("2026-01-01"),
            utcDate("2030-01-01"));
    AlreadyExistsSession session = new AlreadyExistsSession();

    OpenFips201Provisioner.provisionAuthority(
        session,
        AttestationSupport.profileFromIssuer(keyPair.getPrivate(), certificate),
        AttestationSupport.der(certificate),
        hex("5FFF01"));

    assertEquals(
        2,
        session.existingDefinitions,
        "Both create commands must tolerate the already-exists status word");
  }

  private static X509Certificate endEntityCertificate(KeyPair keyPair, X500Name subject)
      throws Exception {
    AttestationSupport.ensureProvider();
    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            subject,
            BigInteger.ONE,
            utcDate("2026-01-01"),
            utcDate("2030-01-01"),
            subject,
            keyPair.getPublic());
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(keyPair.getPrivate());
    return new JcaX509CertificateConverter()
        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .getCertificate(builder.build(signer));
  }

  // Reports the already-exists status word for the create-definition commands so re-provisioning
  // a card that already carries the F9 key and issuer data object continues past them.
  private static final class AlreadyExistsSession implements CardSession {
    int existingDefinitions;

    @Override
    public ResponseAPDU transmit(CommandAPDU command) {
      if (command.getINS() == 0xDB && command.getP2() == 0x00) {
        existingDefinitions++;
        return new ResponseAPDU(new byte[] {(byte) 0x6E, (byte) 0x27});
      }
      return ResponseAPDU.OK;
    }

    @Override
    public void close() {}
  }

  private static final class FailingSession implements CardSession {
    private final int statusWord;

    FailingSession(int statusWord) {
      this.statusWord = statusWord;
    }

    @Override
    public ResponseAPDU transmit(CommandAPDU command) {
      return new ResponseAPDU(new byte[] {(byte) (statusWord >> 8), (byte) statusWord});
    }

    @Override
    public void close() {}
  }

  private static final class OversizedEcPrivateKey
      implements java.security.interfaces.ECPrivateKey {
    @Override
    public BigInteger getS() {
      return BigInteger.ONE.shiftLeft(0x0108);
    }

    @Override
    public String getAlgorithm() {
      return "EC";
    }

    @Override
    public String getFormat() {
      return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
      return new byte[0];
    }

    @Override
    public java.security.spec.ECParameterSpec getParams() {
      try {
        java.security.AlgorithmParameters parameters =
            java.security.AlgorithmParameters.getInstance("EC");
        parameters.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
        return parameters.getParameterSpec(java.security.spec.ECParameterSpec.class);
      } catch (Exception e) {
        throw new IllegalStateException(e);
      }
    }
  }
}
