package dev.mistial.openphysical.sam;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Date;
import javacard.framework.JCSystem;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Time;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * The worst-case F9 certificate and ISSUE response: a 128-octet SAM subject, a 96-octet subject
 * template, a GeneralizedTime validity, a four-octet issuanceSeq and a five-octet eventSeq INTEGER.
 * The certificate must fit the PIV card's 0x2F8-octet limit and the whole response the I/O buffer.
 */
class F9CertificateSizeTest {
  /** {@code PIVAttestation.LENGTH_AUTHORITY_CERT_MAX}. */
  private static final int PIV_AUTHORITY_CERT_MAX = 0x2F8;

  private static final int SIGNATURE_MAX = 72;

  private AutoCloseable engineContext;

  @BeforeEach
  void enterEngine() throws Exception {
    engineContext = WhiteBox.engineContext();
  }

  @AfterEach
  void leaveEngine() throws Exception {
    engineContext.close();
  }

  @Test
  void worstCaseCertificateAndResponseFit() throws Exception {
    try (MockedStatic<JCSystem> system = Mockito.mockStatic(JCSystem.class)) {
      WhiteBox.mockTransientStorage(system);
      new WhiteBox.Transactions().install(system, () -> {}, () -> {});
      WhiteBox.Fixture f = new WhiteBox.Fixture();

      byte[] samSubject =
          new X500Name("C=US,O=" + repeat('O', 45) + ",CN=" + repeat('C', 46)).getEncoded("DER");
      assertEquals(SamConst.LENGTH_SAM_SUBJECT_MAX, samSubject.length, "SAM subject fixture");
      System.arraycopy(samSubject, 0, f.state.samCert, 0, samSubject.length);
      f.state.samCertLength = (short) samSubject.length;
      f.state.samSubjectOffset = 0;
      f.state.samSubjectLength = (short) samSubject.length;

      byte[] template =
          new X500Name("C=US,O=" + repeat('O', 30) + ",CN=" + repeat('C', 31)).getEncoded("DER");
      byte[] rdns = Arrays.copyOfRange(template, 2, template.length);
      assertEquals(SamConst.LENGTH_F9_TEMPLATE_MAX, rdns.length, "template fixture");
      System.arraycopy(rdns, 0, f.state.f9SubjectTemplate, 0, rdns.length);
      f.state.f9SubjectTemplateLength = (short) rdns.length;

      // issuanceSeq 99 999 999 (four octets) and eventSeq 0xFFFFFFFF (a five-octet INTEGER).
      System.arraycopy(U32Test.u32(99_999_998L), 0, f.state.issued, 0, 4);
      System.arraycopy(U32Test.u32(99_999_999L), 0, f.state.quota, 0, 4);
      System.arraycopy(U32Test.u32(0xFFFFFFFEL), 0, f.state.eventSeq, 0, 4);

      f.request = request(f, generalizedValidity());
      short length = f.issue();

      byte[] io = f.io;
      assertEquals(0x70, io[0] & 0xFF);
      assertEquals(0x82, io[1] & 0xFF);
      int certificateLength = ((io[2] & 0xFF) << 8) | (io[3] & 0xFF);
      byte[] der = Arrays.copyOfRange(io, 4, 4 + certificateLength);
      Certificate certificate = Certificate.getInstance(der);
      int signatureSlack = SIGNATURE_MAX - certificate.getSignature().getOctets().length;
      int serialSlack =
          SamConst.LENGTH_SERIAL
              - org.bouncycastle.util.BigIntegers.asUnsignedByteArray(
                      certificate.getSerialNumber().getValue())
                  .length;
      assertEquals(
          BigInteger.valueOf(0xFFFFFFFFL),
          org.bouncycastle.asn1.ASN1Integer.getInstance(
                  org.bouncycastle.asn1.ASN1Sequence.getInstance(
                          certificate
                              .getTBSCertificate()
                              .getExtensions()
                              .getExtension(
                                  new org.bouncycastle.asn1.ASN1ObjectIdentifier(
                                      "1.3.6.1.4.1.57923.20.10.10.2"))
                              .getExtnValue()
                              .getOctets())
                      .getObjectAt(2))
              .getValue(),
          "eventSeq fixture");

      int worstCertificate = certificateLength + signatureSlack + serialSlack;
      assertTrue(
          worstCertificate <= PIV_AUTHORITY_CERT_MAX,
          "worst-case F9 certificate of " + worstCertificate + " octets exceeds the card limit");
      int worstResponse = length + signatureSlack + serialSlack + (SIGNATURE_MAX - entrySig(io));
      assertTrue(
          worstResponse <= SamConst.LENGTH_IO_BUFFER,
          "worst-case ISSUE response of " + worstResponse + " octets exceeds the I/O buffer");
      assertEquals(SamConst.LENGTH_LAST_ENTRY, f.state.lastEntryLength, "ISSUE entry size");
    }
  }

  /** Length of the {@code 72} entry signature that ends the response. */
  private static int entrySig(byte[] io) {
    int cursor = 4 + (((io[2] & 0xFF) << 8) | (io[3] & 0xFF));
    assertEquals(0x71, io[cursor] & 0xFF);
    int entryLength = io[cursor + 1] == (byte) 0x81 ? io[cursor + 2] & 0xFF : io[cursor + 1];
    cursor += (io[cursor + 1] == (byte) 0x81 ? 3 : 2) + entryLength;
    assertEquals(0x72, io[cursor] & 0xFF);
    return io[cursor + 1] & 0xFF;
  }

  private static byte[] generalizedValidity() throws Exception {
    return new DERSequence(
            new ASN1Encodable[] {
              new Time(new Date(2_556_144_000_000L)), new Time(new Date(2_587_680_000_000L))
            })
        .getEncoded("DER");
  }

  /** A valid ISSUE request for a fresh nonce with the given validity. */
  private static byte[] request(WhiteBox.Fixture f, byte[] validity) throws Exception {
    f.ledger.beginIssuance();
    byte[] nonce = Arrays.copyOf(f.nonce, 32);
    byte[] point = WhiteBox.point(f.f9);
    java.security.Signature signer = java.security.Signature.getInstance("SHA256withECDSA");
    signer.initSign(f.f9.getPrivate());
    signer.update("OPF9POP".getBytes());
    signer.update(nonce);
    signer.update(point);
    byte[] pop = signer.sign();
    assertEquals(36, validity.length, "GeneralizedTime validity fixture");
    return WhiteBox.concat(
        WhiteBox.tlv(0x86, point),
        WhiteBox.tlv(0x9E, pop),
        WhiteBox.tlv(0x93, validity),
        WhiteBox.tlv(0x94, new byte[32]),
        WhiteBox.tlv(0x95, new byte[32]));
  }

  private static String repeat(char c, int count) {
    char[] chars = new char[count];
    Arrays.fill(chars, c);
    return new String(chars);
  }
}
