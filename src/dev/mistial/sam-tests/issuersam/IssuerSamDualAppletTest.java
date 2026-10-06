package dev.mistial.tests.issuersam;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import apdu4j.core.BIBO;
import com.makina.security.openfips201.OpenFIPS201;
import java.io.ByteArrayInputStream;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.JavaCardEngine;

/**
 * The PIV applet and the SAM together, driven through the per-card issuance sequence: the card
 * generates F9 and proves possession over the SAM nonce, the SAM issues the F9 certificate, the
 * card loads and serves it, and a leaf attested by the card validates from the root to the leaf.
 *
 * <p>Both applets are installed in the SAM's engine to show they coexist. The issuance itself runs
 * against a second engine holding the card, matching the production topology of distinct card and
 * SAM readers: on one card, selecting the PIV applet deselects the SAM, which by design clears its
 * nonce and operator session, and jCardEngine offers no logical channels.
 */
class IssuerSamDualAppletTest extends IssuerSamTestSupport {
  private static final byte[] PIV_AID_BYTES = hex("A000000308000010000100");
  private static final AID PIV_AID = new AID(PIV_AID_BYTES, (short) 0, (byte) PIV_AID_BYTES.length);
  private static final byte[] F9_DEFINITION = hex("6612 8B01F9 8C0100 8D0100 8E0111 8F0104 900100");
  private static final byte[] KEY_9A_DEFINITION =
      hex("6612 8B019A 8C0101 8D0109 8E0111 8F0104 900100");
  private static final byte[] GENERATE_P256 = hex("AC03800111");
  private static final byte[] LOCAL_PIN = hex("313233343536FFFF");

  private BIBO samSession;
  private BIBO cardSession;

  @Override
  protected void installApplet() {
    super.installApplet();
    engine.installApplet(PIV_AID, OpenFIPS201.class, new byte[0]);
  }

  @AfterEach
  void closeCard() {
    if (cardSession != null) cardSession.close();
  }

  private ResponseAPDU selectPiv() {
    return transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, PIV_AID_BYTES, 256));
  }

  /** Runs an exchange against the card reader instead of the SAM reader. */
  private <T> T onCard(Supplier<T> action) {
    if (cardSession == null) {
      JavaCardEngine card = JavaCardEngine.create();
      card.installApplet(PIV_AID, OpenFIPS201.class, new byte[0]);
      cardSession = card.connect();
      samSession = session;
    }
    session = cardSession;
    try {
      return action.get();
    } finally {
      session = samSession;
    }
  }

  @Test
  void bothAppletsCoexistAndKeepSeparateState() {
    Params params = Params.variant(root, 1);
    personalize(params);
    withMockedScp(() -> assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY"));
    assertSw(0x9000, selectPiv(), "SELECT PIV");
    assertSw(0x9000, selectSam(), "SELECT SAM again");
    withMockedScp(
        () -> {
          assertEquals(LC_OPERATIONAL, lifecycle());
          // Selecting the PIV applet deselected the SAM and cleared the operator session.
          assertSw(0x6982, transmit(0x84, 0x84, 0x00, 0x00), "PIN reset by deselect");
        });
    assertEquals(referenceOpid(params, 1), opidOf(issueOne().certificate));
  }

  @Test
  void fullIssuanceSequenceRootSamCardLeaf() throws Exception {
    Params params = Params.variant(root, 0);
    personalize(params);
    X509CertificateHolder samCert = samCertificate();

    // Card: define and generate F9 over SCP.
    byte[] f9Point =
        onCard(
            () ->
                withMockedScp(
                    () -> {
                      assertSw(0x9000, selectPiv(), "SELECT PIV");
                      assertSw(
                          0x9000, transmit(0x84, 0xDB, 0xFF, 0xFF, F9_DEFINITION), "define F9");
                      byte[] generated =
                          collect(transmit(0x84, 0x47, 0x00, 0xF9, GENERATE_P256), "generate F9");
                      return tlvValue(Arrays.copyOfRange(generated, 3, generated.length), 0x86);
                    }));

    // SAM: BEGIN; card: PROVE over N; host pre-verifies; SAM: ISSUE.
    byte[] certificate =
        withMockedScp(
            () -> {
              assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY");
              byte[] nonce = beginIssuance();
              byte[] pop =
                  onCard(() -> collect(transmit(0x84, 0xF9, 0xF9, 0x01, nonce), "F9 PROVE"));
              assertTrue(
                  verify(publicKey(f9Point), concat("OPF9POP".getBytes(), nonce, f9Point), pop),
                  "host pre-verifies the PoP");
              ResponseAPDU response =
                  transmit(0x84, 0x2A, 0x00, 0xF9, issueData(f9Point, pop, defaultValidity()));
              return parseIssued(collect(response, "ISSUE")).certificate;
            });
    assertEquals(referenceOpid(params, 1), opidOf(certificate));

    // Card: load the SAM-issued certificate, read it back byte-identical, then attest 9A.
    byte[] leaf =
        onCard(
            () -> {
              withMockedScp(
                  () -> {
                    assertSw(
                        0x9000,
                        transmitChained(0x84, 0x24, 0x11, 0xF9, tlv(0x30, tlv(0x70, certificate))),
                        "load F9 certificate");
                    assertSw(
                        0x9000, transmit(0x84, 0xDB, 0xFF, 0xFF, KEY_9A_DEFINITION), "define 9A");
                    assertSw(0x9000, transmit(0x84, 0x24, 0x01, 0x80, LOCAL_PIN), "set PIN");
                    collect(transmit(0x84, 0x47, 0x00, 0x9A, GENERATE_P256), "generate 9A");
                  });
              assertSw(0x9000, selectPiv(), "SELECT PIV");
              assertArrayEquals(
                  certificate,
                  collect(transmit(new CommandAPDU(0x00, 0xF9, 0xF9, 0x00, 256)), "read back"));
              assertSw(0x9000, transmit(0x00, 0x20, 0x00, 0x80, LOCAL_PIN), "VERIFY PIN");
              return collect(transmit(new CommandAPDU(0x00, 0xF9, 0x9A, 0x00, 256)), "attest 9A");
            });

    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    List<X509Certificate> chain = new ArrayList<>();
    chain.add(x509(factory, leaf));
    chain.add(x509(factory, certificate));
    chain.add(x509(factory, samCert.getEncoded()));
    CertPath path = factory.generateCertPath(chain);
    PKIXParameters parameters =
        new PKIXParameters(
            Collections.singleton(
                new TrustAnchor(
                    new JcaX509CertificateConverter().getCertificate(root.certificate), null)));
    parameters.setRevocationEnabled(false);
    CertPathValidator.getInstance("PKIX").validate(path, parameters);
  }

  private static String opidOf(byte[] certificate) {
    try {
      return IssuerSamIssuanceTest.serialNumberOf(new X509CertificateHolder(certificate));
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static X509Certificate x509(CertificateFactory factory, byte[] encoded) throws Exception {
    return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(encoded));
  }
}
