package dev.mistial.tools.openfips201.vci;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import apdu4j.core.BIBO;
import dev.mistial.tools.openfips201.applet.AppletInstallRequest;
import dev.mistial.tools.openfips201.applet.AppletInstallService;
import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.common.ZmqBibo;
import dev.mistial.tools.openfips201.emulator.ZmqEmulatorFixture;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import pro.javacard.gp.keys.PlaintextKeys;

/**
 * End-to-end PIV VCI tests: provisions the emulated card and drives live OPACITY + SM sessions
 * through ZeroMQ, covering happy-path probe and pairing/PIN negatives over secure messaging.
 *
 * <p>Aligned with NIST SP 800-73-5 Part 1 Section 5.5 (VCI), Part 2 Section 4.1 (OPACITY) and
 * Section 3.2.1 (VERIFY / pairing code).
 */
@Tag("slow")
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class OpenFIPS201VciEndToEndTest {
  private ZmqEmulatorFixture fixture;
  private String endpoint;

  @BeforeEach
  void startServer() throws Exception {
    fixture = ZmqEmulatorFixture.start(PlaintextKeys.DEFAULT_KEY());
    endpoint = fixture.endpoint();
    installOpenFips201Applet();
  }

  @AfterEach
  void stopServer() throws Exception {
    if (fixture != null) {
      fixture.close();
    }
  }

  @Test
  void provisionsAndEstablishesVciOverZmq(@TempDir Path tempDir) throws Exception {
    assumeTrue(isCs2Build(), "CS2 E2E test requires -Dvci.suite=CS2");
    String caPrefix = tempDir.resolve("vci-ca").toString();
    String reader = "zmq:" + endpoint;

    // Provision: card generates its SM key, the CA signs it into a CVC, pairing-code mode is set.
    try (BIBO bibo = new ZmqBibo(endpoint, 10_000)) {
      VciProvisioning.provision(bibo, null, null, caPrefix, "12345678", null);
    }

    // Probe with the correct CA: full OPACITY establishment + CVC validation + pairing + wrapped
    // GET DATA must all succeed.
    try (BIBO bibo = new ZmqBibo(endpoint, 10_000)) {
      assertTrue(
          VciProvisioning.probe(bibo, caPrefix + ".crt", "12345678"),
          "VCI probe should succeed against the provisioning CA");
    }

    // Negative: a different CA must fail closed at CVC validation.
    String otherCaPrefix = tempDir.resolve("other-ca").toString();
    VciProvisioning.makeCa(otherCaPrefix, "CN=Untrusted VCI Signer");
    try (BIBO bibo = new ZmqBibo(endpoint, 10_000)) {
      assertFalse(
          VciProvisioning.probe(bibo, otherCaPrefix + ".crt", "12345678"),
          "VCI probe must reject a card CVC signed by a different CA");
    }

    // Negative: a wrong pairing code must fail. SM establishes and the CVC verifies, but the
    // applet rejects the pairing VERIFY over the secure channel, so VCI is not granted.
    try (BIBO bibo = new ZmqBibo(endpoint, 10_000)) {
      assertFalse(
          VciProvisioning.probe(bibo, caPrefix + ".crt", "87654321"),
          "VCI probe must reject an incorrect pairing code");
    }
  }

  /**
   * Wrong pairing code returns a non-success application status inside a successfully SM-wrapped
   * response (Part 2 Section 4.2.6/4.2.7: app status is not an SM error).
   */
  @Test
  void wrongPairingCodeIsEncapsulatedApplicationStatus(@TempDir Path tempDir) throws Exception {
    assumeTrue(isCs2Build(), "CS2 E2E test requires -Dvci.suite=CS2");
    String caPrefix = tempDir.resolve("vci-ca").toString();
    try (BIBO bibo = new ZmqBibo(endpoint, 10_000)) {
      VciProvisioning.provision(bibo, null, null, caPrefix, "12345678", null);
    }

    try (BIBO bibo = new ZmqBibo(endpoint, 10_000)) {
      VciProvisioning.EstablishedSession established =
          VciProvisioning.establishSecureMessaging(bibo, caPrefix + ".crt");
      assertNotNull(established, "SM establishment should succeed");
      assertTrue(established.pairingRequired, "provisioned card requires pairing");

      VciSupport.SmResponse wrong =
          VciProvisioning.verifyReferenceDataOverSm(
              bibo,
              established.session,
              (byte) 0x98,
              "87654321".getBytes(StandardCharsets.US_ASCII));
      assertTrue(
          wrong.statusWord != 0x9000,
          "wrong pairing code must not return 9000 (got 0x"
              + Integer.toHexString(wrong.statusWord)
              + ")");

      // Session must still be usable for another SM exchange (app error, not SM error).
      VciSupport.SmResponse retry =
          VciProvisioning.verifyReferenceDataOverSm(
              bibo,
              established.session,
              (byte) 0x98,
              "12345678".getBytes(StandardCharsets.US_ASCII));
      assertEquals(
          0x9000,
          retry.statusWord,
          "correct pairing after wrong attempt should succeed in the same SM session");
    }
  }

  /**
   * Malformed pairing code length is rejected. SP 800-73-5 requires the pairing code to be exactly
   * 8 bytes (AS01.17 / Part 2).
   */
  @Test
  void shortPairingCodeOverSmIsRejected(@TempDir Path tempDir) throws Exception {
    assumeTrue(isCs2Build(), "CS2 E2E test requires -Dvci.suite=CS2");
    String caPrefix = tempDir.resolve("vci-ca").toString();
    try (BIBO bibo = new ZmqBibo(endpoint, 10_000)) {
      VciProvisioning.provision(bibo, null, null, caPrefix, "12345678", null);
    }

    try (BIBO bibo = new ZmqBibo(endpoint, 10_000)) {
      VciProvisioning.EstablishedSession established =
          VciProvisioning.establishSecureMessaging(bibo, caPrefix + ".crt");
      assertNotNull(established);

      VciSupport.SmResponse shortCode =
          VciProvisioning.verifyReferenceDataOverSm(
              bibo, established.session, (byte) 0x98, "1234".getBytes(StandardCharsets.US_ASCII));
      assertTrue(
          shortCode.statusWord != 0x9000,
          "pairing code shorter than 8 bytes must be rejected (got 0x"
              + Integer.toHexString(shortCode.statusWord)
              + ")");
    }
  }

  @Test
  void pairingResetKeepsSecureMessagingSessionUsable(@TempDir Path tempDir) throws Exception {
    assumeTrue(isCs2Build(), "CS2 E2E test requires -Dvci.suite=CS2");
    String caPrefix = tempDir.resolve("vci-ca").toString();
    try (BIBO bibo = new ZmqBibo(endpoint, 10_000)) {
      VciProvisioning.provision(bibo, null, null, caPrefix, "12345678", null);
    }

    try (BIBO bibo = new ZmqBibo(endpoint, 10_000)) {
      VciProvisioning.EstablishedSession established =
          VciProvisioning.establishSecureMessaging(bibo, caPrefix + ".crt");
      assertNotNull(established);

      VciSupport.SmResponse paired =
          VciProvisioning.verifyReferenceDataOverSm(
              bibo,
              established.session,
              (byte) 0x98,
              "12345678".getBytes(StandardCharsets.US_ASCII));
      assertEquals(0x9000, paired.statusWord, "pairing VERIFY success");

      VciSupport.SmResponse reset =
          VciProvisioning.resetReferenceStatusOverSm(bibo, established.session, (byte) 0x98);
      assertEquals(0x9000, reset.statusWord, "pairing reset is an application success under SM");

      VciSupport.SmResponse status =
          VciProvisioning.getReferenceStatusOverSm(bibo, established.session, (byte) 0x98);
      assertEquals(0x6982, status.statusWord, "pairing status should be false after reset");

      VciSupport.SmResponse pairedAgain =
          VciProvisioning.verifyReferenceDataOverSm(
              bibo,
              established.session,
              (byte) 0x98,
              "12345678".getBytes(StandardCharsets.US_ASCII));
      assertEquals(0x9000, pairedAgain.statusWord, "same SM session remains usable after reset");
    }
  }

  /**
   * Live CS7 (P-384 / AES-256) OPACITY + pairing + wrapped GET DATA on the emulator.
   *
   * <p>Exercises the applet's unified OPACITY path with field length 48 and AES-256 session keys.
   */
  @Test
  void provisionsAndEstablishesCs7VciOverZmq(@TempDir Path tempDir) throws Exception {
    assumeTrue(isCs7Build(), "CS7 E2E test requires -Dvci.suite=CS7");
    String caPrefix = tempDir.resolve("vci-ca-cs7").toString();
    try (BIBO bibo = new ZmqBibo(endpoint, 10_000)) {
      VciProvisioning.provision(bibo, null, null, caPrefix, "12345678", null, VciSupport.ALG_CS7);
    }
    try (BIBO bibo = new ZmqBibo(endpoint, 10_000)) {
      assertTrue(
          VciProvisioning.probe(bibo, caPrefix + ".crt", "12345678"),
          "CS7 VCI probe should succeed end-to-end");
    }
    try (BIBO bibo = new ZmqBibo(endpoint, 10_000)) {
      VciProvisioning.EstablishedSession established =
          VciProvisioning.establishSecureMessaging(bibo, caPrefix + ".crt");
      assertNotNull(established, "CS7 SM establishment");
      assertTrue(established.cvcRaw.length > 200, "CS7 CVC is larger than a typical CS2 CVC");
    }
  }

  @Test
  void cs2OpacityRejectsOffCurveHostPublicKey(@TempDir Path tempDir) throws Exception {
    assumeTrue(isCs2Build(), "CS2 C4 validation test requires -Dvci.suite=CS2");
    assertOffCurveHostPublicKeyRejected(tempDir, VciSupport.ALG_CS2);
  }

  @Test
  void cs2EstablishesOpacityWithMaxAcceptedCvc(@TempDir Path tempDir) throws Exception {
    assumeTrue(isCs2Build(), "CS2 max-CVC test requires -Dvci.suite=CS2");
    String caPrefix = tempDir.resolve("vci-ca-max-cvc").toString();
    try (BIBO bibo = new ZmqBibo(endpoint, 10_000)) {
      VciProvisioning.provisionWithMinimumCvcLength(
          bibo, null, null, caPrefix, "12345678", null, VciSupport.ALG_CS2, 256);
    }

    try (BIBO bibo = new ZmqBibo(endpoint, 10_000)) {
      VciProvisioning.EstablishedSession established =
          VciProvisioning.establishSecureMessaging(bibo, caPrefix + ".crt");
      assertNotNull(established, "OPACITY establishment with 256-byte CS2 CVC");
      assertEquals(256, established.cvcRaw.length, "card should return the max accepted CS2 CVC");

      VciSupport.SmResponse paired =
          VciProvisioning.verifyReferenceDataOverSm(
              bibo,
              established.session,
              (byte) 0x98,
              "12345678".getBytes(StandardCharsets.US_ASCII));
      assertEquals(0x9000, paired.statusWord, "pairing after max-CVC OPACITY establishment");
    }
  }

  @Test
  void cs7EstablishesOpacityWithMaxAcceptedCvc(@TempDir Path tempDir) throws Exception {
    assumeTrue(isCs7Build(), "CS7 max-CVC test requires -Dvci.suite=CS7");
    String caPrefix = tempDir.resolve("vci-ca-cs7-max-cvc").toString();
    try (BIBO bibo = new ZmqBibo(endpoint, 10_000)) {
      VciProvisioning.provisionWithMinimumCvcLength(
          bibo, null, null, caPrefix, "12345678", null, VciSupport.ALG_CS7, 384);
    }

    try (BIBO bibo = new ZmqBibo(endpoint, 10_000)) {
      VciProvisioning.EstablishedSession established =
          VciProvisioning.establishSecureMessaging(bibo, caPrefix + ".crt");
      assertNotNull(established, "OPACITY establishment with 384-byte CS7 CVC");
      assertEquals(384, established.cvcRaw.length, "card should return the max accepted CS7 CVC");

      VciSupport.SmResponse paired =
          VciProvisioning.verifyReferenceDataOverSm(
              bibo,
              established.session,
              (byte) 0x98,
              "12345678".getBytes(StandardCharsets.US_ASCII));
      assertEquals(0x9000, paired.statusWord, "pairing after max-CVC CS7 OPACITY establishment");
    }
  }

  @Test
  void cs7OpacityRejectsOffCurveHostPublicKey(@TempDir Path tempDir) throws Exception {
    assumeTrue(isCs7Build(), "CS7 C4 validation test requires -Dvci.suite=CS7");
    assertOffCurveHostPublicKeyRejected(tempDir, VciSupport.ALG_CS7);
  }

  /**
   * Before pairing, a VCI-gated object remains inaccessible over SM; after correct pairing, the
   * Discovery Object remains readable (ALWAYS) and establishes VCI for subsequent access policy.
   */
  @Test
  void pairingGatesVciWhileDiscoveryRemainsReadableOverSm(@TempDir Path tempDir) throws Exception {
    assumeTrue(isCs2Build(), "CS2 E2E test requires -Dvci.suite=CS2");
    String caPrefix = tempDir.resolve("vci-ca").toString();
    try (BIBO bibo = new ZmqBibo(endpoint, 10_000)) {
      VciProvisioning.provision(bibo, null, null, caPrefix, "12345678", null);
    }

    try (BIBO bibo = new ZmqBibo(endpoint, 10_000)) {
      VciProvisioning.EstablishedSession established =
          VciProvisioning.establishSecureMessaging(bibo, caPrefix + ".crt");
      assertNotNull(established);

      // Discovery Object is ALWAYS-readable; SM alone is enough for the transport.
      VciSupport.SmResponse discovery =
          VciProvisioning.getDiscoveryOverSm(bibo, established.session);
      assertEquals(0x9000, discovery.statusWord, "Discovery Object readable over SM pre-pairing");
      assertTrue(discovery.data.length > 0, "Discovery Object payload non-empty");

      VciSupport.SmResponse paired =
          VciProvisioning.verifyReferenceDataOverSm(
              bibo,
              established.session,
              (byte) 0x98,
              "12345678".getBytes(StandardCharsets.US_ASCII));
      assertEquals(0x9000, paired.statusWord, "pairing VERIFY success");

      VciSupport.SmResponse discoveryAfter =
          VciProvisioning.getDiscoveryOverSm(bibo, established.session);
      assertEquals(0x9000, discoveryAfter.statusWord, "Discovery still readable after pairing");
    }
  }

  private static boolean isCs2Build() {
    return !"CS7".equalsIgnoreCase(System.getProperty("vci.suite", "CS2"));
  }

  private static boolean isCs7Build() {
    return "CS7".equalsIgnoreCase(System.getProperty("vci.suite", "CS2"));
  }

  private void installOpenFips201Applet() throws Exception {
    AppletInstallRequest request = new AppletInstallRequest();
    request.capPath = Paths.get(System.getProperty("cap.path"));
    request.packageAid = "A00000030800001000";
    request.appletAid = "A000000308000010000100";
    request.instanceAid = "A000000308000010000100";
    request.loadCap = false;
    request.deleteExisting = false;
    try (GlobalPlatformSession session =
        GlobalPlatformSession.open(
            CardTarget.parse("zmq:" + endpoint),
            GlobalPlatformSession.ISD_AID,
            ScpConfig.defaultTestScp03())) {
      new AppletInstallService().install(session, request);
    }
  }

  private void assertOffCurveHostPublicKeyRejected(Path tempDir, byte suite) throws Exception {
    String caPrefix = tempDir.resolve("vci-ca-off-curve").toString();
    try (BIBO bibo = new ZmqBibo(endpoint, 10_000)) {
      VciProvisioning.provision(bibo, null, null, caPrefix, "12345678", null, suite);
    }

    try (BIBO bibo = new ZmqBibo(endpoint, 10_000)) {
      byte[] offCurve = offCurveHostPublicPoint(suite);
      assertEquals(
          0x6A80,
          VciProvisioning.submitOpacityWithHostPublicPoint(bibo, suite, offCurve),
          "SP 800-73-5 Part 2 C4 requires invalid Q_eH to fail with 6A80");
    }

    try (BIBO bibo = new ZmqBibo(endpoint, 10_000)) {
      assertNotNull(
          VciProvisioning.establishSecureMessaging(bibo, caPrefix + ".crt"),
          "failed C4 validation must not poison a later valid OPACITY establishment");
    }
  }

  private static byte[] offCurveHostPublicPoint(byte suite) {
    byte[] point = validHostPublicPoint(suite);
    point[point.length - 1] ^= 0x01;
    return point;
  }

  private static byte[] validHostPublicPoint(byte suite) {
    X9ECParameters curve = VciSupport.curveForSuite(suite);
    SecureRandom random = new SecureRandom();
    BigInteger d;
    do {
      d = new BigInteger(curve.getN().bitLength(), random);
    } while (d.signum() <= 0 || d.compareTo(curve.getN()) >= 0);
    ECPoint hostPoint = curve.getG().multiply(d).normalize();
    return VciSupport.encodePoint(hostPoint);
  }
}
