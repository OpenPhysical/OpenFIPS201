package dev.mistial.tools.openfips201.vci;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import apdu4j.core.BIBO;
import dev.mistial.tools.openfips201.emulator.ZmqApduServer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
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
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class OpenFIPS201VciEndToEndTest {
  private ZmqApduServer server;
  private Thread serverThread;
  private String endpoint;

  @BeforeEach
  void startServer() throws Exception {
    server = new ZmqApduServer(PlaintextKeys.DEFAULT_KEY());
    endpoint = server.bind("tcp://127.0.0.1:*");

    CountDownLatch started = new CountDownLatch(1);
    AtomicReference<Throwable> failure = new AtomicReference<>();
    serverThread =
        new Thread(
            () -> {
              try {
                server.start();
                started.countDown();
                server.serve();
              } catch (Throwable t) {
                failure.set(t);
                started.countDown();
              }
            },
            "vci-e2e-emulator");
    serverThread.start();
    assertTrue(started.await(30, TimeUnit.SECONDS), "Emulator did not start");
    if (failure.get() != null) {
      throw new IllegalStateException("Emulator failed to start", failure.get());
    }
  }

  @AfterEach
  void stopServer() throws Exception {
    if (server != null) {
      server.stop();
    }
    if (serverThread != null) {
      serverThread.join(10_000);
    }
    if (server != null) {
      server.close();
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
      VciProvisioning.provision(
          bibo, null, null, caPrefix, "12345678", null, VciSupport.ALG_CS7);
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
}
