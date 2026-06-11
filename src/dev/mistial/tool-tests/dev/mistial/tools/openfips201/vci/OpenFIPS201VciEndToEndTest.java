package dev.mistial.tools.openfips201.vci;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import apdu4j.core.BIBO;
import dev.mistial.tools.openfips201.emulator.ZmqApduServer;
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
 * End-to-end PIV VCI test: provisions the emulated card "the PIV way" (card-generated SM key, CVC
 * signed by a VCI CA, pairing-code mode) and then establishes a real OPACITY secure-messaging
 * session through the same ZeroMQ transport the .NET stack uses, validating the card CVC against
 * the CA. This is the cross-stack interop check for the applet's secure-messaging implementation.
 *
 * <p>Aligned with NIST SP 800-73-5 Part 1 Section 5.1.3 (Pairing Code) & Part 2 Section 4.1 (Key Establishment).
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
}
