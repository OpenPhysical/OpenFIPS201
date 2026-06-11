package dev.mistial.tools.openfips201.emulator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import apdu4j.core.BIBO;
import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.zeromq.SocketType;
import org.zeromq.ZContext;
import org.zeromq.ZMQ;
import pro.javacard.gp.GPSecureChannelVersion;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.keys.PlaintextKeys;

/**
 * End-to-end test of the ZeroMQ emulator bridge: a real SCP03 secure channel is established
 * through the socket against the GP-installed OpenFIPS201 applet, exactly as remote host
 * middleware (e.g. the OpenPhysical .NET stack) will do.
 */
@Timeout(value = 30, unit = TimeUnit.SECONDS)
class OpenFIPS201ZmqEmulatorServerTest {
  private static final byte[] TEST_SCP03_KEY = PlaintextKeys.DEFAULT_KEY();
  private static final byte[] OPENFIPS201_AID_BYTES = {
    (byte) 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00
  };

  private ZmqApduServer server;
  private Thread serverThread;
  private ZContext clientContext;
  private ZMQ.Socket client;
  private String endpoint;

  @BeforeEach
  void startServer() throws Exception {
    server = new ZmqApduServer(TEST_SCP03_KEY);
    endpoint = server.bind("tcp://127.0.0.1:*");

    CountDownLatch started = new CountDownLatch(1);
    AtomicReference<Throwable> startupFailure = new AtomicReference<>();
    serverThread =
        new Thread(
            () -> {
              try {
                server.start();
                started.countDown();
                server.serve();
              } catch (Throwable t) {
                startupFailure.set(t);
                started.countDown();
              }
            },
            "zmq-emulator-server");
    serverThread.start();
    assertTrue(started.await(20, TimeUnit.SECONDS), "Server did not start in time");
    if (startupFailure.get() != null) {
      throw new IllegalStateException("Server failed to start", startupFailure.get());
    }

    clientContext = new ZContext();
    client = clientContext.createSocket(SocketType.REQ);
    client.setReceiveTimeOut(10_000);
    client.connect(endpoint);
  }

  @AfterEach
  void stopServer() throws Exception {
    if (clientContext != null) {
      clientContext.close();
    }
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
  void scp03OpensThroughZmqSocketAgainstSelectedApplet() throws Exception {
    GPSession gp = openScp03(new ZmqBibo(client));

    assertEquals(
        GPSecureChannelVersion.SCP.SCP03,
        gp.getSecureChannel().scp,
        "GPPro should negotiate SCP03 against the emulator through the ZeroMQ socket");

    // Wrapped (C-MAC + C-ENC) PIV GET DATA for the undefined Discovery Object: 6A82 proves the
    // command decrypted to a well-formed tag list inside the applet (see OpenFIPS201RealScp03Test).
    apdu4j.core.ResponseAPDU response =
        gp.transmit(
            new apdu4j.core.CommandAPDU(
                0x00, 0xCB, 0x3F, 0xFF, new byte[] {0x5C, 0x01, 0x7E}, 256));
    assertEquals(0x6A82, response.getSW(), "Wrapped PIV GET DATA should reach the applet");
  }

  @Test
  void resetPowerCyclesTheCardSession() throws Exception {
    GPSession gp = openScp03(new ZmqBibo(client));
    apdu4j.core.ResponseAPDU beforeReset =
        gp.transmit(
            new apdu4j.core.CommandAPDU(
                0x00, 0xCB, 0x3F, 0xFF, new byte[] {0x5C, 0x01, 0x7E}, 256));
    assertEquals(0x6A82, beforeReset.getSW());

    byte[] atr = request("RESET", null);
    assertTrue(atr.length > 0, "RESET should return the ATR");

    // The stale GPPro session must no longer reach the applet: the reset deselected it and tore
    // down the SCP03 session, so the previously working wrapped command cannot succeed anymore.
    apdu4j.core.ResponseAPDU afterReset =
        gp.transmit(
            new apdu4j.core.CommandAPDU(
                0x00, 0xCB, 0x3F, 0xFF, new byte[] {0x5C, 0x01, 0x7E}, 256));
    assertNotEquals(0x6A82, afterReset.getSW(), "Reset must invalidate the old secure channel");

    // A fresh secure channel over the same socket must work, like re-inserting a card.
    GPSession freshGp = openScp03(new ZmqBibo(client));
    assertEquals(GPSecureChannelVersion.SCP.SCP03, freshGp.getSecureChannel().scp);
  }

  @Test
  void pingAtrAndUnknownVerbFollowTheProtocol() {
    assertArrayEquals(
        ZmqApduServer.PING_RESPONSE.getBytes(StandardCharsets.UTF_8), request("PING", null));

    byte[] atr = request("ATR", null);
    assertTrue(atr.length > 0, "ATR must not be empty");

    RuntimeException error = assertThrows(RuntimeException.class, () -> request("BOGUS", null));
    assertTrue(error.getMessage().contains("Unknown verb"), "Server should reject unknown verbs");

    // Missing payload on APDU is an error, not a wedge: the next request must still be served.
    RuntimeException apduError = assertThrows(RuntimeException.class, () -> request("APDU", null));
    assertTrue(apduError.getMessage().contains("payload"));
    assertTrue(request("ATR", null).length > 0, "Server must keep serving after an error reply");
  }

  private GPSession openScp03(BIBO bibo) throws Exception {
    GPSession gp = GPSession.connect(bibo, new pro.javacard.capfile.AID(OPENFIPS201_AID_BYTES));
    PlaintextKeys keys = PlaintextKeys.fromMasterKey(TEST_SCP03_KEY);
    keys.setVersion(0);
    gp.openSecureChannel(
        keys,
        new GPSecureChannelVersion(GPSecureChannelVersion.SCP.SCP03, 0),
        null,
        EnumSet.of(GPSession.APDUMode.MAC, GPSession.APDUMode.ENC));
    return gp;
  }

  private byte[] request(String verb, byte[] payload) {
    if (payload == null) {
      client.send(verb.getBytes(StandardCharsets.US_ASCII), 0);
    } else {
      client.send(verb.getBytes(StandardCharsets.US_ASCII), ZMQ.SNDMORE);
      client.send(payload, 0);
    }
    byte[] status = client.recv();
    assertNotNull(status, "Server reply timed out");
    byte[] body = client.hasReceiveMore() ? client.recv() : new byte[0];
    if (!"OK".equals(new String(status, StandardCharsets.US_ASCII))) {
      throw new RuntimeException(new String(body, StandardCharsets.UTF_8));
    }
    return body;
  }

  /** Minimal APDU-over-ZeroMQ adapter so GPPro can drive the emulator through the socket. */
  private final class ZmqBibo implements BIBO {
    private final ZMQ.Socket socket;

    ZmqBibo(ZMQ.Socket socket) {
      this.socket = socket;
    }

    @Override
    public byte[] transceive(byte[] command) {
      return request("APDU", command);
    }
  }
}
