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

package dev.mistial.tools.openfips201.emulator;

import apdu4j.core.BIBO;
import com.makina.security.openfips201.OpenFIPS201;
import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.concurrent.atomic.AtomicBoolean;
import javacard.framework.AID;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.engine.globalplatform.SCPConfig;
import pro.javacard.gp.GPRegistryEntry;
import pro.javacard.gp.GPSecureChannelVersion;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.keys.PlaintextKeys;
import org.zeromq.SocketType;
import org.zeromq.ZContext;
import org.zeromq.ZMQ;

/**
 * ZeroMQ REP server exposing an OpenFIPS201 jCardEngine emulator as a remote card.
 *
 * <p>On startup the applet is installed through the real GlobalPlatform card-content lifecycle
 * (load file registration, SCP03 to the ISD, INSTALL [for install and make selectable]) so the
 * emulated card is in the same state as a freshly provisioned physical card.
 *
 * <p>Wire protocol (multipart frames; the first frame is an ASCII verb):
 *
 * <ul>
 *   <li>{@code ["APDU", command bytes]} -> {@code ["OK", response bytes (data || SW1 SW2)]}
 *   <li>{@code ["RESET"]} -> {@code ["OK", ATR]} after power-cycling the card session
 *   <li>{@code ["ATR"]} -> {@code ["OK", ATR]}
 *   <li>{@code ["PING"]} -> {@code ["OK", "OpenFIPS201-emulator"]}
 *   <li>any failure -> {@code ["ERR", UTF-8 message]}
 * </ul>
 *
 * <p>Threading: jCardEngine binds the simulator and its sessions to the creating thread, so
 * {@link #start()} and {@link #serve()} must be called on the same thread. {@link #stop()} and
 * {@link #close()} may be called from any thread. The card is one global session; clients are
 * expected to take turns, exactly as with a shared physical reader.
 */
public final class ZmqApduServer implements AutoCloseable {

  public static final String DEFAULT_ENDPOINT = "tcp://127.0.0.1:5555";
  public static final String PING_RESPONSE = "OpenFIPS201-emulator";

  static final String VERB_APDU = "APDU";
  static final String VERB_RESET = "RESET";
  static final String VERB_ATR = "ATR";
  static final String VERB_PING = "PING";
  static final String REPLY_OK = "OK";
  static final String REPLY_ERR = "ERR";

  private static final byte[] PACKAGE_AID_BYTES = hex("A00000030800001000");
  private static final byte[] APPLET_AID_BYTES = hex("A000000308000010000100");
  private static final byte[] ISD_AID_BYTES = hex("A000000151000000");

  /** Receive poll interval; bounds how quickly stop() is observed. */
  private static final int RECEIVE_TIMEOUT_MS = 250;

  private final byte[] scp03MasterKey;
  private final ZContext context;
  private final ZMQ.Socket socket;
  private final AtomicBoolean running = new AtomicBoolean(false);

  private JavaCardEngine engine;
  private BIBO card;
  private String boundEndpoint;

  public ZmqApduServer(byte[] scp03MasterKey) {
    this.scp03MasterKey = scp03MasterKey.clone();
    this.context = new ZContext();
    this.socket = context.createSocket(SocketType.REP);
    this.socket.setReceiveTimeOut(RECEIVE_TIMEOUT_MS);
  }

  /**
   * Binds the REP socket. Endpoints with a wildcard port (e.g. {@code tcp://127.0.0.1:*}) are
   * supported; the resolved endpoint is returned and also available via {@link
   * #getBoundEndpoint()}.
   */
  public String bind(String endpoint) {
    if (!socket.bind(endpoint)) {
      throw new IllegalStateException("Could not bind ZeroMQ endpoint " + endpoint);
    }
    boundEndpoint = socket.getLastEndpoint();
    return boundEndpoint;
  }

  public String getBoundEndpoint() {
    return boundEndpoint;
  }

  /**
   * Creates the emulator and provisions the applet through the GlobalPlatform lifecycle. Must be
   * called on the thread that will run {@link #serve()}.
   */
  public void start() {
    engine =
        new JavaCardEngine.Builder()
            .withSCP(new SCPConfig.SCP03(scp03MasterKey, false))
            .build();
    installAppletViaGlobalPlatform();
    card = connectCard();
    running.set(true);
  }

  /** Serves requests until {@link #stop()} is called. Must run on the {@link #start()} thread. */
  public void serve() {
    while (running.get()) {
      serveOnce();
    }
  }

  /** Handles at most one request; returns false on receive timeout. */
  public boolean serveOnce() {
    byte[] verbFrame = socket.recv();
    if (verbFrame == null) {
      return false;
    }
    byte[] payload = socket.hasReceiveMore() ? socket.recv() : null;
    // Drain any unexpected extra frames so the REP state machine stays consistent.
    while (socket.hasReceiveMore()) {
      socket.recv();
    }

    String verb = new String(verbFrame, StandardCharsets.US_ASCII);
    try {
      if (VERB_APDU.equals(verb)) {
        if (payload == null || payload.length < 4) {
          reply(REPLY_ERR, utf8("APDU verb requires a command APDU payload"));
        } else {
          reply(REPLY_OK, card.transceive(payload));
        }
      } else if (VERB_RESET.equals(verb)) {
        resetCard();
        reply(REPLY_OK, engine.getATR());
      } else if (VERB_ATR.equals(verb)) {
        reply(REPLY_OK, engine.getATR());
      } else if (VERB_PING.equals(verb)) {
        reply(REPLY_OK, utf8(PING_RESPONSE));
      } else {
        reply(REPLY_ERR, utf8("Unknown verb: " + verb));
      }
    } catch (Exception e) {
      // Always answer so the REQ/REP exchange never wedges; the card session may have been
      // power-cycled by a failed RESET, so surface the failure to the client instead.
      reply(REPLY_ERR, utf8(e.getClass().getSimpleName() + ": " + e.getMessage()));
    }
    return true;
  }

  /** Requests the serve loop to exit. Safe to call from any thread. */
  public void stop() {
    running.set(false);
  }

  @Override
  public void close() {
    stop();
    if (card != null) {
      try {
        card.close();
      } catch (RuntimeException ignored) {
        // Card session teardown must not mask shutdown.
      }
      card = null;
    }
    context.close();
  }

  private void resetCard() {
    // The session was opened with resetOnClose, so closing it power-cycles the card: transient
    // state, applet selection and any open secure channel are gone, exactly like a reader reset.
    card.close();
    card = connectCard();
  }

  private BIBO connectCard() {
    return engine.connect("*", true);
  }

  /** Mirrors how a physical card is provisioned; see OpenFIPS201RealScp03Test for the test twin. */
  private void installAppletViaGlobalPlatform() {
    engine.loadApplet(
        new AID(PACKAGE_AID_BYTES, (short) 0, (byte) PACKAGE_AID_BYTES.length),
        new AID(APPLET_AID_BYTES, (short) 0, (byte) APPLET_AID_BYTES.length),
        OpenFIPS201.class);

    BIBO adminSession = engine.connect();
    try {
      GPSession gp = GPSession.connect(adminSession, new pro.javacard.capfile.AID(ISD_AID_BYTES));
      PlaintextKeys keys = PlaintextKeys.fromMasterKey(scp03MasterKey);
      keys.setVersion(0);
      gp.openSecureChannel(
          keys,
          new GPSecureChannelVersion(GPSecureChannelVersion.SCP.SCP03, 0),
          null,
          EnumSet.of(GPSession.APDUMode.MAC, GPSession.APDUMode.ENC));
      gp.installAndMakeSelectable(
          new pro.javacard.capfile.AID(PACKAGE_AID_BYTES),
          new pro.javacard.capfile.AID(APPLET_AID_BYTES),
          new pro.javacard.capfile.AID(APPLET_AID_BYTES),
          EnumSet.noneOf(GPRegistryEntry.Privilege.class),
          null);
    } catch (Exception e) {
      throw new IllegalStateException("GlobalPlatform install of OpenFIPS201 failed", e);
    } finally {
      adminSession.close();
    }
  }

  private void reply(String status, byte[] payload) {
    socket.send(status.getBytes(StandardCharsets.US_ASCII), ZMQ.SNDMORE);
    socket.send(payload, 0);
  }

  private static byte[] utf8(String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] hex(String value) {
    byte[] bytes = new byte[value.length() / 2];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }
}
