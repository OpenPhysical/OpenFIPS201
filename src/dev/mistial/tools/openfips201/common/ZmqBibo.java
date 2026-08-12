/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.common;

import apdu4j.core.BIBO;
import apdu4j.core.BIBOException;
import java.nio.charset.StandardCharsets;
import org.zeromq.SocketType;
import org.zeromq.ZContext;
import org.zeromq.ZMQ;

public final class ZmqBibo implements BIBO {
  private static final int CONNECT_ATTEMPTS = 4;
  private static final int CONNECT_TIMEOUT_MS = 500;

  private final ZContext context;
  private final ZMQ.Socket socket;
  private final String endpoint;
  private final Thread ownerThread;
  private boolean open = true;

  public ZmqBibo(String endpoint, int receiveTimeoutMs) {
    if (endpoint == null || endpoint.isEmpty()) {
      throw new IllegalArgumentException("ZeroMQ endpoint is required");
    }
    if (receiveTimeoutMs <= 0) {
      throw new IllegalArgumentException("ZeroMQ receive timeout must be positive");
    }
    this.endpoint = endpoint;
    this.ownerThread = Thread.currentThread();
    context = new ZContext();
    socket = connect(receiveTimeoutMs);
  }

  @Override
  public byte[] transceive(byte[] command) throws BIBOException {
    requireOwnerThread();
    requireOpen();
    if (command == null || command.length < 4) {
      throw new BIBOException("Command APDU must contain at least four bytes");
    }
    if (!socket.send(ZmqProtocol.VERB_APDU.getBytes(StandardCharsets.US_ASCII), ZMQ.SNDMORE)
        || !socket.send(command, 0)) {
      throw fail("could not send command APDU to " + endpoint);
    }
    byte[] status = socket.recv();
    if (status == null) {
      throw fail(
          "timed out waiting for APDU response at " + endpoint + "; card state is indeterminate");
    }
    byte[] body = socket.hasReceiveMore() ? socket.recv() : new byte[0];
    if (socket.hasReceiveMore()) {
      while (socket.hasReceiveMore()) {
        socket.recv();
      }
      throw fail("received an invalid multi-frame APDU response from " + endpoint);
    }
    if (!ZmqProtocol.REPLY_OK.equals(new String(status, StandardCharsets.US_ASCII))) {
      throw new BIBOException("Emulator error: " + new String(body, StandardCharsets.UTF_8));
    }
    return body;
  }

  @Override
  public void close() {
    requireOwnerThread();
    closeTransport();
  }

  private ZMQ.Socket connect(int receiveTimeoutMs) {
    for (int attempt = 0; attempt < CONNECT_ATTEMPTS; attempt++) {
      ZMQ.Socket candidate = context.createSocket(SocketType.REQ);
      candidate.setReceiveTimeOut(CONNECT_TIMEOUT_MS);
      candidate.setLinger(0);
      if (!candidate.connect(endpoint)
          || !candidate.send(ZmqProtocol.VERB_PING.getBytes(StandardCharsets.US_ASCII), 0)) {
        candidate.close();
        continue;
      }
      byte[] status = candidate.recv();
      if (status == null) {
        candidate.close();
        continue;
      }
      byte[] body = candidate.hasReceiveMore() ? candidate.recv() : new byte[0];
      boolean hasExtraFrame = candidate.hasReceiveMore();
      if (!hasExtraFrame
          && ZmqProtocol.REPLY_OK.equals(new String(status, StandardCharsets.US_ASCII))
          && ZmqProtocol.PING_RESPONSE.equals(new String(body, StandardCharsets.UTF_8))) {
        candidate.setReceiveTimeOut(receiveTimeoutMs);
        return candidate;
      }
      candidate.close();
      context.close();
      open = false;
      throw new IllegalStateException(
          "ZeroMQ endpoint " + endpoint + " does not speak the OpenFIPS201 emulator protocol");
    }
    context.close();
    open = false;
    throw new IllegalStateException(
        "ZeroMQ emulator at " + endpoint + " did not become ready within two seconds");
  }

  private void requireOwnerThread() {
    if (Thread.currentThread() != ownerThread) {
      throw new IllegalStateException("ZeroMQ transport must be used by its creating thread");
    }
  }

  private void requireOpen() throws BIBOException {
    if (!open) {
      throw new BIBOException("ZeroMQ transport is closed or unusable");
    }
  }

  private BIBOException fail(String message) {
    closeTransport();
    return new BIBOException(message);
  }

  private void closeTransport() {
    if (!open) {
      return;
    }
    open = false;
    socket.close();
    context.close();
  }
}
