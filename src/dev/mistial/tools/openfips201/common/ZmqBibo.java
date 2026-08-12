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
  private final ZContext context;
  private final ZMQ.Socket socket;

  public ZmqBibo(String endpoint, int receiveTimeoutMs) {
    context = new ZContext();
    socket = context.createSocket(SocketType.REQ);
    socket.setReceiveTimeOut(receiveTimeoutMs);
    socket.setLinger(0);
    socket.connect(endpoint);
  }

  @Override
  public byte[] transceive(byte[] command) throws BIBOException {
    socket.send("APDU".getBytes(StandardCharsets.US_ASCII), ZMQ.SNDMORE);
    socket.send(command, 0);
    byte[] status = socket.recv();
    if (status == null) {
      throw new BIBOException("ZeroMQ emulator did not respond");
    }
    byte[] body = socket.hasReceiveMore() ? socket.recv() : new byte[0];
    if (!"OK".equals(new String(status, StandardCharsets.US_ASCII))) {
      throw new BIBOException("Emulator error: " + new String(body, StandardCharsets.UTF_8));
    }
    return body;
  }

  @Override
  public void close() {
    context.close();
  }
}
