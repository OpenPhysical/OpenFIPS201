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

package dev.mistial.tools.openfips201.vci;

import apdu4j.core.BIBO;
import apdu4j.core.BIBOException;
import java.nio.charset.StandardCharsets;
import org.zeromq.SocketType;
import org.zeromq.ZContext;
import org.zeromq.ZMQ;

/**
 * apdu4j {@link BIBO} that speaks the OpenFIPS201 emulator's ZeroMQ REQ/REP APDU protocol
 * ({@code ["APDU", bytes] -> ["OK", response]}). Lets GPPro and the VCI probe drive a remote
 * emulator exactly like a local card.
 */
final class ZmqBibo implements BIBO {
  private final ZContext context;
  private final ZMQ.Socket socket;

  ZmqBibo(String endpoint, int receiveTimeoutMs) {
    this.context = new ZContext();
    this.socket = context.createSocket(SocketType.REQ);
    this.socket.setReceiveTimeOut(receiveTimeoutMs);
    this.socket.setLinger(0);
    this.socket.connect(endpoint);
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
      throw new BIBOException(
          "Emulator error: " + new String(body, StandardCharsets.UTF_8));
    }
    return body;
  }

  @Override
  public void close() {
    context.close();
  }
}
