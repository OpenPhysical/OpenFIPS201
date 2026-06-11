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

import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import pro.javacard.gp.keys.PlaintextKeys;

/**
 * Hosts an OpenFIPS201 jCardEngine emulator behind a ZeroMQ REP socket so host middleware (e.g.
 * the OpenPhysical .NET stack via its {@code zmq:} reader scheme) can drive it with raw APDUs.
 *
 * <p>The emulated card serves one logical card session: clients must take turns, exactly as with
 * a physical card in a shared reader.
 */
@Command(
    name = "emulator-server",
    mixinStandardHelpOptions = true,
    description =
        "Serve an OpenFIPS201 emulator (GP-provisioned, SCP03) over a ZeroMQ REP socket.")
public final class EmulatorServerTool implements Callable<Integer> {

  @Option(
      names = "--endpoint",
      description = "ZeroMQ endpoint to bind (default: ${DEFAULT-VALUE}).",
      defaultValue = ZmqApduServer.DEFAULT_ENDPOINT)
  private String endpoint;

  @Option(
      names = "--scp03-key",
      description =
          "SCP03 master key as hex (16/24/32 bytes). Default: the GlobalPlatform test key.")
  private String scp03KeyHex;

  public static void main(String[] args) {
    CommandLine commandLine = new CommandLine(new EmulatorServerTool());
    commandLine.setExecutionExceptionHandler(
        (exception, parsedCommand, parseResult) -> {
          parsedCommand.getErr().println("Error: " + exception.getMessage());
          return 1;
        });
    System.exit(commandLine.execute(args));
  }

  @Override
  public Integer call() {
    byte[] key = scp03KeyHex == null ? PlaintextKeys.DEFAULT_KEY() : parseKey(scp03KeyHex);
    try (ZmqApduServer server = new ZmqApduServer(key)) {
      String bound = server.bind(endpoint);
      server.start();
      System.out.println("OpenFIPS201 emulator serving on " + bound);
      System.out.println("Applet installed via GlobalPlatform lifecycle; Ctrl-C to stop.");
      Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
      server.serve();
    }
    return 0;
  }

  private static byte[] parseKey(String hex) {
    String normalized = hex.replace(" ", "").replace(":", "");
    if (normalized.length() % 2 != 0) {
      throw new IllegalArgumentException("--scp03-key must contain an even number of hex digits");
    }
    byte[] key = new byte[normalized.length() / 2];
    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) Integer.parseInt(normalized.substring(i * 2, i * 2 + 2), 16);
    }
    if (key.length != 16 && key.length != 24 && key.length != 32) {
      throw new IllegalArgumentException("--scp03-key must be 16, 24 or 32 bytes of hex");
    }
    return key;
  }
}
