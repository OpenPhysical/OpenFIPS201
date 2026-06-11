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
import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Provisions and exercises PIV VCI (secure messaging / OPACITY CS2) on an OpenFIPS201 card or
 * emulator, "the PIV way": the card generates its own SM key, a VCI signer CA signs the resulting
 * public key into a CVC, the CVC is loaded, and pairing-code VCI mode is configured. The
 * {@code probe} subcommand then establishes a real secure-messaging session and validates the
 * card CVC against the signer CA.
 */
@Command(
    name = "vci-tool",
    mixinStandardHelpOptions = true,
    description = "Provision and test PIV VCI secure messaging on OpenFIPS201.",
    subcommands = {
      VciTool.MakeCa.class,
      VciTool.Provision.class,
      VciTool.Probe.class
    })
public final class VciTool implements Callable<Integer> {

  public static void main(String[] args) {
    CommandLine commandLine = new CommandLine(new VciTool());
    commandLine.setExecutionExceptionHandler(
        (exception, parsedCommand, parseResult) -> {
          parsedCommand.getErr().println("Error: " + exception.getMessage());
          return 1;
        });
    System.exit(commandLine.execute(args));
  }

  @Override
  public Integer call() {
    CommandLine.usage(this, System.err);
    return 2;
  }

  /** Shared reader option: {@code zmq:tcp://host:port} for the emulator, or a PC/SC reader name. */
  abstract static class ReaderOptions {
    @Option(
        names = "--reader",
        required = true,
        description = "Reader: 'zmq:<endpoint>' for the emulator, or a PC/SC reader name fragment.")
    String reader;

    @Option(
        names = "--timeout-ms",
        description = "ZeroMQ request timeout in milliseconds (default: ${DEFAULT-VALUE}).",
        defaultValue = "10000")
    int timeoutMs;

    BIBO openBibo() throws Exception {
      if (reader.startsWith("zmq:")) {
        return new ZmqBibo(reader.substring(4), timeoutMs);
      }
      return PcscBibo.open(reader);
    }
  }

  @Command(name = "make-ca", description = "Generate a self-signed VCI signer CA (EC P-256).")
  static final class MakeCa implements Callable<Integer> {
    @Option(names = "--out", required = true, description = "Output path prefix (.key/.crt PEM).")
    String out;

    @Option(
        names = "--subject",
        description = "CA subject DN (default: ${DEFAULT-VALUE}).",
        defaultValue = "CN=OpenFIPS201 VCI Signer")
    String subject;

    @Override
    public Integer call() throws Exception {
      VciProvisioning.makeCa(out, subject);
      System.out.println("VCI signer CA written: " + out + ".key / " + out + ".crt");
      return 0;
    }
  }

  @Command(
      name = "provision",
      description =
          "Have the card generate its VCI key, sign it into a CVC, and enable pairing-code VCI.")
  static final class Provision extends ReaderOptions implements Callable<Integer> {
    @Option(names = "--ca-cert", description = "VCI signer CA certificate PEM (with --ca-key).")
    String caCert;

    @Option(names = "--ca-key", description = "VCI signer CA private key PEM (with --ca-cert).")
    String caKey;

    @Option(
        names = "--ca-out",
        description = "Generate a fresh CA at this path prefix instead of supplying --ca-cert/key.")
    String caOut;

    @Option(
        names = "--pairing-code",
        description = "8-digit pairing code (default: ${DEFAULT-VALUE}).",
        defaultValue = "12345678")
    String pairingCode;

    @Option(
        names = "--scp03-key",
        description = "SCP03 master key hex for provisioning (default: GlobalPlatform test key).")
    String scp03KeyHex;

    @Override
    public Integer call() throws Exception {
      try (BIBO bibo = openBibo()) {
        VciProvisioning.provision(
            bibo, caCert, caKey, caOut, pairingCode, scp03KeyHex);
      }
      return 0;
    }
  }

  @Command(
      name = "probe",
      description = "Establish VCI secure messaging and validate the card CVC against the CA.")
  static final class Probe extends ReaderOptions implements Callable<Integer> {
    @Option(names = "--ca-cert", required = true, description = "VCI signer CA certificate PEM.")
    String caCert;

    @Option(
        names = "--pairing-code",
        description = "8-digit pairing code (default: ${DEFAULT-VALUE}).",
        defaultValue = "12345678")
    String pairingCode;

    @Override
    public Integer call() throws Exception {
      try (BIBO bibo = openBibo()) {
        return VciProvisioning.probe(bibo, caCert, pairingCode) ? 0 : 1;
      }
    }
  }
}
