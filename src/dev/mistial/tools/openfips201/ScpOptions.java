package dev.mistial.tools.openfips201;

import dev.mistial.tools.openfips201.common.ScpConfig;
import picocli.CommandLine.Option;

/** Shared SCP command-line options with exactly one accepted key representation. */
class ScpOptions {
  @Option(
      names = "--target",
      required = true,
      description = "Card target: pcsc:<reader-filter> or zmq:<endpoint>.")
  String target;

  @Option(
      names = "--scp",
      defaultValue = "auto",
      description = "Secure-channel protocol: auto, 02, or 03. Default: ${DEFAULT-VALUE}.")
  String scp;

  @Option(
      names = "--scp-key-version",
      defaultValue = "0",
      description = "GlobalPlatform key version. Default: ${DEFAULT-VALUE}.")
  int scpKeyVersion;

  @Option(names = "--scp-key", description = "Shared ENC, MAC, and DEK key in hexadecimal.")
  String scpKey;

  @Option(names = "--scp-enc-key", description = "ENC key in hexadecimal.")
  String scpEncKey;

  @Option(names = "--scp-mac-key", description = "MAC key in hexadecimal.")
  String scpMacKey;

  @Option(names = "--scp-dek-key", description = "DEK key in hexadecimal.")
  String scpDekKey;

  /**
   * Validates the selected SCP mode and the shared or split key representation.
   *
   * @return secure-channel configuration for the requested card operation
   */
  ScpConfig scp() {
    return ScpConfig.fromCliKeys(
        ScpConfig.parseMode(scp), scpKeyVersion, scpKey, scpEncKey, scpMacKey, scpDekKey);
  }
}
