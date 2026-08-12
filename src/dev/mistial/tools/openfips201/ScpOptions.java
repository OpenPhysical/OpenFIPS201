package dev.mistial.tools.openfips201;

import dev.mistial.tools.openfips201.common.ScpConfig;
import picocli.CommandLine.Option;

/** Shared SCP command-line options with exactly one accepted key representation. */
class ScpOptions {
  @Option(names = "--target", required = true)
  String target;

  @Option(names = "--scp", defaultValue = "auto")
  String scp;

  @Option(names = "--scp-key-version", defaultValue = "0")
  int scpKeyVersion;

  @Option(names = "--scp-key")
  String scpKey;

  @Option(names = "--scp-enc-key")
  String scpEncKey;

  @Option(names = "--scp-mac-key")
  String scpMacKey;

  @Option(names = "--scp-dek-key")
  String scpDekKey;

  ScpConfig scp() {
    return ScpConfig.fromCliKeys(
        ScpConfig.parseMode(scp), scpKeyVersion, scpKey, scpEncKey, scpMacKey, scpDekKey);
  }
}
