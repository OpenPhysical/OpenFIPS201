package dev.mistial.tools.openfips201;

import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.crypto.SecretSource;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Arrays;
import picocli.CommandLine.Option;

/**
 * Shared SCP command-line options with exactly one accepted key representation.
 *
 * <p>Each key has a literal, {@code -env} and {@code -file} form (see {@link SecretSource}).
 * Literal keys are refused for {@code pcsc:} targets.
 */
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

  @Option(
      names = "--scp-key",
      description = "Shared ENC, MAC, and DEK key in hexadecimal (zmq: targets only).")
  String scpKey;

  @Option(names = "--scp-key-env", description = "Environment variable holding the shared key.")
  String scpKeyEnv;

  @Option(names = "--scp-key-file", description = "Owner-only file holding the shared key.")
  String scpKeyFile;

  @Option(names = "--scp-enc-key", description = "ENC key in hexadecimal (zmq: targets only).")
  String scpEncKey;

  @Option(names = "--scp-enc-key-env", description = "Environment variable holding the ENC key.")
  String scpEncKeyEnv;

  @Option(names = "--scp-enc-key-file", description = "Owner-only file holding the ENC key.")
  String scpEncKeyFile;

  @Option(names = "--scp-mac-key", description = "MAC key in hexadecimal (zmq: targets only).")
  String scpMacKey;

  @Option(names = "--scp-mac-key-env", description = "Environment variable holding the MAC key.")
  String scpMacKeyEnv;

  @Option(names = "--scp-mac-key-file", description = "Owner-only file holding the MAC key.")
  String scpMacKeyFile;

  @Option(names = "--scp-dek-key", description = "DEK key in hexadecimal (zmq: targets only).")
  String scpDekKey;

  @Option(names = "--scp-dek-key-env", description = "Environment variable holding the DEK key.")
  String scpDekKeyEnv;

  @Option(names = "--scp-dek-key-file", description = "Owner-only file holding the DEK key.")
  String scpDekKeyFile;

  /**
   * Validates the selected SCP mode and the shared or split key representation.
   *
   * @return secure-channel configuration for the requested card operation
   */
  ScpConfig scp() {
    byte[] shared = null;
    byte[] enc = null;
    byte[] mac = null;
    byte[] dek = null;
    try {
      shared = key("--scp-key", scpKey, scpKeyEnv, scpKeyFile);
      enc = key("--scp-enc-key", scpEncKey, scpEncKeyEnv, scpEncKeyFile);
      mac = key("--scp-mac-key", scpMacKey, scpMacKeyEnv, scpMacKeyFile);
      dek = key("--scp-dek-key", scpDekKey, scpDekKeyEnv, scpDekKeyFile);
      return ScpConfig.fromKeys(ScpConfig.parseMode(scp), scpKeyVersion, shared, enc, mac, dek);
    } finally {
      wipe(shared);
      wipe(enc);
      wipe(mac);
      wipe(dek);
    }
  }

  private byte[] key(String option, String literal, String env, String file) {
    try {
      return SecretSource.of(option, literal, env, file).refuseLiteralFor(target).hex();
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  private static void wipe(byte[] value) {
    if (value != null) {
      Arrays.fill(value, (byte) 0);
    }
  }
}
