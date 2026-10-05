/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201;

import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.crypto.SecretSource;
import java.util.Arrays;
import picocli.CommandLine.Option;

/**
 * Stock SCP master key options: a literal ({@code zmq:} targets only), an environment variable, or
 * an owner-only file (see {@link SecretSource}).
 */
class StockKeyOptions {
  static final String OPTION = "--stock-scp-key";

  @Option(names = OPTION, description = "Stock SCP master key in hexadecimal (zmq: targets only).")
  String literal;

  @Option(
      names = OPTION + "-env",
      description = "Environment variable holding the stock SCP master key.")
  String env;

  @Option(
      names = OPTION + "-file",
      description = "Owner-only file holding the stock SCP master key.")
  String file;

  SecretSource source(String target) {
    return SecretSource.of(OPTION, literal, env, file).refuseLiteralFor(target);
  }

  /**
   * Returns the stock SCP configuration for a supplied key, or {@code null} when no key form was
   * given and the profile's stock key applies.
   */
  ScpConfig override(String mode, int keyVersion, String target) throws Exception {
    byte[] key = source(target).hex();
    if (key == null) {
      return null;
    }
    try {
      return ScpConfig.fromMaster(ScpConfig.parseMode(mode), keyVersion, key);
    } finally {
      Arrays.fill(key, (byte) 0);
    }
  }

  /** Returns the supplied key, prompting on the console without echo when none was given. */
  byte[] keyOrPrompt(String target, String prompt) throws Exception {
    return source(target).hexOrPrompt(prompt);
  }
}
