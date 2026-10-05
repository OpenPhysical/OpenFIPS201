/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.crypto;

import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.SecureFiles;
import java.io.Console;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

/**
 * One secret command-line input with its literal, {@code -env} and {@code -file} forms.
 *
 * <p>Contract: at most one form may be given. A literal value on the command line is visible in the
 * process table and shell history, so it is refused for PC/SC targets ({@link
 * #refuseLiteralFor(String)}); the emulator ({@code zmq:}) still accepts it. A {@code -file} must
 * be a regular file owned by the current user with no group or other permission bits ({@link
 * SecureFiles#requireOwnerOnly(Path)}). With no form given, {@link #charsOrPrompt(String)} reads
 * the secret from the console without echo. Every returned array is owned by the caller, which
 * wipes it after use.
 */
public final class SecretSource {
  private final String option;
  private final String literal;
  private final String env;
  private final String file;

  private SecretSource(String option, String literal, String env, String file) {
    this.option = option;
    this.literal = literal;
    this.env = env;
    this.file = file;
  }

  /**
   * @param option the literal option name, for example {@code --stock-scp-key}; the env and file
   *     forms are {@code option + "-env"} and {@code option + "-file"}
   */
  public static SecretSource of(String option, String literal, String env, String file) {
    SecretSource source = new SecretSource(option, literal, empty(env), empty(file));
    int forms = (literal != null ? 1 : 0) + (source.env != null ? 1 : 0);
    forms += source.file != null ? 1 : 0;
    if (forms > 1) {
      throw new IllegalArgumentException(
          "Use only one of " + option + ", " + option + "-env, or " + option + "-file");
    }
    return source;
  }

  public boolean isPresent() {
    return literal != null || env != null || file != null;
  }

  public boolean isLiteral() {
    return literal != null;
  }

  /**
   * Refuses a literal secret when {@code target} names a PC/SC reader.
   *
   * @return this source
   */
  public SecretSource refuseLiteralFor(String target) {
    if (literal != null && target != null && target.startsWith("pcsc:")) {
      throw new IllegalArgumentException(
          "secrets on argv are refused for pcsc: targets; use "
              + option
              + "-env or "
              + option
              + "-file");
    }
    return this;
  }

  /** Returns the secret characters, or {@code null} when no form was given. */
  public char[] chars() throws IOException {
    if (literal != null) {
      return literal.toCharArray();
    }
    if (env != null) {
      return fromEnv(env);
    }
    if (file != null) {
      return fromFile(Paths.get(file));
    }
    return null;
  }

  /** Returns the secret characters, prompting on the console without echo when none was given. */
  public char[] charsOrPrompt(String prompt) throws IOException {
    char[] value = chars();
    return value != null ? value : fromConsole(prompt, option);
  }

  /** Returns the decoded hex secret, or {@code null} when no form was given. */
  public byte[] hex() throws IOException {
    return parseAndWipe(chars());
  }

  /** Returns the decoded hex secret, prompting on the console without echo when none was given. */
  public byte[] hexOrPrompt(String prompt) throws IOException {
    return parseAndWipe(charsOrPrompt(prompt));
  }

  /** Reads an environment variable into a new array. */
  public static char[] fromEnv(String name) {
    String value = System.getenv(name);
    if (value == null) {
      throw new IllegalArgumentException("Environment variable is not set: " + name);
    }
    return value.toCharArray();
  }

  /**
   * Reads an owner-only UTF-8 secret file, without trailing whitespace, into a new array. The raw
   * file bytes and decode buffers are wiped before return.
   */
  public static char[] fromFile(Path path) throws IOException {
    SecureFiles.requireOwnerOnly(path);
    byte[] raw = Files.readAllBytes(path);
    CharBuffer decoded = null;
    try {
      decoded =
          StandardCharsets.UTF_8
              .newDecoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .onUnmappableCharacter(CodingErrorAction.REPORT)
              .decode(ByteBuffer.wrap(raw));
      int end = decoded.limit();
      while (end > 0 && Character.isWhitespace(decoded.get(end - 1))) {
        end--;
      }
      char[] value = new char[end];
      decoded.get(value, 0, end);
      return value;
    } catch (CharacterCodingException e) {
      throw new IllegalArgumentException("secret file is not valid UTF-8: " + path);
    } finally {
      Arrays.fill(raw, (byte) 0);
      if (decoded != null && decoded.hasArray()) {
        Arrays.fill(decoded.array(), '\0');
      }
    }
  }

  /** Reads a secret from the console without echo. */
  public static char[] fromConsole(String prompt, String option) {
    Console console = System.console();
    if (console == null) {
      throw new IllegalArgumentException(
          option + " is required; use " + option + "-env or " + option + "-file");
    }
    char[] value = console.readPassword("%s: ", prompt);
    if (value == null || value.length == 0) {
      throw new IllegalArgumentException(option + " is required");
    }
    return value;
  }

  private static byte[] parseAndWipe(char[] value) {
    if (value == null) {
      return null;
    }
    try {
      return HexUtil.parseSecret(value);
    } finally {
      Arrays.fill(value, '\0');
    }
  }

  private static String empty(String value) {
    return value == null || value.isEmpty() ? null : value;
  }
}
