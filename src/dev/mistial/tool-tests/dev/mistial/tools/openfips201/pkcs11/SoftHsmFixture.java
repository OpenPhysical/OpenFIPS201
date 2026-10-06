/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.SecureFiles;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Comparator;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;

/**
 * SoftHSM2 environment shared by every {@code softhsm}-tagged test in one JVM.
 *
 * <p>Contract: a SoftHSM2 module reads {@code SOFTHSM2_CONF} once, at its first {@code
 * C_Initialize} in the process, so the JVM uses one OpenFIPS201 home ({@code openfips201.home})
 * whose {@code softhsm/softhsm2.conf} points at a private token directory. That is the layout
 * {@code producer setup --dev-softhsm} creates, so producer and PKCS#11 tests share it. The home is
 * deleted at JVM exit. Tests isolate themselves with {@link #uniqueLabel(String)}.
 */
public final class SoftHsmFixture {
  private static final String[] MODULES = {
    "/opt/homebrew/lib/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib64/pkcs11/libsofthsm2.so"
  };
  private static final SecureRandom RANDOM = new SecureRandom();
  private static Path home;

  private SoftHsmFixture() {}

  /** The SoftHSM2 module ({@code OPENFIPS201_SOFTHSM_MODULE} or a default path), or null. */
  public static String module() {
    String override = System.getenv("OPENFIPS201_SOFTHSM_MODULE");
    if (override != null && !override.isEmpty()) {
      return Files.exists(Paths.get(override)) ? override : null;
    }
    for (String candidate : MODULES) {
      if (Files.exists(Paths.get(candidate))) {
        return candidate;
      }
    }
    return null;
  }

  /**
   * Skips the calling test when no SoftHSM2 module is installed; otherwise points {@code
   * openfips201.home} at the JVM's SoftHSM home and returns it.
   */
  public static synchronized Path requireSoftHsm() throws IOException {
    Assumptions.assumeTrue(module() != null, "SoftHSM2 module not found");
    if (home == null) {
      Path created = Files.createTempDirectory("openfips201-softhsm").toRealPath();
      Path tokens =
          SecureFiles.createPrivateDirectories(created, created.resolve("softhsm/tokens"));
      String conf =
          "directories.tokendir = "
              + tokens
              + "\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n";
      SecureFiles.writeNew(
          created.resolve("softhsm/softhsm2.conf"), conf.getBytes(StandardCharsets.UTF_8));
      Runtime.getRuntime().addShutdownHook(new Thread(() -> deleteTree(created)));
      home = created;
    }
    System.setProperty("openfips201.home", home.toString());
    return home;
  }

  public static Path conf() throws IOException {
    return requireSoftHsm().resolve("softhsm/softhsm2.conf");
  }

  /** Token selection for {@code label} on the JVM's SoftHSM, without a PIN source. */
  public static Pkcs11Config config(String label) throws IOException {
    Pkcs11Config config = new Pkcs11Config();
    config.module = module();
    config.softhsmConfig = conf().toString();
    config.tokenLabel = label;
    return config;
  }

  /** {@code prefix} followed by 8 random hex digits. */
  public static String uniqueLabel(String prefix) {
    byte[] suffix = new byte[4];
    RANDOM.nextBytes(suffix);
    return prefix + HexUtil.format(suffix).toLowerCase(java.util.Locale.ROOT);
  }

  private static void deleteTree(Path root) {
    try (Stream<Path> paths = Files.walk(root)) {
      paths.sorted(Comparator.reverseOrder()).forEach(path -> path.toFile().delete());
    } catch (IOException e) {
      // Best effort at JVM exit; the directory is below java.io.tmpdir.
    }
  }
}
