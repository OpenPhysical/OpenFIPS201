/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.producer;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11AdminService;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11Config;
import dev.mistial.tools.openfips201.profiles.IssuerProfile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.EnumSet;
import java.util.Set;

public final class ProducerSetupService {
  private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

  public Result setup(
      String name,
      String module,
      String tokenLabel,
      String rootSubject,
      String f9Subject,
      boolean force)
      throws Exception {
    Path producer = ProducerPaths.producer(name);
    Path profilePath = ProducerPaths.producerProfile(name);
    if (Files.exists(profilePath) && !force) {
      throw new IllegalArgumentException("Producer already exists: " + name);
    }
    Files.createDirectories(producer);
    Files.createDirectories(ProducerPaths.home().resolve("softhsm").resolve("tokens"));
    Path pinFile = producer.resolve("pkcs11.pin");
    String pin = randomHex(16);
    writePrivateFile(pinFile, pin + "\n");
    Path softhsmConf = ProducerPaths.home().resolve("softhsm").resolve("softhsm2.conf");
    writeSoftHsmConfig(softhsmConf);

    String selectedModule = module == null || module.isEmpty() ? defaultSoftHsmModule() : module;
    String selectedToken = tokenLabel == null || tokenLabel.isEmpty() ? name : tokenLabel;
    initSoftHsmTokenIfNeeded(softhsmConf, selectedToken, pin);

    byte[] rootId = randomBytes(8);
    byte[] aesId = randomBytes(8);
    String rootLabel = name + "-root-ca";
    String aesLabel = name + "-card-master";
    Pkcs11Config pkcs11 = new Pkcs11Config();
    pkcs11.module = selectedModule;
    pkcs11.tokenLabel = selectedToken;
    pkcs11.pinFile = pinFile.toString();
    pkcs11.softhsmConfig = softhsmConf.toString();

    new Pkcs11AdminService().ensureRootSigner(pkcs11, rootLabel, rootId, rootSubject);
    new Pkcs11AdminService().generateAes256Key(pkcs11, aesLabel, aesId);

    IssuerProfile profile = new IssuerProfile();
    profile.name = name;
    profile.pkcs11 = pkcs11.copy();
    profile.pkcs11.keyAlias = rootLabel;
    profile.pkcs11.keyId = HexUtil.format(rootId);
    profile.attestation.rootSubject = rootSubject;
    profile.attestation.issuerSubject = f9Subject;
    profile.cardKeys.masterKeyAlias = aesLabel;
    profile.cardKeys.masterKeyId = HexUtil.format(aesId);
    profile.cardKeys.pkcs11 = pkcs11.copy();
    profile.cardKeys.pkcs11.keyAlias = aesLabel;
    profile.cardKeys.pkcs11.keyId = HexUtil.format(aesId);
    profile.receipts.directory = producer.resolve("receipts").toString();
    Files.write(profilePath, GSON.toJson(profile).getBytes(StandardCharsets.UTF_8));
    return new Result(profilePath, softhsmConf, selectedModule, selectedToken);
  }

  private static void writeSoftHsmConfig(Path path) throws Exception {
    if (Files.exists(path)) {
      return;
    }
    Files.createDirectories(path.getParent());
    String body =
        "directories.tokendir = "
            + ProducerPaths.home().resolve("softhsm").resolve("tokens")
            + "\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n";
    Files.write(path, body.getBytes(StandardCharsets.UTF_8));
  }

  private static void initSoftHsmTokenIfNeeded(Path conf, String tokenLabel, String pin)
      throws Exception {
    ProcessBuilder process =
        new ProcessBuilder(
            "softhsm2-util",
            "--init-token",
            "--free",
            "--label",
            tokenLabel,
            "--so-pin",
            pin,
            "--pin",
            pin);
    process.environment().put("SOFTHSM2_CONF", conf.toString());
    Process started = process.start();
    int exit = started.waitFor();
    if (exit != 0) {
      String stderr = new String(started.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
      if (!stderr.contains("Token label is already used")) {
        throw new IllegalStateException("softhsm2-util failed: " + stderr.trim());
      }
    }
  }

  private static String defaultSoftHsmModule() {
    String[] candidates = {
      "/opt/homebrew/lib/softhsm/libsofthsm2.so",
      "/usr/local/lib/softhsm/libsofthsm2.so",
      "/usr/lib/softhsm/libsofthsm2.so"
    };
    for (String candidate : candidates) {
      if (Files.exists(Path.of(candidate))) {
        return candidate;
      }
    }
    return "libsofthsm2.so";
  }

  private static void writePrivateFile(Path path, String value) throws Exception {
    Files.write(path, value.getBytes(StandardCharsets.UTF_8));
    try {
      Set<PosixFilePermission> permissions =
          EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
      Files.setPosixFilePermissions(path, permissions);
    } catch (UnsupportedOperationException ignored) {
      // Windows filesystems do not expose POSIX modes.
    }
  }

  private static byte[] randomBytes(int length) {
    byte[] value = new byte[length];
    new SecureRandom().nextBytes(value);
    return value;
  }

  private static String randomHex(int length) {
    return HexUtil.format(randomBytes(length));
  }

  public static final class Result {
    public final Path profilePath;
    public final Path softhsmConfig;
    public final String module;
    public final String tokenLabel;

    Result(Path profilePath, Path softhsmConfig, String module, String tokenLabel) {
      this.profilePath = profilePath;
      this.softhsmConfig = softhsmConfig;
      this.module = module;
      this.tokenLabel = tokenLabel;
    }
  }
}
