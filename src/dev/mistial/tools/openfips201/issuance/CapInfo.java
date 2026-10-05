/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import dev.mistial.tools.openfips201.common.HexUtil;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import pro.javacard.capfile.CAPFile;

/**
 * The PIV CAP an issuance installs: its SHA-256, its GlobalPlatform load-file data hash (SHA-256)
 * and the build properties written beside it ({@code <cap>.properties}).
 */
public final class CapInfo {
  public final Path path;
  public final String sha256;
  public final String loadFileHash;
  public final Map<String, String> properties;

  CapInfo(Path path, String sha256, String loadFileHash, Map<String, String> properties) {
    this.path = path;
    this.sha256 = sha256;
    this.loadFileHash = loadFileHash;
    this.properties = properties;
  }

  /**
   * Reads {@code cap} and its properties. The build must have attestation enabled ({@code
   * attestation.enabled=true}): without it the card cannot generate, prove or load F9.
   */
  public static CapInfo read(Path cap) throws Exception {
    if (cap == null || !Files.isRegularFile(cap)) {
      throw new IllegalArgumentException("CAP file not found: " + cap);
    }
    byte[] bytes = Files.readAllBytes(cap);
    CAPFile parsed = CAPFile.fromBytes(bytes);
    Path propertiesPath = Paths.get(cap.toString() + ".properties");
    if (!Files.isRegularFile(propertiesPath)) {
      throw new IllegalArgumentException("CAP build properties not found: " + propertiesPath);
    }
    Properties loaded = new Properties();
    try (InputStream in = Files.newInputStream(propertiesPath)) {
      loaded.load(in);
    }
    Map<String, String> properties = new LinkedHashMap<String, String>();
    for (Map.Entry<String, String> entry :
        new TreeMap<String, String>(asStrings(loaded)).entrySet()) {
      properties.put(entry.getKey(), entry.getValue());
    }
    if (!"true".equals(properties.get("attestation.enabled"))) {
      throw new IllegalArgumentException(
          "CAP " + cap + " was built without attestation (attestation.enabled=true is required)");
    }
    return new CapInfo(
        cap,
        HexUtil.format(IssuanceCrypto.sha256(bytes)),
        HexUtil.format(parsed.getLoadFileDataHash("SHA-256")),
        properties);
  }

  private static Map<String, String> asStrings(Properties properties) {
    Map<String, String> out = new LinkedHashMap<String, String>();
    for (String name : properties.stringPropertyNames()) {
      out.put(name, properties.getProperty(name));
    }
    return out;
  }
}
