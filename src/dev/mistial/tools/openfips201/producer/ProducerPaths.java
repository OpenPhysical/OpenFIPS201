/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.producer;

import java.nio.file.Path;
import java.nio.file.Paths;

public final class ProducerPaths {
  private ProducerPaths() {}

  public static Path home() {
    String override = System.getProperty("openfips201.home");
    if (override != null && !override.isEmpty()) {
      return Paths.get(override);
    }
    override = System.getenv("OPENFIPS201_HOME");
    if (override != null && !override.isEmpty()) {
      return Paths.get(override);
    }
    return Paths.get(System.getProperty("user.home"), ".openfips201");
  }

  public static Path producer(String name) {
    return home().resolve("producers").resolve(segment("producer", name));
  }

  public static Path producerProfile(String name) {
    return producer(name).resolve("producer.json");
  }

  public static Path batch(String producer, String batch) {
    return producer(producer).resolve("batches").resolve(segment("batch", batch));
  }

  private static String segment(String label, String value) {
    if (value == null || value.isEmpty()) {
      throw new IllegalArgumentException(label + " name is required");
    }
    if (value.indexOf('/') >= 0 || value.indexOf('\\') >= 0) {
      throw new IllegalArgumentException(label + " name must be a single path segment");
    }
    Path path = Paths.get(value);
    if (path.isAbsolute() || path.getNameCount() != 1 || ".".equals(value) || "..".equals(value)) {
      throw new IllegalArgumentException(label + " name must be a single path segment");
    }
    return value;
  }
}
