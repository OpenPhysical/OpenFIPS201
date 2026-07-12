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
    return home().resolve("producers").resolve(name);
  }

  public static Path producerProfile(String name) {
    return producer(name).resolve("producer.json");
  }

  public static Path batch(String producer, String batch) {
    return producer(producer).resolve("batches").resolve(batch);
  }
}
