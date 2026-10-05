/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.opid;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Loads {@code <openfips201.testVectors>/opid/*.json}. The property defaults to {@code
 * test-vectors}, resolved against the working directory (the repository root).
 */
final class OpidVectors {
  static final String SCHEMA = "openphysical.opid-vectors/2";

  private OpidVectors() {}

  static Path directory() {
    return Paths.get(System.getProperty("openfips201.testVectors", "test-vectors"), "opid");
  }

  static JsonObject load(String name) throws IOException {
    Path path = directory().resolve(name);
    JsonObject root =
        JsonParser.parseString(new String(Files.readAllBytes(path), StandardCharsets.UTF_8))
            .getAsJsonObject();
    assertEquals(SCHEMA, root.get("schema").getAsString(), name);
    return root;
  }
}
