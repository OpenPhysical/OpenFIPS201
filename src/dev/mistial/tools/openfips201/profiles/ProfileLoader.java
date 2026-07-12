/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.profiles;

import com.google.gson.Gson;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public final class ProfileLoader {
  private static final Gson GSON = new Gson();

  private ProfileLoader() {}

  public static IssuerProfile load(String profile) throws Exception {
    if (profile == null || profile.isEmpty() || "emulator-dev".equals(profile)) {
      return emulatorDev();
    }
    if ("issuer-card".equals(profile)) {
      IssuerProfile p = new IssuerProfile();
      p.name = "issuer-card";
      validate(p);
      return p;
    }
    try (Reader reader = Files.newBufferedReader(Paths.get(profile), StandardCharsets.UTF_8)) {
      IssuerProfile p = GSON.fromJson(reader, IssuerProfile.class);
      validate(p);
      return p;
    }
  }

  public static IssuerProfile emulatorDev() {
    IssuerProfile p = new IssuerProfile();
    p.name = "emulator-dev";
    p.stockScp.masterKeyEnv = null;
    p.applet.loadCap = false;
    p.cardKeys.masterKeyEnv = "OPENFIPS201_EMULATOR_CARD_MASTER";
    p.receipts.directory = "build/cardstock-receipts";
    return p;
  }

  private static void validate(IssuerProfile p) {
    if (p == null) {
      throw new IllegalArgumentException("profile is empty");
    }
    requireNoSecret("stockScp.masterKeyEnv", p.stockScp.masterKeyEnv);
    requireNoSecret("cardKeys.masterKeyEnv", p.cardKeys.masterKeyEnv);
    requireNoSecret("pkcs11.pinEnv", p.pkcs11.pinEnv);
  }

  private static void requireNoSecret(String field, String value) {
    if (value == null) {
      return;
    }
    String lower = value.toLowerCase(java.util.Locale.ROOT);
    if (lower.matches(".*[0-9a-f]{32,}.*")) {
      throw new IllegalArgumentException(field + " must name an environment variable, not a key");
    }
  }
}
