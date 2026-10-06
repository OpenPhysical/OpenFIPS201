/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.crypto.SigningKey;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Map;
import java.util.TreeMap;

/**
 * Canonical JSON for root-signed documents: object members sorted by name (recursively), no
 * whitespace. A signed document carries {@code sig}: the hex ECDSA P-256 / SHA-256 signature by the
 * root over the UTF-8 canonical form of the document without {@code sig}.
 */
public final class CanonicalJson {
  static final String SIG = "sig";
  private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

  private CanonicalJson() {}

  public static String canonical(JsonElement element) {
    return GSON.toJson(sorted(element));
  }

  private static JsonElement sorted(JsonElement element) {
    if (element.isJsonObject()) {
      TreeMap<String, JsonElement> members = new TreeMap<String, JsonElement>();
      for (Map.Entry<String, JsonElement> entry : element.getAsJsonObject().entrySet()) {
        members.put(entry.getKey(), sorted(entry.getValue()));
      }
      JsonObject out = new JsonObject();
      for (Map.Entry<String, JsonElement> entry : members.entrySet()) {
        out.add(entry.getKey(), entry.getValue());
      }
      return out;
    }
    if (element.isJsonArray()) {
      JsonArray out = new JsonArray();
      for (JsonElement item : element.getAsJsonArray()) {
        out.add(sorted(item));
      }
      return out;
    }
    return element;
  }

  /** Adds {@code sig} over the canonical form of {@code document}; returns the canonical text. */
  public static String sign(JsonObject document, SigningKey root) throws Exception {
    JsonObject unsigned = document.deepCopy();
    unsigned.remove(SIG);
    byte[] signature =
        root.sign("SHA256withECDSA", canonical(unsigned).getBytes(StandardCharsets.UTF_8));
    unsigned.addProperty(SIG, HexUtil.format(signature));
    return canonical(unsigned);
  }

  /**
   * Parses {@code text}, which must be canonical, and requires its {@code sig} to verify under
   * {@code root}.
   */
  public static JsonObject verify(String text, PublicKey root) {
    JsonElement parsed = JsonParser.parseString(text);
    if (!parsed.isJsonObject() || !canonical(parsed).equals(text)) {
      throw new IllegalArgumentException("signed document is not canonical JSON");
    }
    JsonObject document = parsed.getAsJsonObject();
    if (!document.has(SIG)) {
      throw new IllegalArgumentException("signed document carries no sig");
    }
    String signature = document.get(SIG).getAsString();
    JsonObject unsigned = document.deepCopy();
    unsigned.remove(SIG);
    if (!IssuanceCrypto.verify(
        root, canonical(unsigned).getBytes(StandardCharsets.UTF_8), HexUtil.parse(signature))) {
      throw new IllegalStateException("root signature does not verify");
    }
    return document;
  }
}
