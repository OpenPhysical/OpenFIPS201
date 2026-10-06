/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.producer;

import apdu4j.core.CommandAPDU;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import dev.mistial.tools.openfips201.attestation.StrictDer;
import dev.mistial.tools.openfips201.common.CardTransport;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.crypto.KeyIdentifiers;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11AdminService;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11Session;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * Station separation (root station: root CA, IIN FF1 keys, registry, SAM reader; production
 * station: card-master and handoff keys, SAM and card readers). Root, SAM and card are never
 * together, and the production host can never see the root key, an FF1 key or LCG parameters.
 */
public final class StationGuard {
  private StationGuard() {}

  /** {@code producer.json} schema 3, or a refusal with migration guidance. */
  public static JsonObject requireSchema(String producer) throws IOException {
    Path path = ProducerPaths.producerProfile(producer);
    if (!Files.exists(path)) {
      throw new IllegalArgumentException("Producer is not set up: " + producer);
    }
    JsonElement document =
        JsonParser.parseString(new String(Files.readAllBytes(path), StandardCharsets.UTF_8));
    if (!document.isJsonObject()
        || !document.getAsJsonObject().has("schema")
        || !ProducerSetupService.SCHEMA.equals(
            document.getAsJsonObject().get("schema").getAsString())) {
      throw new IllegalArgumentException(
          "Producer "
              + producer
              + " is not schema "
              + ProducerSetupService.SCHEMA
              + "; set up a root station and a production station ('producer setup --station"
              + " root|production') and re-issue its SAMs");
    }
    return document.getAsJsonObject();
  }

  /** The producer's station role. */
  public static String station(String producer) throws IOException {
    JsonObject document = requireSchema(producer);
    return document.has("station") ? document.get("station").getAsString() : null;
  }

  /** Refuses a command meant for the other station. */
  public static void requireStation(String producer, String station) throws IOException {
    String actual = station(producer);
    if (!station.equals(actual)) {
      throw new IllegalStateException(
          "This command runs only at a "
              + station
              + " station; producer "
              + producer
              + " is a "
              + actual
              + " station");
    }
  }

  /** Reads one public root certificate. */
  public static X509Certificate readRootPem(Path rootPem) throws IOException {
    if (rootPem == null || !Files.isRegularFile(rootPem)) {
      throw new IllegalArgumentException("root certificate not found: " + rootPem);
    }
    return StrictDer.readSinglePemCertificate(rootPem);
  }

  /**
   * A production command refuses to start when its token holds the root key (by its root.pem key
   * identifier or the root key label) or any AES key labelled {@code *-fpe}, or when any batch
   * record holds LCG parameters.
   */
  public static void requireProductionClean(
      String producer, Pkcs11Session session, X509Certificate root) throws IOException {
    byte[] rootSki = KeyIdentifiers.ski(root.getPublicKey());
    for (byte[] point : Pkcs11AdminService.ecPublicPoints(session)) {
      // RFC 7093 method 1 hashes the subjectPublicKey octets, which are the point itself.
      if (Arrays.equals(Arrays.copyOf(sha256(point), KeyIdentifiers.SKI_LENGTH), rootSki)) {
        throw new IllegalStateException(
            "The production token holds the root CA key; root and production are separate"
                + " stations");
      }
    }
    if (Pkcs11AdminService.hasEcPrivateKey(session, producer + "-root-ca")) {
      throw new IllegalStateException(
          "The production token holds a key labelled "
              + producer
              + "-root-ca; root and production are separate stations");
    }
    for (String label : Pkcs11AdminService.aesKeyLabels(session)) {
      if (label.endsWith("-fpe")) {
        throw new IllegalStateException(
            "The production token holds an FF1 key (" + label + "); it belongs on the root token");
      }
    }
    requireNoLcgRecords(producer);
  }

  /** Refuses when any batch record of {@code producer} carries LCG parameters. */
  public static void requireNoLcgRecords(String producer) throws IOException {
    Path batches = ProducerPaths.producer(producer).resolve("batches");
    if (!Files.isDirectory(batches)) {
      return;
    }
    try (DirectoryStream<Path> entries = Files.newDirectoryStream(batches)) {
      for (Path entry : entries) {
        Path json = entry.resolve("batch.json");
        if (!Files.isRegularFile(json, LinkOption.NOFOLLOW_LINKS)) {
          continue;
        }
        JsonElement document =
            JsonParser.parseString(new String(Files.readAllBytes(json), StandardCharsets.UTF_8));
        if (document.isJsonObject() && document.getAsJsonObject().has("lcg")) {
          throw new IllegalStateException(
              "Batch record " + json + " holds LCG parameters; they never leave the root station");
        }
      }
    }
  }

  /**
   * A root-station command refuses a reader whose card answers SELECT for the PIV applet: the root
   * station never touches a card.
   */
  public static void requireNotPivCard(CardTransport transport) {
    int sw =
        transport
            .bibo()
            .transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, GlobalPlatformSession.PIV_AID, 256))
            .getSW();
    if (sw == 0x9000 || (sw & 0xFF00) == 0x6100) {
      throw new IllegalStateException(
          "The reader holds a PIV card; the root station handles only SAMs");
    }
  }

  private static byte[] sha256(byte[] value) {
    org.bouncycastle.crypto.digests.SHA256Digest digest =
        new org.bouncycastle.crypto.digests.SHA256Digest();
    digest.update(value, 0, value.length);
    byte[] out = new byte[32];
    digest.doFinal(out, 0);
    return out;
  }
}
