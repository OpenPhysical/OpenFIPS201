/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import dev.mistial.tools.openfips201.common.SecureFiles;
import dev.mistial.tools.openfips201.crypto.EcdhKeyTransport;
import dev.mistial.tools.openfips201.crypto.KeyIdentifiers;
import dev.mistial.tools.openfips201.producer.ProducerPaths;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * Production-station handoff public keys ({@code station.pem}, a P-256 {@code PUBLIC KEY}).
 *
 * <ul>
 *   <li>{@code station init} (production) writes the station's handoff point;
 *   <li>{@code station import} (root) stores it as {@code station-keys/<name>.pem}; {@code sam
 *       personalize --station <name>} wraps the SAM handoff secrets to it.
 * </ul>
 *
 * <p>The station key identifier is the RFC 7093 method 1 value of the point (SHA-256, leftmost 160
 * bits), which binds a handoff bundle to its station.
 */
public final class StationKeys {
  private static final Pattern NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,63}");

  private StationKeys() {}

  /** {@code station-keys/<name>.pem} of the root station {@code producer}. */
  public static Path stationFile(String producer, String station) {
    if (station == null || !NAME.matcher(station).matches()) {
      throw new IllegalArgumentException("station name must be 1..64 of [A-Za-z0-9._-]");
    }
    return ProducerPaths.producer(producer).resolve("station-keys").resolve(station + ".pem");
  }

  /** {@code station import}: stores a production station's handoff key; never replaces one. */
  public static Path importStation(String producer, String station, Path pem) throws IOException {
    byte[] point = readPoint(pem);
    Path file = stationFile(producer, station);
    ProducerPaths.createDirectories(file.getParent());
    if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
      throw new IllegalArgumentException("station " + station + " is already imported: " + file);
    }
    SecureFiles.writeNew(file, encode(point));
    return file;
  }

  /** The handoff point of an imported station. */
  public static byte[] importedPoint(String producer, String station) throws IOException {
    Path file = stationFile(producer, station);
    if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
      throw new IllegalArgumentException(
          "station " + station + " is not imported; run 'station import'");
    }
    return readPoint(file);
  }

  /** {@code station init}: writes {@code point} as a new PEM file. */
  public static Path writeStationPem(Path out, byte[] point) throws IOException {
    EcdhKeyTransport.requireP256Point(point);
    return SecureFiles.writeNew(out, encode(point));
  }

  /** The station key identifier of {@code point}. */
  public static byte[] ski(byte[] point) {
    EcdhKeyTransport.requireP256Point(point);
    return KeyIdentifiers.ski(IssuanceCrypto.publicKey(point));
  }

  /** Reads a P-256 {@code PUBLIC KEY} PEM file and returns its uncompressed point. */
  public static byte[] readPoint(Path pem) throws IOException {
    String text = new String(Files.readAllBytes(pem), StandardCharsets.US_ASCII);
    try (PEMParser parser = new PEMParser(new StringReader(text))) {
      Object object = parser.readObject();
      if (!(object instanceof SubjectPublicKeyInfo) || parser.readObject() != null) {
        throw new IllegalArgumentException(pem + " must hold exactly one PUBLIC KEY");
      }
      byte[] point = ((SubjectPublicKeyInfo) object).getPublicKeyData().getBytes();
      EcdhKeyTransport.requireP256Point(point);
      return point;
    }
  }

  private static byte[] encode(byte[] point) throws IOException {
    SubjectPublicKeyInfo spki =
        new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(
                X9ObjectIdentifiers.id_ecPublicKey, X9ObjectIdentifiers.prime256v1),
            point);
    StringWriter text = new StringWriter();
    try (PemWriter writer = new PemWriter(text)) {
      writer.writeObject(new PemObject("PUBLIC KEY", spki.getEncoded("DER")));
    }
    return text.toString().getBytes(StandardCharsets.US_ASCII);
  }
}
