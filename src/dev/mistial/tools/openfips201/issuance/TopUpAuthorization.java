/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import dev.mistial.tools.openfips201.common.ByteArrays;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.SecureFiles;
import dev.mistial.tools.openfips201.crypto.SigningKey;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;

/**
 * A root-signed quota top-up, exchanged as files between the stations (root, SAM and card are never
 * together). The root signs {@code "OPSAMTOPUP1" || samSki || ts(u64 ms BE) || add(u32 BE)} with
 * ECDSA P-256 / SHA-256; the SAM accepts it once, and only when {@code ts} is strictly greater than
 * the last timestamp it accepted.
 *
 * <ul>
 *   <li>{@code sam top-up --request-out} (production) writes the request ({@code
 *       openfips201.topup-request/2}): the batch, samId, SAM SKI, timestamp and amount, and the
 *       SAM's current STATUS signed over {@code nonce};
 *   <li>{@code root sign-top-up} checks it against the registry and the bound SAM's certificate,
 *       records a registry {@code topup} line and returns the authorization ({@code
 *       openfips201.topup-authorization/2});
 *   <li>{@code sam top-up --authorization-in} (production) applies it.
 * </ul>
 */
public final class TopUpAuthorization {
  public static final String REQUEST_SCHEMA = "openfips201.topup-request/2";
  public static final String AUTHORIZATION_SCHEMA = "openfips201.topup-authorization/2";
  static final byte[] PREFIX = "OPSAMTOPUP1".getBytes(StandardCharsets.US_ASCII);
  private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

  public String schema;
  public String producer;
  public String batch;
  public int iin;
  public int batchNumber;
  public String samId;
  public String samSki;
  public long timestamp;
  public long add;

  /** The SAM's signed STATUS response ({@code statusTLV || 9E sig}) over {@link #nonce}. */
  public String status;

  public String nonce;
  public String signature;

  public static TopUpAuthorization request(
      String producer,
      String batch,
      int iin,
      int batchNumber,
      String samId,
      byte[] samSki,
      long timestamp,
      long add,
      byte[] signedStatus,
      byte[] nonce) {
    if (add < 1 || add > 0xFFFFFFFFL) {
      throw new IllegalArgumentException("--add must be 1..4294967295");
    }
    if (samSki == null || samSki.length != 20) {
      throw new IllegalArgumentException("SAM SKI must be 20 octets");
    }
    TopUpAuthorization request = new TopUpAuthorization();
    request.schema = REQUEST_SCHEMA;
    request.producer = producer;
    request.batch = batch;
    request.iin = iin;
    request.batchNumber = batchNumber;
    request.samId = samId;
    request.samSki = HexUtil.format(samSki);
    request.timestamp = timestamp;
    request.add = add;
    request.status = HexUtil.format(signedStatus);
    request.nonce = HexUtil.format(nonce);
    return request;
  }

  /** The signed message. */
  public byte[] message() {
    return ByteArrays.concat(
        PREFIX,
        HexUtil.parse(samSki),
        IssuanceCrypto.unsigned(timestamp, 8),
        IssuanceCrypto.unsigned(add, 4));
  }

  /**
   * The SAM STATUS carried by the request, verified under {@code samKey}.
   *
   * @throws IllegalStateException when the signature does not verify
   */
  public SamStatus verifiedStatus(PublicKey samKey) {
    if (status == null || nonce == null) {
      throw new IllegalArgumentException("the top-up request carries no signed SAM STATUS");
    }
    return SamStatus.parseSigned(HexUtil.parse(status), HexUtil.parse(nonce), samKey);
  }

  /** Signs this request with {@code root}; the result is an authorization. */
  public TopUpAuthorization sign(SigningKey root) throws Exception {
    if (!REQUEST_SCHEMA.equals(schema)) {
      throw new IllegalArgumentException("not a top-up request: " + schema);
    }
    TopUpAuthorization signed = copy();
    signed.schema = AUTHORIZATION_SCHEMA;
    signed.signature = HexUtil.format(root.sign("SHA256withECDSA", message()));
    if (!signed.verifies(root.publicKey())) {
      throw new IllegalStateException("root top-up signature does not verify");
    }
    return signed;
  }

  public boolean verifies(PublicKey root) {
    return signature != null && IssuanceCrypto.verify(root, message(), HexUtil.parse(signature));
  }

  public byte[] signatureBytes() {
    if (signature == null) {
      throw new IllegalStateException("top-up is not signed");
    }
    return HexUtil.parse(signature);
  }

  public Path writeNew(Path file) throws Exception {
    return SecureFiles.writeNew(file, GSON.toJson(this).getBytes(StandardCharsets.UTF_8));
  }

  public static TopUpAuthorization read(Path file) throws Exception {
    TopUpAuthorization value =
        GSON.fromJson(
            new String(Files.readAllBytes(file), StandardCharsets.UTF_8), TopUpAuthorization.class);
    if (value == null
        || (!REQUEST_SCHEMA.equals(value.schema) && !AUTHORIZATION_SCHEMA.equals(value.schema))) {
      throw new IllegalArgumentException("not a top-up request or authorization: " + file);
    }
    return value;
  }

  private TopUpAuthorization copy() {
    TopUpAuthorization copy = new TopUpAuthorization();
    copy.schema = schema;
    copy.producer = producer;
    copy.batch = batch;
    copy.iin = iin;
    copy.batchNumber = batchNumber;
    copy.samId = samId;
    copy.samSki = samSki;
    copy.timestamp = timestamp;
    copy.add = add;
    copy.status = status;
    copy.nonce = nonce;
    copy.signature = signature;
    return copy;
  }
}
