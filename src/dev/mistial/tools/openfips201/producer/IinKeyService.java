/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.producer;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.SecureFiles;
import dev.mistial.tools.openfips201.crypto.EcdhKeyTransport;
import dev.mistial.tools.openfips201.crypto.KeyIdentifiers;
import dev.mistial.tools.openfips201.opid.OpidCipher;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11AdminService;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11KeyTransport;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11Session;
import dev.mistial.tools.openfips201.profiles.IssuerProfile;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Arrays;

/**
 * The FF1 key of each IIN on the producer's root token.
 *
 * <p>Contract: the key is generated on (or imported into) the root token by {@link
 * Pkcs11AdminService#ensureIinFpeKey(Pkcs11Session, String, int)} under the label prefix of the
 * producer name, and leaves the token only wrapped: to a SAM transport key ({@link
 * Pkcs11KeyTransport#wrapForSam(String, byte[], int)}) or to an operator backup key ({@link
 * #backupKey(Pkcs11Session, String, int, PublicKey, Path)}). Host FF1 runs through the token
 * ({@link #cipher(Pkcs11Session, String, int, String)}).
 */
public final class IinKeyService {
  public static final String BACKUP_SCHEMA = "openfips201.iin-fpe-backup/1";

  private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

  private final Pkcs11AdminService admin = new Pkcs11AdminService();

  /** Ensures the root token holds the IIN's FF1 key; returns its KCV (hex). */
  public String ensureKey(Pkcs11Session rootSession, String producer, int iin) {
    return HexUtil.format(admin.ensureIinFpeKey(rootSession, producer, iin).kcv());
  }

  /**
   * Returns FF1 through the token key of {@code iin}, after checking that its KCV equals {@code
   * expectedKcv} (hex).
   */
  public OpidCipher cipher(
      Pkcs11Session rootSession, String producer, int iin, String expectedKcv) {
    OpidCipher cipher =
        Pkcs11AdminService.iinCipher(rootSession, Pkcs11AdminService.iinFpeKeyLabel(producer, iin));
    if (expectedKcv == null || !expectedKcv.equalsIgnoreCase(HexUtil.format(cipher.kcv()))) {
      cipher.destroy();
      throw new IllegalStateException(
          "IIN " + iin + " token key check value differs from " + expectedKcv);
    }
    return cipher;
  }

  /**
   * Migrates {@code iin-IIII.fpe.json} into the root token: the key is imported as a sensitive
   * token object, its KCV is verified through the token, and only then is the file overwritten and
   * deleted. Returns the KCV (hex).
   */
  public String importKey(Pkcs11Session rootSession, String producer, int iin) throws IOException {
    if (!IinKeyStore.exists(producer, iin)) {
      throw new IllegalArgumentException(
          "no plaintext key file for IIN " + iin + ": " + IinKeyStore.file(producer, iin));
    }
    String kcv = IinKeyStore.kcv(producer, iin);
    byte[] key = IinKeyStore.read(producer, iin, kcv);
    try {
      admin.importIinFpeKey(rootSession, producer, iin, key, HexUtil.parse(kcv));
    } finally {
      Arrays.fill(key, (byte) 0);
    }
    IinKeyStore.destroyFile(producer, iin);
    return kcv;
  }

  /**
   * Wraps the IIN's FF1 key to {@code backupPublicKey} (P-256) with the ECDH + X9.63 + RFC 3394
   * construction and SharedInfo {@code "OPFPEBK1" || backupPub || ASCII(IIII)}, and writes the
   * result to the new owner-only file {@code out}. The plaintext key is never written.
   */
  public Pkcs11KeyTransport.Wrapped backupKey(
      Pkcs11Session rootSession, String producer, int iin, PublicKey backupPublicKey, Path out)
      throws IOException {
    return backupKey(rootSession, producer, iin, backupPublicKey, out, false);
  }

  /**
   * As {@link #backupKey(Pkcs11Session, String, int, PublicKey, Path)}; {@code allowHostKdf} as for
   * {@link Pkcs11KeyTransport#Pkcs11KeyTransport(Pkcs11Session, boolean)}.
   */
  public Pkcs11KeyTransport.Wrapped backupKey(
      Pkcs11Session rootSession,
      String producer,
      int iin,
      PublicKey backupPublicKey,
      Path out,
      boolean allowHostKdf)
      throws IOException {
    if (Files.exists(out)) {
      throw new IllegalArgumentException("backup output already exists: " + out);
    }
    String label = Pkcs11AdminService.iinFpeKeyLabel(producer, iin);
    String kcv = HexUtil.format(Pkcs11AdminService.iinCipher(rootSession, label).kcv());
    byte[] recipient = EcdhKeyTransport.point(backupPublicKey);
    Pkcs11KeyTransport.Wrapped wrapped =
        new Pkcs11KeyTransport(rootSession, allowHostKdf)
            .wrapTo(label, recipient, EcdhKeyTransport.backupSharedInfo(recipient, iin));
    JsonObject document = new JsonObject();
    document.addProperty("schema", BACKUP_SCHEMA);
    document.addProperty("iin", iin);
    document.addProperty("kcv", kcv);
    document.addProperty("created", Instant.now().toString());
    document.addProperty("recipientSki", HexUtil.format(KeyIdentifiers.ski(backupPublicKey)));
    document.addProperty("kdf", "ANSI-X9.63-SHA256");
    document.addProperty("sharedInfo", "OPFPEBK1 || recipientPublicKey(65) || ASCII(IIII)");
    document.addProperty("wrap", "RFC3394-AES256");
    document.addProperty("ephemeralPublicKey", HexUtil.format(wrapped.ephemeralPublicKey));
    document.addProperty("wrappedKey", HexUtil.format(wrapped.wrappedKey));
    SecureFiles.writeNew(out, GSON.toJson(document).getBytes(StandardCharsets.UTF_8));
    return wrapped;
  }

  /**
   * Refuses to continue while the plaintext key file of {@code iin} exists, unless the producer's
   * custody is {@code softhsm-dev}.
   */
  public static void requireNoPlaintextKey(String producer, int iin) throws IOException {
    if (IinKeyStore.exists(producer, iin)
        && !ProducerSetupService.CUSTODY_SOFTHSM_DEV.equals(custody(producer))) {
      throw new IllegalStateException(
          "plaintext FF1 key file present for IIN "
              + iin
              + "; run 'openfips201 producer iin import-key'");
    }
  }

  /** Loads {@code producer.json}. */
  public static IssuerProfile profile(String producer) throws IOException {
    Path path = ProducerPaths.producerProfile(producer);
    if (!Files.exists(path)) {
      throw new IllegalArgumentException("Producer does not exist: " + producer);
    }
    IssuerProfile profile =
        GSON.fromJson(
            new String(Files.readAllBytes(path), StandardCharsets.UTF_8), IssuerProfile.class);
    if (profile == null || profile.pkcs11 == null) {
      throw new IllegalArgumentException("Producer profile is incomplete: " + path);
    }
    return profile;
  }

  /** The {@code custody} recorded in {@code producer.json}, or {@code null}. */
  public static String custody(String producer) throws IOException {
    Path path = ProducerPaths.producerProfile(producer);
    if (!Files.exists(path)) {
      return null;
    }
    JsonElement document =
        JsonParser.parseString(new String(Files.readAllBytes(path), StandardCharsets.UTF_8));
    if (document.isJsonObject() && document.getAsJsonObject().has("custody")) {
      return document.getAsJsonObject().get("custody").getAsString();
    }
    return null;
  }
}
