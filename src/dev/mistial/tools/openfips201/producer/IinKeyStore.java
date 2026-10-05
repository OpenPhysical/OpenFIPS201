/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.producer;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.SecureFiles;
import dev.mistial.tools.openfips201.opid.OpidCipher;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Locale;

/**
 * The FF1 key of one IIN: {@code producers/<p>/iin-<IIII>.fpe.json}, schema {@code
 * openfips201.iin-fpe/1}, owner-only (0600). One AES-256 key enciphers the OPIDs of every batch and
 * SAM of the IIN. The file is created once with {@code CREATE_NEW} and never overwritten; batches
 * refer to it by its key check value.
 *
 * <p>This is the legacy plaintext custody. {@link IinKeyService#importKey} moves the key into the
 * root token and then destroys the file ({@link #destroyFile(String, int)}).
 */
public final class IinKeyStore {
  public static final String SCHEMA = "openfips201.iin-fpe/1";
  private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

  /** File contents. */
  static final class Record {
    String schema;
    int iin;
    String created;
    String key;
    String kcv;
  }

  private IinKeyStore() {}

  public static Path file(String producer, int iin) {
    return ProducerPaths.producer(producer)
        .resolve(String.format(Locale.ROOT, "iin-%04d.fpe.json", iin));
  }

  /** Returns the KCV of the IIN's key, creating the key file with a fresh key when none exists. */
  public static String ensure(String producer, int iin, SecureRandom random) throws IOException {
    Path file = file(producer, iin);
    if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
      return load(file, iin).kcv;
    }
    byte[] key = OpidCipher.generateKey(random);
    char[] hex = HexUtil.format(key).toCharArray();
    try {
      Record record = new Record();
      record.schema = SCHEMA;
      record.iin = iin;
      record.created = Instant.now().toString();
      record.key = new String(hex);
      record.kcv = HexUtil.format(OpidCipher.of(key).kcv());
      byte[] json = GSON.toJson(record).getBytes(StandardCharsets.UTF_8);
      try {
        SecureFiles.writeNew(file, json);
      } finally {
        Arrays.fill(json, (byte) 0);
      }
      return record.kcv;
    } finally {
      Arrays.fill(key, (byte) 0);
      Arrays.fill(hex, '\0');
    }
  }

  /**
   * Returns the IIN's key; the file must be owner-only and its key must have check value {@code
   * expectedKcv}. The caller wipes the returned array.
   */
  public static byte[] read(String producer, int iin, String expectedKcv) throws IOException {
    Record record = load(file(producer, iin), iin);
    if (expectedKcv == null || !expectedKcv.equalsIgnoreCase(record.kcv)) {
      throw new IllegalStateException(
          "IIN "
              + iin
              + " key check value "
              + record.kcv
              + " differs from the batch's "
              + expectedKcv);
    }
    return HexUtil.parse(record.key);
  }

  /** Reports whether the plaintext key file of {@code iin} exists. */
  public static boolean exists(String producer, int iin) {
    return Files.exists(file(producer, iin), LinkOption.NOFOLLOW_LINKS);
  }

  /** Returns the KCV recorded in (and verified against) the key file of {@code iin}. */
  public static String kcv(String producer, int iin) throws IOException {
    return load(file(producer, iin), iin).kcv;
  }

  /**
   * Overwrites the key file of {@code iin} with zero bytes of its length, forces it to storage, and
   * deletes it.
   */
  public static void destroyFile(String producer, int iin) throws IOException {
    Path file = file(producer, iin);
    long length = Files.size(file);
    try (java.nio.channels.FileChannel channel =
        java.nio.channels.FileChannel.open(
            file, java.nio.file.StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
      java.nio.ByteBuffer zeros = java.nio.ByteBuffer.allocate((int) Math.min(length, 1 << 16));
      long written = 0;
      while (written < length) {
        zeros.clear();
        zeros.limit((int) Math.min(zeros.capacity(), length - written));
        written += channel.write(zeros, written);
      }
      channel.force(true);
    }
    Files.delete(file);
  }

  private static Record load(Path file, int iin) throws IOException {
    if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
      throw new IllegalStateException("IIN key file not found: " + file);
    }
    SecureFiles.requireOwnerOnly(file);
    byte[] json = Files.readAllBytes(file);
    Record record;
    try {
      record = GSON.fromJson(new String(json, StandardCharsets.UTF_8), Record.class);
    } finally {
      Arrays.fill(json, (byte) 0);
    }
    if (record == null || !SCHEMA.equals(record.schema) || record.iin != iin) {
      throw new IllegalStateException("not the key file of IIN " + iin + ": " + file);
    }
    byte[] key = HexUtil.parse(record.key);
    try {
      if (!HexUtil.format(OpidCipher.of(key).kcv()).equalsIgnoreCase(record.kcv)) {
        throw new IllegalStateException("IIN key file " + file + " fails its key check value");
      }
    } finally {
      Arrays.fill(key, (byte) 0);
    }
    return record;
  }
}
