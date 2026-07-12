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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public final class BatchCreateService {
  private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
  private static final int STOCK_SCP_KEY_VERSION = 1;

  public Result create(String producer, String name) throws Exception {
    if (!Files.exists(ProducerPaths.producerProfile(producer))) {
      throw new IllegalArgumentException("Producer is not set up: " + producer);
    }
    Path directory = ProducerPaths.batch(producer, name);
    Files.createDirectories(directory.resolve("receipts"));
    byte[] stockKey = new byte[16];
    new SecureRandom().nextBytes(stockKey);
    BatchMetadata metadata = new BatchMetadata();
    metadata.producer = producer;
    metadata.name = name;
    metadata.created = Instant.now().toString();
    metadata.stockScpMode = "scp03";
    metadata.stockScpKeyVersion = STOCK_SCP_KEY_VERSION;
    metadata.stockScpKcv = kcv(stockKey);
    metadata.receiptsCsv = "receipts.csv";
    Files.write(
        directory.resolve("batch.json"),
        GSON.toJson(metadata).getBytes(StandardCharsets.UTF_8));
    ensureCsvHeader(directory.resolve(metadata.receiptsCsv));
    return new Result(HexUtil.format(stockKey), metadata.stockScpKcv, directory);
  }

  static void ensureCsvHeader(Path csv) throws Exception {
    if (Files.exists(csv)) {
      return;
    }
    Files.write(
        csv,
        ("timestamp,producer,batch,target,status,cplc,kdd,new_key_version,enc_kcv,mac_kcv,dek_kcv,"
                + "root_subject,instance_id,f9_subject,f9_serial_hex,f9_spki_sha256,f9_cert_sha256,"
                + "proof_slot,proof_key_deleted,proof_issuer_matched\n")
            .getBytes(StandardCharsets.UTF_8));
  }

  private static String kcv(byte[] key) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
    return HexUtil.format(Arrays.copyOf(cipher.doFinal(new byte[16]), 3));
  }

  public static final class Result {
    public final String stockScpKey;
    public final String stockScpKcv;
    public final Path directory;

    Result(String stockScpKey, String stockScpKcv, Path directory) {
      this.stockScpKey = stockScpKey;
      this.stockScpKcv = stockScpKcv;
      this.directory = directory;
    }
  }
}
