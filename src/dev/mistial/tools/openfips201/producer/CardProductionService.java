/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.producer;

import com.google.gson.Gson;
import dev.mistial.tools.openfips201.cardstock.CardstockPreparationService;
import dev.mistial.tools.openfips201.cardstock.CardstockReceipt;
import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11SigningKey;
import dev.mistial.tools.openfips201.profiles.IssuerProfile;
import dev.mistial.tools.openfips201.profiles.ProfileLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class CardProductionService {
  private static final Gson GSON = new Gson();

  public Path produce(String producer, String batch, CardTarget target, String stockScpKey, boolean yes)
      throws Exception {
    Path profilePath = ProducerPaths.producerProfile(producer);
    Path batchPath = ProducerPaths.batch(producer, batch).resolve("batch.json");
    if (!Files.exists(profilePath)) {
      throw new IllegalArgumentException("Producer is not set up: " + producer);
    }
    if (!Files.exists(batchPath)) {
      throw new IllegalArgumentException("Batch does not exist: " + batch);
    }
    IssuerProfile profile = ProfileLoader.load(profilePath.toString());
    BatchMetadata metadata =
        GSON.fromJson(new String(Files.readAllBytes(batchPath), StandardCharsets.UTF_8), BatchMetadata.class);
    ScpConfig stockScp =
        ScpConfig.fromMaster(
            ScpConfig.Mode.SCP03, metadata.stockScpKeyVersion, HexUtil.parse(stockScpKey));
    Path receiptsDirectory = ProducerPaths.batch(producer, batch).resolve("receipts");
    Path receiptPath =
        new CardstockPreparationService()
            .prepare(
                target,
                profile,
                new Pkcs11SigningKey(profile.pkcs11),
                yes,
                batch,
                receiptsDirectory,
                stockScp,
                profilePath.toString(),
                stockScpKey);
    appendCsv(ProducerPaths.batch(producer, batch).resolve(metadata.receiptsCsv), receiptPath);
    return receiptPath;
  }

  private static void appendCsv(Path csv, Path receiptPath) throws Exception {
    BatchCreateService.ensureCsvHeader(csv);
    CardstockReceipt receipt =
        GSON.fromJson(new String(Files.readAllBytes(receiptPath), StandardCharsets.UTF_8), CardstockReceipt.class);
    String line =
        csv(receipt.timestamp)
            + ","
            + csv(receipt.profileName)
            + ","
            + csv(receipt.batchName)
            + ","
            + csv(receipt.target)
            + ","
            + csv("ok")
            + ","
            + csv(receipt.cplc)
            + ","
            + csv(receipt.cardKdd)
            + ","
            + receipt.newScpKeyVersion
            + ","
            + csv(receipt.newScpEncKcv)
            + ","
            + csv(receipt.newScpMacKcv)
            + ","
            + csv(receipt.newScpDekKcv)
            + ","
            + csv(receipt.rootSubject)
            + ","
            + csv(receipt.f9Subject)
            + ","
            + csv(receipt.f9IssuerCertificateSha256)
            + ","
            + csv(receipt.f9ProofSlot)
            + ","
            + receipt.proofKeyDeleted
            + "\n";
    Files.write(csv, line.getBytes(StandardCharsets.UTF_8), java.nio.file.StandardOpenOption.APPEND);
  }

  private static String csv(String value) {
    if (value == null) {
      value = "";
    }
    return "\"" + value.replace("\"", "\"\"") + "\"";
  }
}
