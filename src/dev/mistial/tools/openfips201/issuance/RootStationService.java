/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import com.google.gson.JsonObject;
import dev.mistial.tools.openfips201.attestation.StrictDer;
import dev.mistial.tools.openfips201.common.HexUtil;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;

/**
 * Root-station operations that need neither a SAM nor a card: the allocation registry, top-up
 * signing and the OPID audit of a production ledger.
 */
public final class RootStationService {
  /** {@code root init}: creates the allocation registry and its token head. */
  public AllocationRegistry init(String producer, RootKeys keys) throws Exception {
    return AllocationRegistry.create(producer, keys);
  }

  /** {@code root allocate}: records an (IIN, batch) allocation with its initial quota. */
  public JsonObject allocate(String producer, RootKeys keys, int iin, int batch, long quota)
      throws Exception {
    return AllocationRegistry.open(producer, keys).allocate(iin, batch, quota);
  }

  /**
   * {@code root sign-top-up}: the request must name a batch bound in the registry to its SAM, carry
   * that SAM's STATUS signed under its certificate (OPERATIONAL, the batch's IIN and batch number,
   * an earlier last top-up), and a timestamp later than every top-up already authorized for the
   * batch. The authorization is recorded as a registry {@code topup} line before it is returned.
   */
  public TopUpAuthorization signTopUp(String producer, RootKeys keys, TopUpAuthorization request)
      throws Exception {
    if (!TopUpAuthorization.REQUEST_SCHEMA.equals(request.schema)) {
      throw new IllegalArgumentException("not a top-up request: " + request.schema);
    }
    if (!producer.equals(request.producer)) {
      throw new IllegalArgumentException("the request is for producer " + request.producer);
    }
    AllocationRegistry registry = AllocationRegistry.open(producer, keys);
    JsonObject binding = registry.binding(request.iin, request.batchNumber);
    if (binding == null || !binding.get("samId").getAsString().equals(request.samId)) {
      throw new IllegalArgumentException("the request names a SAM that is not bound to the batch");
    }
    RootBatchRecord.SamFile sam =
        RootBatchRecord.readSam(producer, request.iin, request.batchNumber);
    if (sam == null || !sam.samId.equals(request.samId)) {
      throw new IllegalStateException("no SAM record for the bound SAM of this batch");
    }
    if (!sam.samSki.equalsIgnoreCase(request.samSki)) {
      throw new IllegalArgumentException("the request names a different SAM key");
    }
    PublicKey samKey =
        StrictDer.parseCertificate(Base64.getDecoder().decode(sam.certificate)).getPublicKey();
    SamStatus status = request.verifiedStatus(samKey);
    if (!HexUtil.format(status.samSki()).equalsIgnoreCase(sam.samSki)
        || !status.isOperational()
        || !String.format(Locale.ROOT, "%04d", request.iin).equals(status.iin)
        || !String.format(Locale.ROOT, "%04d", request.batchNumber).equals(status.batch)) {
      throw new IllegalArgumentException(
          "the SAM STATUS in the request is not that of the operational batch SAM");
    }
    if (request.timestamp <= status.lastTopUpTs) {
      throw new IllegalArgumentException(
          "the request timestamp is not later than the SAM's last top-up");
    }
    registry.topUp(request.iin, request.batchNumber, request.samId, request.timestamp, request.add);
    return request.sign(keys.rootSigner());
  }

  /**
   * {@code root audit-ledger}: verifies an exported production ledger ({@link
   * IssuanceLedger#verify}) and replays every issued OPID with {@link
   * dev.mistial.tools.openfips201.opid.OpidSequence#opidAt} from the root's LCG record and the IIN
   * FF1 key on the root token.
   */
  public IssuanceLedger.Report auditLedger(
      String producer, RootKeys keys, Path ledgerFile, int iin, int batch) throws Exception {
    RootBatchRecord.SamFile sam = RootBatchRecord.readSam(producer, iin, batch);
    if (sam == null) {
      throw new IllegalArgumentException(
          String.format(Locale.ROOT, "IIN %04d batch %04d has no bound SAM", iin, batch));
    }
    RootBatchRecord.LcgFile lcg = RootBatchRecord.readLcg(producer, iin, batch, sam.samId);
    if (lcg == null) {
      throw new IllegalStateException("no LCG record for the bound SAM of this batch");
    }
    byte[] samCertificate = Base64.getDecoder().decode(sam.certificate);
    PublicKey samKey = StrictDer.parseCertificate(samCertificate).getPublicKey();
    IssuanceLedger.Report report =
        new IssuanceLedger(ledgerFile)
            .verify(samKey, samCertificate, HexUtil.parse(lcg.paramsDigest), lcg.quota, iin);
    BatchLcgAuditor auditor = BatchLcgAuditor.of(lcg, keys.iinCipher(iin));
    for (Map.Entry<Long, String> issued : report.opids.entrySet()) {
      try {
        auditor.require(issued.getKey(), issued.getValue());
        report.audited++;
      } catch (RuntimeException e) {
        report.problems.add("issuance " + issued.getKey() + ": " + e.getMessage());
      }
    }
    return report;
  }

  /** Parses a batch name {@code IIII-NNNN} into {IIN, batch}. */
  public static int[] parseBatchName(String name) {
    if (name == null || !name.matches("[0-9]{4}-[0-9]{4}")) {
      throw new IllegalArgumentException("batch must be IIII-NNNN: " + name);
    }
    return new int[] {Integer.parseInt(name.substring(0, 4)), Integer.parseInt(name.substring(5))};
  }
}
