/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import dev.mistial.tools.openfips201.attestation.OpenPhysicalExtensions;
import dev.mistial.tools.openfips201.attestation.StrictDer;
import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.CardTransport;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.producer.BatchMetadata;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * {@code ledger verify} and {@code ledger reconcile} at the production station. Nothing here
 * recomputes an OPID: the ledger's OPIDs are the SAM's, checked by signature, chain and DECIPHER.
 */
public final class LedgerService {
  /** Default number of issued OPIDs DECIPHER-checked by {@code ledger verify --sam}. */
  public static final int DEFAULT_DECIPHER_SAMPLE = 8;

  /**
   * Offline verification: {@link IssuanceLedger#verify} including the batch's receipt files against
   * their ledger bindings, the SAM certificate under {@code root} with its batch extension against
   * the batch record, and the batch's allocate and bind registry lines (root signatures, linkage,
   * bind line hash == the certificate's registryHead).
   */
  public IssuanceLedger.Report verify(BatchMetadata batch, X509Certificate root) throws Exception {
    byte[] samCertificate = IssuanceService.samCertificate(batch);
    PublicKey samKey = StrictDer.parseCertificate(samCertificate).getPublicKey();
    IssuanceLedger ledger = new IssuanceLedger(batch.directory().resolve(batch.ledger));
    IssuanceLedger.Report report =
        ledger.verify(
            samKey,
            samCertificate,
            HexUtil.parse(batch.paramsDigest),
            batch.quota.initial,
            batch.opid.iin,
            batch.directory().resolve("receipts"));
    try {
      SamCertificateFactory.requireValid(
          root, samCertificate, StrictDer.parseCertificate(samCertificate).getNotBefore());
      OpenPhysicalExtensions.SamBatch extension = SamReceiveService.samBatch(samCertificate);
      AllocationRegistry.verifyBinding(
          batch.registry.allocate, batch.registry.bind, root.getPublicKey(), batch.sam.samId);
      if (extension.issuerId != batch.opid.iin
          || extension.batch != batch.opid.batch
          || extension.allocationSeq != batch.registry.allocationSeq
          || !Arrays.equals(
              extension.registryHead(), AllocationRegistry.headAfter(batch.registry.bind))) {
        report.problems.add("the registry lines do not match the SAM certificate");
      }
    } catch (RuntimeException e) {
      report.problems.add("registry or SAM certificate: " + e.getMessage());
    }
    if (BatchMetadata.STATE_CLOSED.equals(batch.state) && !report.closed) {
      report.problems.add("batch.json is CLOSED but the ledger has no close line");
    }
    return report;
  }

  /**
   * {@link #verify(BatchMetadata, X509Certificate)}, then the live SAM: its signed STATUS must be
   * at the ledger's last entry (eventSeq, chain head and issued count), which is what detects a
   * truncated tail, and CLOSED exactly when the ledger is closed. With {@code custody} and {@code
   * operatorPin}, up to {@code sample} issued OPIDs are DECIPHERed and must come back as their
   * issuance numbers of this batch.
   */
  public IssuanceLedger.Report verify(
      BatchMetadata batch,
      X509Certificate root,
      CardTarget sam,
      Custody custody,
      byte[] operatorPin,
      int sample)
      throws Exception {
    IssuanceLedger.Report report = verify(batch, root);
    PublicKey samKey =
        StrictDer.parseCertificate(IssuanceService.samCertificate(batch)).getPublicKey();
    try (CardTransport transport = sam.openTransport()) {
      SamClient client = ApduSamClient.selectPlain(transport);
      if (report.terminated) {
        // A terminated SAM has no key to sign STATUS; its last entry (signed in the TERMINATE
        // response the ledger records) must be the ledger's last entry.
        SamLedgerEntry last = SamLedgerEntry.Signed.parse(client.lastEntry()).entry;
        if (report.lastEntry == null
            || !Arrays.equals(last.head(), report.lastEntry.entry.head())) {
          report.problems.add("the terminated SAM's last entry is not the ledger's last entry");
        }
        return report;
      }
      SamStatus status = new SamOperationsService().signedStatus(client, samKey);
      compare(report, status);
      if (report.closed != status.isClosed()) {
        report.problems.add(
            "the SAM is "
                + SamStatus.lifecycleName(status.lifecycle)
                + " but the ledger is "
                + (report.closed ? "closed" : "open"));
      }
      if (custody != null && operatorPin != null && sample > 0) {
        try (GlobalPlatformSession session = IssuanceService.openSam(transport, batch, custody)) {
          SamClient secure = ApduSamClient.secure(session);
          secure.verifyPin(operatorPin);
          for (Map.Entry<Long, String> issued : sample(report, sample)) {
            try {
              secure.decipher(issued.getValue()).requireIssuance(batch.opid.batch, issued.getKey());
              report.deciphered++;
            } catch (RuntimeException e) {
              report.problems.add(
                  "DECIPHER of issuance " + issued.getKey() + ": " + e.getMessage());
            }
          }
        }
      }
    }
    return report;
  }

  /** The first, the last and evenly spaced issued OPIDs, at most {@code count}. */
  static List<Map.Entry<Long, String>> sample(IssuanceLedger.Report report, int count) {
    List<Map.Entry<Long, String>> all =
        new ArrayList<Map.Entry<Long, String>>(report.opids.entrySet());
    if (all.size() <= count) {
      return all;
    }
    List<Map.Entry<Long, String>> picked = new ArrayList<Map.Entry<Long, String>>();
    for (int i = 0; i < count; i++) {
      picked.add(all.get((int) ((long) i * (all.size() - 1) / (count - 1))));
    }
    return picked;
  }

  /** Adds a live-comparison problem when the SAM is not at the ledger's last entry. */
  static void compare(IssuanceLedger.Report report, SamStatus status) {
    if (report.lastEntry == null) {
      return;
    }
    SamLedgerEntry last = report.lastEntry.entry;
    if (status.eventSeq != last.eventSeq || !Arrays.equals(status.chainHead(), last.head())) {
      report.problems.add(
          "the SAM is at event "
              + status.eventSeq
              + " but the ledger ends at event "
              + last.eventSeq
              + " (truncated or diverged ledger)");
    }
    if (status.issued != report.issued) {
      report.problems.add(
          "the SAM has issued " + status.issued + " but the ledger records " + report.issued);
    }
  }

  /** Recovers at most one SAM event missing from the ledger. */
  public LedgerReconciler.Outcome reconcile(BatchMetadata batch, CardTarget sam) throws Exception {
    byte[] samCertificate = IssuanceService.samCertificate(batch);
    PublicKey samKey = StrictDer.parseCertificate(samCertificate).getPublicKey();
    IssuanceLedger ledger = new IssuanceLedger(batch.directory().resolve(batch.ledger));
    try (BatchLock ignored = BatchLock.acquire(batch.directory());
        CardTransport transport = sam.openTransport()) {
      LedgerReconciler.Outcome outcome =
          LedgerReconciler.recover(
              ApduSamClient.selectPlain(transport),
              ledger,
              samKey,
              null,
              "ISSUE response lost; recovered with GET LAST ENTRY");
      if (outcome == LedgerReconciler.Outcome.RECOVERED_TOPUP) {
        SamLedgerEntry last = ledger.lastSamEntry().entry;
        batch.quota.authorizedTotal = last.quota;
        batch.quota.lastTopUpTs = last.timestamp;
        batch.replace();
      }
      return outcome;
    }
  }
}
