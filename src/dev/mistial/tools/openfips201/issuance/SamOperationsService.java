/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.producer.BatchMetadata;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * {@code sam status} and the production half of {@code sam top-up} (request out, authorization in)
 * against a SAM bound to a batch.
 */
public final class SamOperationsService {
  private static final long ONE_SECOND = 1000L;
  private final SecureRandom random = new SecureRandom();

  /** STATUS signed over a fresh 32-octet nonce and verified under {@code samKey}. */
  public SamStatus signedStatus(SamClient sam, PublicKey samKey) {
    byte[] nonce = new byte[32];
    random.nextBytes(nonce);
    return SamStatus.parseSigned(sam.signedStatus(nonce), nonce, samKey);
  }

  /**
   * A top-up request for {@code add} more issuances, carrying the SAM's STATUS signed over a fresh
   * nonce. Its timestamp is max(now, last accepted + 1 s), so the SAM's strict ordering accepts it.
   */
  public TopUpAuthorization request(
      BatchMetadata batch, SamClient sam, PublicKey samKey, long add) {
    requireBound(batch);
    byte[] nonce = new byte[32];
    random.nextBytes(nonce);
    byte[] response = sam.signedStatus(nonce);
    SamStatus status = SamStatus.parseSigned(response, nonce, samKey);
    if (!HexUtil.format(status.samSki()).equals(batch.sam.ski) || !status.isOperational()) {
      throw new IllegalStateException("The SAM is not the operational SAM of batch " + batch.name);
    }
    long last = Math.max(batch.quota.lastTopUpTs, status.lastTopUpTs);
    long timestamp = Math.max(System.currentTimeMillis(), last + ONE_SECOND);
    return TopUpAuthorization.request(
        batch.producer,
        batch.name,
        batch.opid.iin,
        batch.opid.batch,
        batch.sam.samId,
        HexUtil.parse(batch.sam.ski),
        timestamp,
        add,
        response,
        nonce);
  }

  /**
   * Sends a root-signed top-up. The authorization must name this batch and SAM and verify under
   * {@code rootKey}; the SAM's TOPUP entry must verify and extend the ledger. The ledger {@code
   * topup} line and {@code batch.json} are then updated, and the new quota confirmed with a signed
   * STATUS.
   *
   * @return the confirmed STATUS
   */
  public SamStatus topUp(
      BatchMetadata batch,
      SamClient sam,
      TopUpAuthorization authorization,
      PublicKey rootKey,
      PublicKey samKey)
      throws Exception {
    requireBound(batch);
    if (!TopUpAuthorization.AUTHORIZATION_SCHEMA.equals(authorization.schema)) {
      throw new IllegalArgumentException("the top-up is not signed; run 'root sign-top-up'");
    }
    if (!batch.producer.equals(authorization.producer)
        || !batch.name.equals(authorization.batch)
        || !batch.sam.samId.equals(authorization.samId)
        || !batch.sam.ski.equalsIgnoreCase(authorization.samSki)) {
      throw new IllegalArgumentException("the top-up authorization is for another batch or SAM");
    }
    if (!authorization.verifies(rootKey)) {
      throw new IllegalArgumentException("the top-up signature does not verify under the root");
    }
    if (authorization.timestamp <= batch.quota.lastTopUpTs) {
      throw new IllegalArgumentException(
          "the top-up authorization is not newer than the last applied top-up (replay)");
    }
    IssuanceLedger ledger = new IssuanceLedger(batch.directory().resolve(batch.ledger));
    try (BatchLock ignored = BatchLock.acquire(batch.directory())) {
      SamLedgerEntry.Signed last = ledger.lastSamEntry();
      SamLedgerEntry.Signed signed =
          SamLedgerEntry.Signed.parse(
              sam.topUp(
                  authorization.timestamp, authorization.add, authorization.signatureBytes()));
      SamLedgerEntry entry = signed.entry;
      if (!signed.verify(samKey)
          || entry.type != SamLedgerEntry.TYPE_TOPUP
          || entry.timestamp != authorization.timestamp
          || entry.added != authorization.add) {
        throw new IllegalStateException("the SAM's TOPUP entry does not match the authorization");
      }
      if (last == null
          || entry.eventSeq != last.entry.eventSeq + 1
          || !Arrays.equals(entry.prevHead(), last.entry.head())) {
        throw new IllegalStateException(
            "the TOPUP entry does not extend the ledger; run 'ledger reconcile'");
      }
      ledger.appendTopUp(signed);
      batch.quota.authorizedTotal = entry.quota;
      batch.quota.lastTopUpTs = entry.timestamp;
      batch.replace();
      SamStatus status = signedStatus(sam, samKey);
      if (status.quota != entry.quota || status.lastTopUpTs != entry.timestamp) {
        throw new IllegalStateException("the SAM's STATUS does not confirm the top-up");
      }
      return status;
    }
  }

  private static void requireBound(BatchMetadata batch) {
    if (!BatchMetadata.STATE_SAM_BOUND.equals(batch.state)) {
      throw new IllegalStateException("Batch " + batch.name + " is not bound to a SAM");
    }
  }
}
