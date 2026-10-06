/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.attestation.AttestationVerifier;
import dev.mistial.tools.openfips201.attestation.F9SubjectNames;
import dev.mistial.tools.openfips201.attestation.StrictDer;
import dev.mistial.tools.openfips201.attestation.VerificationReport;
import dev.mistial.tools.openfips201.attestation.VerificationRequest;
import dev.mistial.tools.openfips201.opid.Opid;
import dev.mistial.tools.openfips201.producer.BatchMetadata;
import java.nio.file.Path;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

/**
 * The card's identity is the OPID the SAM allocates: on emulated card and SAM readers, in every
 * attestation build profile, the SAM certifies the card's on-card F9 key with the batch's next OPID
 * as subject serialNumber, the card serves exactly that certificate, and its attestation leaves
 * validate from the root.
 */
@Timeout(value = 120, unit = TimeUnit.SECONDS)
class OpenFIPS201CardstockInstanceIdTest {
  @TempDir Path rootHome;
  @TempDir Path productionHome;
  private String previousHome;
  private EmulatorBed bed;
  private final IssuanceTestKeys.LocalRoot root = new IssuanceTestKeys.LocalRoot();
  private final IssuanceTestKeys.LocalCustody custody =
      new IssuanceTestKeys.LocalCustody(root.rootCertificate());

  @BeforeEach
  void start() throws Exception {
    EmulatorBed.requireAttestationCap();
    previousHome = System.getProperty("openfips201.home");
    bed = EmulatorBed.start(SoftBatch.PRODUCER, rootHome, productionHome, 4711, 3);
    bed.bringUp(root, custody);
  }

  @AfterEach
  void stop() throws Exception {
    if (bed != null) {
      bed.close();
    }
    if (previousHome == null) {
      System.clearProperty("openfips201.home");
    } else {
      System.setProperty("openfips201.home", previousHome);
    }
  }

  @Test
  void cardIdentityIsTheSamAllocatedOpid() throws Exception {
    BatchMetadata batch = BatchMetadata.read(SoftBatch.PRODUCER, bed.batch);
    assertEquals(BatchMetadata.STATE_SAM_BOUND, batch.state);

    CardIssuanceOrchestrator.Result result =
        new IssuanceService().produce(bed.produceRequest(), custody);
    assertEquals(CardIssuanceOrchestrator.EXIT_OK, result.exitCode, failure(result));
    IssuanceReceipt receipt = result.record;

    Opid expected = Opid.parseCanonical(bed.rootOpids(root, 1).get(0));
    assertEquals(expected.toPrinted(), receipt.sam.opid);
    byte[] f9 = Base64.getDecoder().decode(receipt.f9.certificateBase64);
    assertEquals(
        expected,
        F9SubjectNames.extractOpid(
            X500Name.getInstance(
                StrictDer.parseCertificate(f9).getSubjectX500Principal().getEncoded())));
    assertTrue(receipt.f9.readBackIdentical, "the card serves the certificate it loaded");

    VerificationReport report =
        AttestationVerifier.verify(
            VerificationRequest.builder()
                .anchor(custody.rootCertificate())
                .samCertificate(IssuanceService.samCertificate(batch))
                .f9Certificate(f9)
                .leaf(Base64.getDecoder().decode(receipt.proof.leafBase64))
                .expectOpid(expected)
                .build());
    assertTrue(report.valid(), report.toTable());
    assertTrue(receipt.proof.keyDeleted);
    assertEquals(expected.toPrinted(), receipt.identifiers.opid);
    assertArrayEquals(
        dev.mistial.tools.openfips201.opid.OpidIdentifiers.fascNBytes(expected),
        dev.mistial.tools.openfips201.common.HexUtil.parse(receipt.identifiers.fascN));

    IssuanceLedger.Report ledger =
        new LedgerService()
            .verify(
                BatchMetadata.read(SoftBatch.PRODUCER, bed.batch),
                custody.rootCertificate(),
                bed.sam.target(),
                custody,
                EmulatorBed.OPERATOR_PIN,
                LedgerService.DEFAULT_DECIPHER_SAMPLE);
    assertTrue(ledger.valid(), ledger.problems.toString());
  }

  @Test
  void eachCardReceivesTheNextOpid() throws Exception {
    java.util.List<String> expected = bed.rootOpids(root, 2);
    for (int seq = 1; seq <= 2; seq++) {
      if (seq > 1) {
        bed.newCard();
      }
      CardIssuanceOrchestrator.Result result =
          new IssuanceService().produce(bed.produceRequest(), custody);
      assertEquals(0, result.exitCode, failure(result));
      assertEquals(expected.get(seq - 1), result.record.sam.opid);
    }
  }

  private static String failure(CardIssuanceOrchestrator.Result result) {
    return result.record.failure == null ? "" : result.record.failure.redactedMessage;
  }
}
