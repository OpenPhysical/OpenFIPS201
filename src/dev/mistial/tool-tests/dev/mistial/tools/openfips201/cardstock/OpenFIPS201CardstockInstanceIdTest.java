/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.cardstock;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import dev.mistial.tools.openfips201.attestation.F9InstanceId;
import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.crypto.PemSigningKey;
import dev.mistial.tools.openfips201.emulator.ZmqEmulatorFixture;
import dev.mistial.tools.openfips201.profiles.IssuerProfile;
import dev.mistial.tools.openfips201.profiles.ProfileLoader;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import pro.javacard.gp.keys.PlaintextKeys;

/**
 * Emulator cardstock prepare must mint a durable F9 instance id, embed it in the F9 cert/subject,
 * and prove the live INS F9 leaf issuer carries that id.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class OpenFIPS201CardstockInstanceIdTest {
  private ZmqEmulatorFixture fixture;
  private String endpoint;

  @BeforeEach
  void startServer() throws Exception {
    fixture = ZmqEmulatorFixture.start(PlaintextKeys.DEFAULT_KEY());
    endpoint = fixture.endpoint();
  }

  @AfterEach
  void stopServer() throws Exception {
    if (fixture != null) {
      fixture.close();
    }
  }

  @Test
  void cardstockPrepareRecordsInstanceIdAndMatchedProofLeaf(@TempDir Path tempDir)
      throws Exception {
    // ant test matrix rebuilds the emulator applet with and without attestation. F9 key
    // definition is rejected with 6A80 when ATTESTATION_ENABLED is false.
    Assumptions.assumeTrue(
        !"false".equalsIgnoreCase(System.getProperty("attestation.enabled", "true")),
        "cardstock F9 instance-id e2e requires -Dattestation.enabled=true");

    IssuerProfile profile = ProfileLoader.emulatorDev();
    profile.applet.capPath = System.getProperty("cap.path");
    profile.receipts.directory = tempDir.resolve("receipts").toString();
    profile.attestation.issuerSubject = "O=OpenPhysical,CN=Cardstock F9";
    profile.attestation.rootSubject = "O=OpenPhysical,CN=Cardstock Root";

    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair root = generator.generateKeyPair();
    PemSigningKey signer = new PemSigningKey(root.getPrivate(), root.getPublic(), "ephemeral");

    Path receiptPath =
        new CardstockPreparationService()
            .prepare(
                CardTarget.parse("zmq:" + endpoint),
                profile,
                signer,
                true,
                "test-batch",
                tempDir.resolve("receipts"));

    assertTrue(Files.exists(receiptPath), "receipt JSON must be written");
    CardstockReceipt receipt =
        new Gson()
            .fromJson(
                new String(Files.readAllBytes(receiptPath), StandardCharsets.UTF_8),
                CardstockReceipt.class);

    assertNotNull(receipt.instanceId, "instanceId");
    assertEquals(32, receipt.instanceId.length(), "instanceId length");
    assertTrue(receipt.instanceId.matches("[0-9A-F]{32}"), "instanceId hex: " + receipt.instanceId);
    assertEquals(receipt.instanceId, receipt.f9CertificateSerialHex, "serial hex");
    assertNotNull(receipt.f9SpkiSha256, "spki hash");
    assertEquals(64, receipt.f9SpkiSha256.length(), "spki hash length");
    assertNotNull(receipt.f9IssuerCertificateSha256, "cert hash");
    assertTrue(receipt.f9ProofIssuerMatched, "proof issuer matched");
    assertTrue(receipt.proofKeyDeleted, "proof key deleted");
    assertNotNull(receipt.f9CertificateBase64, "f9 cert base64");
    assertNotNull(receipt.f9ProofCertificateBase64, "proof leaf base64");

    dev.mistial.tools.openfips201.crypto.PemFiles.ensureProvider();
    X509Certificate f9 =
        F9InstanceId.parseCertificate(Base64.getDecoder().decode(receipt.f9CertificateBase64));
    F9InstanceId fromCert = F9InstanceId.extractFromCertificate(f9);
    assertEquals(receipt.instanceId, fromCert.toHex(), "cert extract");
    assertEquals(fromCert.toSerialNumber(), f9.getSerialNumber(), "cert serial");
    assertEquals(
        fromCert,
        F9InstanceId.fromSerialNumberRdn(
                org.bouncycastle.asn1.x500.X500Name.getInstance(
                    f9.getSubjectX500Principal().getEncoded()))
            .orElseThrow(() -> new AssertionError("subject missing serialNumber RDN")));

    byte[] proofLeaf = Base64.getDecoder().decode(receipt.f9ProofCertificateBase64);
    assertEquals(
        fromCert,
        F9InstanceId.extractFromLeafIssuer(proofLeaf)
            .orElseThrow(() -> new AssertionError("proof leaf missing serialNumber RDN")),
        "proof leaf instance id");
    assertTrue(F9InstanceId.subjectsMatch(f9, proofLeaf), "subjectsMatch");
    CardstockPreparationService.verifyProofMatchesF9Instance(f9, receipt.instanceId, proofLeaf);

    assertTrue(
        receipt.operationsPerformed.stream()
            .anyMatch(op -> op.contains("attestation proof issuer matches F9 instanceId")),
        "ops=" + receipt.operationsPerformed);

    ByteArrayOutputStream printed = new ByteArrayOutputStream();
    CardstockReceiptPrinter.printSummary(
        new PrintStream(printed, true, StandardCharsets.UTF_8.name()),
        "Cardstock prepared.",
        receipt,
        receiptPath);
    String summary = printed.toString(StandardCharsets.UTF_8.name());
    assertTrue(summary.contains(receipt.instanceId), "summary instance id");
    assertTrue(summary.contains("Proof issuer OK: true"), "summary proof ok");
    assertTrue(summary.contains(receiptPath.toString()), "summary path");
  }

  @Test
  void receiptPrinterRendersMissingFieldsSafely() {
    CardstockReceipt empty = new CardstockReceipt();
    ByteArrayOutputStream printed = new ByteArrayOutputStream();
    CardstockReceiptPrinter.printSummary(
        new PrintStream(printed, true), "Cardstock prepared.", empty, Paths.get("missing.json"));
    String summary = new String(printed.toByteArray(), StandardCharsets.UTF_8);
    assertTrue(summary.contains("(missing)"));
    assertTrue(summary.contains("Proof issuer OK: false"));
    assertFalse(summary.contains("null"));
  }
}
