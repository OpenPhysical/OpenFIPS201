/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.OpenFips201Tool;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11AdminService;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11Session;
import dev.mistial.tools.openfips201.pkcs11.SoftHsmFixture;
import dev.mistial.tools.openfips201.producer.ProducerPaths;
import dev.mistial.tools.openfips201.producer.ProducerSetupService;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

/**
 * A production station refuses to start when its token holds the root CA key (by the root.pem key
 * identifier or by the root key label), an FF1 key ({@code *-fpe}), or when a batch record holds
 * LCG parameters.
 */
@Tag("softhsm")
class ProductionGuardSoftHsmTest {
  @TempDir Path temp;
  private String producer;
  private String lastError = "";

  @BeforeEach
  void setUpProductionStation() throws Exception {
    SoftHsmFixture.requireSoftHsm();
    producer = SoftHsmFixture.uniqueLabel("guard-");
    Path rootPem = temp.resolve("root.pem");
    Files.write(rootPem, EmulatorBed.pem(new IssuanceTestKeys.TestRoot().certificate()));
    ProducerSetupService.Request setup = new ProducerSetupService.Request();
    setup.name = producer;
    setup.station = ProducerSetupService.STATION_PRODUCTION;
    setup.module = SoftHsmFixture.module();
    setup.rootPem = rootPem;
    setup.devSoftHsm = true;
    setup.soPinOut = temp.resolve("so.pin");
    new ProducerSetupService().setup(setup);
  }

  private Pkcs11Session token() throws Exception {
    try (ProductionContext context = ProductionContext.load(producer)) {
      return Pkcs11Session.open(context.profile.cardKeys.pkcs11);
    }
  }

  private void requireClean() throws Exception {
    try (ProductionContext context = ProductionContext.load(producer)) {
      context.requireProductionClean(producer);
    }
  }

  private int stationInit() {
    CommandLine commandLine = new CommandLine(new OpenFips201Tool());
    ByteArrayOutputStream err = new ByteArrayOutputStream();
    commandLine.setErr(new PrintWriter(err, true));
    commandLine.setOut(new PrintWriter(new ByteArrayOutputStream(), true));
    commandLine.setExecutionExceptionHandler(
        (exception, parsed, result) -> {
          parsed.getErr().println("Error: " + exception);
          return 1;
        });
    Path out = temp.resolve("station-" + System.nanoTime() + ".pem");
    int exit =
        commandLine.execute("station", "init", "--producer", producer, "--out", out.toString());
    lastError = new String(err.toByteArray(), StandardCharsets.UTF_8);
    return exit;
  }

  private void assertRefused(String fragment) {
    IllegalStateException refused = assertThrows(IllegalStateException.class, this::requireClean);
    assertTrue(refused.getMessage().contains(fragment), refused.getMessage());
    assertEquals(1, stationInit());
    assertTrue(lastError.contains(fragment), lastError);
  }

  @Test
  void cleanProductionTokenStarts() throws Exception {
    requireClean();
    assertEquals(0, stationInit(), lastError);
  }

  @Test
  void ff1KeyOnTheProductionTokenIsRefused() throws Exception {
    try (Pkcs11Session session = token()) {
      new Pkcs11AdminService().ensureAes256Key(session, producer + "-iin-4321-fpe");
    }
    assertRefused("FF1 key");
  }

  @Test
  void rootKeyLabelOnTheProductionTokenIsRefused() throws Exception {
    try (Pkcs11Session session = token()) {
      new Pkcs11AdminService().ensureEcdhKey(session, producer + "-root-ca");
    }
    assertRefused("-root-ca");
  }

  @Test
  void keyMatchingTheRootCertificateIsRefused() throws Exception {
    byte[] point;
    try (Pkcs11Session session = token()) {
      point = new Pkcs11AdminService().ensureEcdhKey(session, "unrelated-label");
    }
    // A root.pem certifying the token key: the guard matches by subject key identifier.
    KeyPair signer = IssuanceTestKeys.p256();
    X500Name name = new X500Name("CN=Guard Root");
    long now = System.currentTimeMillis();
    byte[] der =
        new X509v3CertificateBuilder(
                name,
                BigInteger.ONE,
                new Date(now - 86_400_000L),
                new Date(now + 86_400_000L),
                name,
                SubjectPublicKeyInfo.getInstance(IssuanceCrypto.publicKey(point).getEncoded()))
            .build(new JcaContentSignerBuilder("SHA256withECDSA").build(signer.getPrivate()))
            .getEncoded();
    java.io.StringWriter text = new java.io.StringWriter();
    try (PemWriter writer = new PemWriter(text)) {
      writer.writeObject(new PemObject("CERTIFICATE", der));
    }
    Files.write(
        ProducerPaths.producer(producer).resolve("root.pem"),
        text.toString().getBytes(StandardCharsets.US_ASCII));
    assertRefused("root CA key");
  }

  @Test
  void batchRecordWithLcgParametersIsRefused() throws Exception {
    Path batch = ProducerPaths.producer(producer).resolve("batches").resolve("4321-0001");
    Files.createDirectories(batch);
    Files.write(
        batch.resolve("batch.json"),
        "{\"schema\":\"openfips201.batch/4\",\"lcg\":{\"a\":1,\"c\":1,\"x0\":1}}"
            .getBytes(StandardCharsets.UTF_8));
    assertRefused("LCG parameters");
  }
}
