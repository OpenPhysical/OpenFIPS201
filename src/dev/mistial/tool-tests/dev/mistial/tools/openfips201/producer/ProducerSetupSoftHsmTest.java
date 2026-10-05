/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.producer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.SecureFiles;
import dev.mistial.tools.openfips201.crypto.KeyIdentifiers;
import dev.mistial.tools.openfips201.crypto.PemFiles;
import dev.mistial.tools.openfips201.crypto.SecretSource;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11AdminService;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11Config;
import dev.mistial.tools.openfips201.pkcs11.SoftHsmFixture;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** {@code producer setup --dev-softhsm}, {@code destroy} and root reissue against SoftHSM2. */
@Tag("softhsm")
class ProducerSetupSoftHsmTest {
  @TempDir Path temp;

  private String name;
  private final List<String> shownSoPins = new ArrayList<String>();

  @BeforeEach
  void useSoftHsmHome() throws Exception {
    SoftHsmFixture.requireSoftHsm();
    name = SoftHsmFixture.uniqueLabel("ps-");
  }

  @Test
  void setupTwiceKeepsThePinFileTokenAndRootKey() throws Exception {
    ProducerSetupService.Result first = new ProducerSetupService().setup(request());
    Path pinFile = ProducerPaths.producer(name).resolve("pkcs11.pin");
    byte[] pin = Files.readAllBytes(pinFile);
    assertTrue(first.tokenInitialized);
    assertEquals(ProducerSetupService.CUSTODY_SOFTHSM_DEV, first.custody);
    assertEquals(Pkcs11AdminService.RootSigner.Outcome.KEY_GENERATED, first.root.outcome);
    assertEquals("rw-------", mode(pinFile));
    assertEquals("rwx------", mode(ProducerPaths.producer(name)));
    assertEquals(1, shownSoPins.size());

    // An existing token needs no SO PIN destination.
    ProducerSetupService.Request rerun = request();
    rerun.soPinDisplay = null;
    ProducerSetupService.Result second = new ProducerSetupService().setup(rerun);

    assertFalse(second.tokenInitialized);
    assertEquals(1, shownSoPins.size());
    assertArrayEquals(pin, Files.readAllBytes(pinFile));
    assertTrue(Pkcs11AdminService.tokenExists(tokenConfig()));
    assertEquals(Pkcs11AdminService.RootSigner.Outcome.EXISTING, second.root.outcome);
    assertArrayEquals(first.root.certificate.getEncoded(), second.root.certificate.getEncoded());
    assertArrayEquals(first.root.keyId(), second.root.keyId());
    assertProducerRecordsRoot(second.root.certificate);
  }

  @Test
  void soAndUserPinsAreDistinctRandomHex() throws Exception {
    new ProducerSetupService().setup(request());
    String userPin =
        new String(
                Files.readAllBytes(ProducerPaths.producer(name).resolve("pkcs11.pin")),
                StandardCharsets.US_ASCII)
            .trim();
    String soPin = shownSoPins.get(0);

    assertTrue(userPin.matches("[0-9A-F]{32}"), userPin.length() + " characters");
    assertTrue(soPin.matches("[0-9A-F]{32}"), soPin.length() + " characters");
    assertNotEquals(userPin, soPin);
    String profile = new String(Files.readAllBytes(ProducerPaths.producerProfile(name)), "UTF-8");
    assertFalse(profile.contains(userPin));
    assertFalse(profile.contains(soPin));
  }

  @Test
  void soPinOutIsWrittenOwnerOnlyAndNeverInsideTheHome() throws Exception {
    ProducerSetupService.Request inside = request();
    inside.soPinOut = ProducerPaths.home().resolve("so.pin");
    assertThrows(IllegalArgumentException.class, () -> new ProducerSetupService().setup(inside));
    assertFalse(Pkcs11AdminService.tokenExists(tokenConfig()));

    ProducerSetupService.Request outside = request();
    outside.soPinOut = temp.resolve("so.pin");
    ProducerSetupService.Result result = new ProducerSetupService().setup(outside);

    assertEquals(outside.soPinOut, result.soPinFile);
    assertEquals("rw-------", mode(outside.soPinOut));
    assertTrue(shownSoPins.isEmpty());
    assertNotEquals(
        new String(Files.readAllBytes(outside.soPinOut), StandardCharsets.US_ASCII).trim(),
        new String(
                Files.readAllBytes(ProducerPaths.producer(name).resolve("pkcs11.pin")),
                StandardCharsets.US_ASCII)
            .trim());
  }

  @Test
  void existingTokenWithoutPinFileIsRefused() throws Exception {
    new ProducerSetupService().setup(request());
    Path pinFile = ProducerPaths.producer(name).resolve("pkcs11.pin");
    Path moved = temp.resolve("pkcs11.pin");
    Files.move(pinFile, moved);

    IllegalStateException refused =
        assertThrows(
            IllegalStateException.class, () -> new ProducerSetupService().setup(request()));

    assertTrue(refused.getMessage().contains("is missing"), refused.getMessage());
    assertFalse(Files.exists(pinFile));
    assertTrue(Pkcs11AdminService.tokenExists(tokenConfig()));
  }

  @Test
  void destroyNeedsTheTokenLabelAndSoPinThenAllowsAFreshSetup() throws Exception {
    ProducerSetupService.Result created = new ProducerSetupService().setup(request());
    Path soPin =
        SecureFiles.writeNew(
            temp.resolve("so.pin"), shownSoPins.get(0).getBytes(StandardCharsets.US_ASCII));
    Path wrongSoPin =
        SecureFiles.writeNew(
            temp.resolve("wrong.pin"), "00000000".getBytes(StandardCharsets.US_ASCII));

    assertThrows(
        IllegalArgumentException.class,
        () -> new ProducerSetupService().destroy(name, name + "x", source(soPin)));
    assertThrows(
        RuntimeException.class,
        () -> new ProducerSetupService().destroy(name, name, source(wrongSoPin)));
    assertTrue(Files.exists(ProducerPaths.producerProfile(name)));

    new ProducerSetupService().destroy(name, name, source(soPin));

    assertFalse(Pkcs11AdminService.tokenExists(tokenConfig()));
    assertFalse(Files.exists(ProducerPaths.producerProfile(name)));
    assertFalse(Files.exists(ProducerPaths.producer(name).resolve("pkcs11.pin")));
    assertFalse(Files.exists(ProducerPaths.producer(name).resolve("root.pem")));

    ProducerSetupService.Result recreated = new ProducerSetupService().setup(request());
    assertTrue(recreated.tokenInitialized);
    assertEquals(Pkcs11AdminService.RootSigner.Outcome.KEY_GENERATED, recreated.root.outcome);
    assertNotEquals(
        HexUtil.format(created.root.certificate.getPublicKey().getEncoded()),
        HexUtil.format(recreated.root.certificate.getPublicKey().getEncoded()));
  }

  @Test
  void reissueKeepsTheRootKeyAndRewritesRootPem() throws Exception {
    ProducerSetupService.Result created = new ProducerSetupService().setup(request());

    ProducerSetupService.Result reissued =
        new ProducerSetupService().reissueRootCertificate(name, 3650);

    assertEquals(Pkcs11AdminService.RootSigner.Outcome.CERTIFICATE_REISSUED, reissued.root.outcome);
    assertArrayEquals(
        created.root.certificate.getPublicKey().getEncoded(),
        reissued.root.certificate.getPublicKey().getEncoded());
    assertNotEquals(
        created.root.certificate.getSerialNumber(), reissued.root.certificate.getSerialNumber());
    assertProducerRecordsRoot(reissued.root.certificate);
    assertEquals(
        Pkcs11AdminService.RootSigner.Outcome.EXISTING,
        new ProducerSetupService().setup(request()).root.outcome);
  }

  private void assertProducerRecordsRoot(X509Certificate certificate) throws Exception {
    Path producer = ProducerPaths.producer(name);
    X509Certificate exported = PemFiles.readCertificate(producer.resolve("root.pem"));
    assertArrayEquals(certificate.getEncoded(), exported.getEncoded());
    JsonObject profile =
        JsonParser.parseString(
                new String(
                    Files.readAllBytes(ProducerPaths.producerProfile(name)),
                    StandardCharsets.UTF_8))
            .getAsJsonObject();
    assertEquals(ProducerSetupService.SCHEMA, profile.get("schema").getAsString());
    assertEquals("softhsm-dev", profile.get("custody").getAsString());
    JsonObject rootCa = profile.getAsJsonObject("rootCa");
    assertEquals(
        HexUtil.format(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded())),
        rootCa.get("certificateSha256").getAsString());
    assertEquals(
        HexUtil.format(KeyIdentifiers.ski(certificate.getPublicKey())),
        rootCa.get("ski").getAsString());
    assertNull(profile.getAsJsonObject("pkcs11").get("pinEnv"));
    assertEquals(
        producer.resolve("pkcs11.pin").toString(),
        profile.getAsJsonObject("pkcs11").get("pinFile").getAsString());
  }

  private ProducerSetupService.Request request() {
    ProducerSetupService.Request request = new ProducerSetupService.Request();
    request.name = name;
    request.module = SoftHsmFixture.module();
    request.rootSubject = "CN=" + name + " Root";
    request.f9Subject = "CN=" + name + " F9";
    request.devSoftHsm = true;
    request.soPinDisplay = soPin -> shownSoPins.add(new String(soPin));
    return request;
  }

  private Pkcs11Config tokenConfig() throws Exception {
    return SoftHsmFixture.config(name);
  }

  private static SecretSource source(Path file) {
    return SecretSource.of("--so-pin", null, null, file.toString());
  }

  private static String mode(Path path) throws Exception {
    return PosixFilePermissions.toString(Files.getPosixFilePermissions(path));
  }
}
