/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.producer;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Producer custody rules that hold without a PKCS#11 module. */
class ProducerCustodyTest {
  /** Classes on the producer setup path; none may start a child process. */
  private static final String[] SETUP_PATH = {
    "dev.mistial.tools.openfips201.producer.ProducerSetupService",
    "dev.mistial.tools.openfips201.producer.ProducerSetupService$Request",
    "dev.mistial.tools.openfips201.producer.ProducerSetupService$Result",
    "dev.mistial.tools.openfips201.producer.ProducerPaths",
    "dev.mistial.tools.openfips201.pkcs11.Pkcs11AdminService",
    "dev.mistial.tools.openfips201.pkcs11.Pkcs11Session",
    "dev.mistial.tools.openfips201.pkcs11.Pkcs11Token",
    "dev.mistial.tools.openfips201.pkcs11.Pkcs11Config",
    "dev.mistial.tools.openfips201.common.SecureFiles",
    "dev.mistial.tools.openfips201.crypto.SecretSource"
  };

  @TempDir Path temp;
  private String previousHome;

  @BeforeEach
  void useTemporaryHome() {
    previousHome = System.getProperty("openfips201.home");
    System.setProperty("openfips201.home", temp.toString());
  }

  @AfterEach
  void restoreHome() {
    if (previousHome == null) {
      System.clearProperty("openfips201.home");
    } else {
      System.setProperty("openfips201.home", previousHome);
    }
  }

  @Test
  void setupPathNeverStartsAChildProcess() throws Exception {
    for (String className : SETUP_PATH) {
      String constants = classFileText(className);
      assertFalse(constants.contains("java/lang/ProcessBuilder"), className);
      assertFalse(constants.contains("java/lang/Process"), className);
      assertFalse(constants.contains("softhsm2-util"), className);
    }
  }

  @Test
  void hardwareCustodyRequiresAModule() {
    ProducerSetupService.Request request = new ProducerSetupService.Request();
    request.name = "hw";
    request.rootSubject = "CN=hw Root";

    IllegalArgumentException refused =
        assertThrows(
            IllegalArgumentException.class, () -> new ProducerSetupService().setup(request));

    assertTrue(refused.getMessage().contains("--dev-softhsm"), refused.getMessage());
    assertFalse(Files.exists(ProducerPaths.producerProfile("hw")));
  }

  @Test
  void devSoftHsmRefusesExternalPinSourcesAndHardwareRefusesSoPinOut() {
    ProducerSetupService.Request soft = new ProducerSetupService.Request();
    soft.name = "soft";
    soft.rootSubject = "CN=soft Root";
    soft.devSoftHsm = true;
    soft.pinEnv = "SOME_PIN";
    assertThrows(IllegalArgumentException.class, () -> new ProducerSetupService().setup(soft));

    ProducerSetupService.Request hardware = new ProducerSetupService.Request();
    hardware.name = "hw";
    hardware.rootSubject = "CN=hw Root";
    hardware.module = "/nonexistent/module.so";
    hardware.soPinOut = temp.resolve("so.pin");
    assertThrows(IllegalArgumentException.class, () -> new ProducerSetupService().setup(hardware));
  }

  @Test
  void destroyAndReissueRequireAnExistingProducer() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new ProducerSetupService().reissueRootCertificate("missing", 30));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new ProducerSetupService()
                .destroy(
                    "missing",
                    "missing",
                    dev.mistial.tools.openfips201.crypto.SecretSource.of(
                        "--so-pin", "x", null, null)));
  }

  private static String classFileText(String className) throws Exception {
    String resource = "/" + className.replace('.', '/') + ".class";
    try (InputStream in = ProducerCustodyTest.class.getResourceAsStream(resource)) {
      if (in == null) {
        throw new AssertionError("class file not found: " + resource);
      }
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      byte[] buffer = new byte[4096];
      for (int read = in.read(buffer); read > 0; read = in.read(buffer)) {
        out.write(buffer, 0, read);
      }
      return new String(out.toByteArray(), StandardCharsets.ISO_8859_1);
    }
  }
}
