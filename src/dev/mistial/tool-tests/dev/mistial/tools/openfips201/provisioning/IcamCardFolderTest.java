package dev.mistial.tools.openfips201.provisioning;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.interfaces.RSAPrivateKey;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Offline tests for the vendored GSA card-46 image. The system property override supports checking
 * another card-builder checkout without weakening the default CI coverage.
 */
class IcamCardFolderTest {

  @TempDir Path temporaryDirectory;

  private static final Path ICAM_ROOT =
      Paths.get("test-vectors/gsa-icam-card-builder/cards/ICAM_Card_Objects");
  private static final String[] VENDORED_POSITIVE_CARDS = {
    "01_Golden_PIV",
    "02_Golden_PIV-I",
    "37_Golden_FIPS_201-2_PIV_PPS_F=512_D=64",
    "39_Golden_FIPS_201-2_Fed_PIV-I",
    "46_Golden_FIPS_201-2_PIV",
    "47_Golden_FIPS_201-2_PIV_SAN_Order",
    "54_Golden_FIPS_201-2_NFI_PIV-I"
  };
  private static final String[] VENDORED_NEGATIVE_CARDS = {
    "03_SKID_Mismatch",
    "04_Tampered_CHUID",
    "06_Tampered_PHOTO",
    "07_Tampered_Fingerprints",
    "08_Tampered_Security_Object",
    "23_Public_Private_Key_mismatch",
    "38_Bad_Hash_in_Sec_Object",
    "55_FIPS_201-2_Missing_Security_Object"
  };

  private static final Path ICAM_46 =
      Paths.get(
          System.getProperty(
              "openfips201.icam46",
              "test-vectors/gsa-icam-card-builder/cards/ICAM_Card_Objects/"
                  + "46_Golden_FIPS_201-2_PIV"));

  @Test
  void loadsEveryVendoredPositiveGsaProfile() throws Exception {
    assumeTrue(Files.isDirectory(ICAM_ROOT), "vendored GSA corpus not present at " + ICAM_ROOT);
    for (String card : VENDORED_POSITIVE_CARDS) {
      Path path = ICAM_ROOT.resolve(card);
      assertTrue(Files.isDirectory(path), "missing vendored positive GSA card " + card);
      ConformancePackage pkg;
      try {
        pkg = IcamCardFolder.load(path);
      } catch (Exception e) {
        throw new AssertionError(card + " must pass the positive GSA profile preflight", e);
      }
      assertEquals(card, pkg.credentialId);
      assertTrue(pkg.dataObjects.size() >= 7, card + " must contain the core PIV objects");
      assertTrue(pkg.keys.size() >= 2, card + " must contain mandatory PIV keys");
    }
  }

  @Test
  void rejectsEveryVendoredNegativeGsaProfile() {
    assumeTrue(Files.isDirectory(ICAM_ROOT), "vendored GSA corpus not present at " + ICAM_ROOT);
    for (String card : VENDORED_NEGATIVE_CARDS) {
      Path path = ICAM_ROOT.resolve(card);
      assertTrue(Files.isDirectory(path), "missing vendored negative GSA card " + card);
      assertThrows(Exception.class, () -> IcamCardFolder.load(path), card + " must be rejected");
    }
  }

  @Test
  void card05SourceFolderRequiresRuntimeCertificateTampering() throws Exception {
    Path path = ICAM_ROOT.resolve("05_Tampered_Certificates");
    assumeTrue(Files.isDirectory(path), "vendored GSA card 05 not present at " + path);

    // GSA card 05's source folder contains valid signed certificate/key pairs. The two
    // ICAM_Test_Card certificate copies are byte-identical to their numbered counterparts, so the
    // negative condition exists only after the test harness tampers with an on-card certificate.
    assertArrayEquals(
        Files.readAllBytes(path.resolve("4 - ICAM_PIV_Dig_Sig_SP_800-73-4.crt")),
        Files.readAllBytes(
            path.resolve(
                "4 - ICAM_Test_Card_PIV_Dig_Sig_SP_800-73-4_Tampered_Certificates.crt")));
    assertArrayEquals(
        Files.readAllBytes(path.resolve("5 - ICAM_PIV_Key_Mgmt_SP_800-73-4.crt")),
        Files.readAllBytes(
            path.resolve(
                "5 - ICAM_Test_Card_PIV_Key_Mgmt_SP_800-73-4_Tampered_Certificates.crt")));
    assertDoesNotThrow(() -> IcamCardFolder.load(path));
  }

  @Test
  void loadsGoldenCard46Natively() throws Exception {
    assumeTrue(Files.isDirectory(ICAM_46), "ICAM card 46 not present at " + ICAM_46);

    ConformancePackage pkg = IcamCardFolder.load(ICAM_46);
    assertEquals("46_Golden_FIPS_201-2_PIV", pkg.credentialId);
    assertEquals(StandardCardProfile.PIN.length, pkg.pin.length);
    assertEquals(4, pkg.keys.size(), "PIV Auth, Dig Sig, Key Mgmt, Card Auth");
    // 7 binary containers + 4 cert containers
    assertEquals(11, pkg.dataObjects.size());

    boolean sawChuid = false;
    boolean sawDiscovery = false;
    for (ConformancePackage.DataObject object : pkg.dataObjects) {
      assertTrue(object.payload.length > 0, object.label + " payload must be non-empty");
      assertObjectAccess(object);
      if ("Cardholder Unique Identifier".equals(object.label)) {
        sawChuid = true;
        assertEquals(ConformancePackage.PutForm.TAG_LIST, object.putForm);
        assertEquals(0x5F, object.id[0] & 0xFF);
        assertEquals(0xC1, object.id[1] & 0xFF);
        assertEquals(0x02, object.id[2] & 0xFF);
      }
      if ("Discovery Object".equals(object.label)) {
        sawDiscovery = true;
        assertEquals(ConformancePackage.PutForm.DISCOVERY, object.putForm);
        assertEquals((byte) 0x7E, object.payload[0]);
      }
      if (object.label.contains("Certificate")) {
        // X.509 Certificate for PIV container: 70 <cert> 71 01 00 FE 00.
        assertEquals((byte) 0x70, object.payload[0], object.label + " must start with 70");
        assertEquals(
            (byte) 0xFE,
            object.payload[object.payload.length - 2],
            object.label + " must end with empty FE tag");
        assertEquals(
            0, object.payload[object.payload.length - 1] & 0xFF, object.label + " FE length must be 0");
      }
    }
    assertTrue(sawChuid, "CHUID must be present");
    assertTrue(sawDiscovery, "Discovery must be present");

    for (ConformancePackage.KeyMaterial key : pkg.keys) {
      assertNotNull(key.privateKey, key.label);
      assertNotNull(key.certificate, key.label);
      assertEquals(IcamCardFolder.ALG_RSA_2048, key.algorithm, key.label + " should be RSA-2048");
      assertTrue(key.privateKey instanceof RSAPrivateKey, key.label);
      assertEquals(IcamCardFolder.ATTR_IMPORTABLE, key.attributes);
      assertKeyAccess(key);
    }

    assertFalse(pkg.keys.isEmpty());
  }

  @Test
  void rejectsGoldenCardWithTamperedChuidSignature() throws Exception {
    assumeTrue(Files.isDirectory(ICAM_46), "ICAM card 46 not present at " + ICAM_46);
    ConformancePackage pkg = IcamCardFolder.load(ICAM_46);
    Map<String, ConformancePackage.DataObject> objects = index(pkg);
    ConformancePackage.DataObject chuid = objects.get("5FC102");
    byte[] tampered = chuid.payload.clone();
    tampered[tampered.length - 8] ^= 0x01;
    objects.put(
        "5FC102",
        new ConformancePackage.DataObject(
            chuid.id,
            chuid.label,
            chuid.modeContact,
            chuid.modeContactless,
            chuid.putForm,
            tampered));

    IllegalArgumentException failure =
        assertThrows(
            IllegalArgumentException.class,
            () -> CertificationProfileValidator.validateSecurityObject(objects));
    assertTrue(failure.getMessage().contains("CHUID CMS signature verification failed"));
  }

  @Test
  void rejectsGoldenCardWithTamperedSecurityObjectInputs() throws Exception {
    assumeTrue(Files.isDirectory(ICAM_46), "ICAM card 46 not present at " + ICAM_46);
    ConformancePackage pkg = IcamCardFolder.load(ICAM_46);
    for (String objectId : new String[] {"5FC103", "5FC108"}) {
      Map<String, ConformancePackage.DataObject> objects = index(pkg);
      replaceWithTamperedPayload(objects, objectId);

      IllegalArgumentException failure =
          assertThrows(
              IllegalArgumentException.class,
              () -> CertificationProfileValidator.validateSecurityObject(objects));
      assertTrue(
          failure.getMessage().contains("DG hash"),
          objectId + " tampering must be detected through the signed LDS hash");
    }
  }

  @Test
  void rejectsGoldenCardWithTamperedCertificateContainer() throws Exception {
    assumeTrue(Files.isDirectory(ICAM_46), "ICAM card 46 not present at " + ICAM_46);
    ConformancePackage pkg = IcamCardFolder.load(ICAM_46);
    Map<String, ConformancePackage.DataObject> objects = index(pkg);
    replaceWithTamperedPayload(objects, "5FC105");

    IllegalArgumentException failure =
        assertThrows(
            IllegalArgumentException.class,
            () -> CertificationProfileValidator.validateKeyBindings(pkg, objects));
    assertTrue(failure.getMessage().contains("does not match container"));
  }

  @Test
  void rejectsGoldenCardWithTamperedSecurityObjectCms() throws Exception {
    assumeTrue(Files.isDirectory(ICAM_46), "ICAM card 46 not present at " + ICAM_46);
    ConformancePackage pkg = IcamCardFolder.load(ICAM_46);
    Map<String, ConformancePackage.DataObject> objects = index(pkg);
    replaceWithTamperedPayload(objects, "5FC106");

    assertThrows(Exception.class, () -> CertificationProfileValidator.validateSecurityObject(objects));
  }

  @Test
  void certificationPreflightProvesKeyCertificateAndContainerBinding() throws Exception {
    assumeTrue(Files.isDirectory(ICAM_46), "ICAM card 46 not present at " + ICAM_46);
    ConformancePackage pkg = IcamCardFolder.load(ICAM_46);
    Map<String, ConformancePackage.DataObject> objects = index(pkg);
    assertDoesNotThrow(() -> CertificationProfileValidator.validateKeyBindings(pkg, objects));

    ConformancePackage.KeyMaterial original = pkg.keys.get(0);
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    ConformancePackage.KeyMaterial mismatched =
        new ConformancePackage.KeyMaterial(
            original.slot,
            original.label,
            original.algorithm,
            original.role,
            original.attributes,
            original.modeContact,
            original.modeContactless,
            generator.generateKeyPair().getPrivate(),
            original.certificate);
    ArrayList<ConformancePackage.KeyMaterial> wrongKeys =
        new ArrayList<ConformancePackage.KeyMaterial>(pkg.keys);
    wrongKeys.set(0, mismatched);
    ConformancePackage wrongKeyPackage =
        new ConformancePackage(
            pkg.credentialId,
            pkg.sourceDirectory,
            pkg.pin,
            pkg.puk,
            pkg.adminKeyAlg,
            pkg.adminKey,
            pkg.dataObjects,
            wrongKeys);
    IllegalArgumentException keyFailure =
        assertThrows(
            IllegalArgumentException.class,
            () -> CertificationProfileValidator.validateKeyBindings(wrongKeyPackage, objects));
    assertTrue(keyFailure.getMessage().contains("private key does not match"));

    Map<String, ConformancePackage.DataObject> wrongObjects = index(pkg);
    ConformancePackage.DataObject pivAuth = wrongObjects.get("5FC105");
    ConformancePackage.DataObject cardAuth = wrongObjects.get("5FC101");
    wrongObjects.put(
        "5FC105",
        new ConformancePackage.DataObject(
            pivAuth.id,
            pivAuth.label,
            pivAuth.modeContact,
            pivAuth.modeContactless,
            pivAuth.putForm,
            cardAuth.payload));
    IllegalArgumentException containerFailure =
        assertThrows(
            IllegalArgumentException.class,
            () -> CertificationProfileValidator.validateKeyBindings(pkg, wrongObjects));
    assertTrue(containerFailure.getMessage().contains("does not match container"));
  }

  private static Map<String, ConformancePackage.DataObject> index(ConformancePackage pkg) {
    Map<String, ConformancePackage.DataObject> result =
        new HashMap<String, ConformancePackage.DataObject>();
    for (ConformancePackage.DataObject object : pkg.dataObjects) {
      StringBuilder id = new StringBuilder();
      for (byte value : object.id) id.append(String.format("%02X", value & 0xFF));
      result.put(id.toString(), object);
    }
    return result;
  }

  private static void replaceWithTamperedPayload(
      Map<String, ConformancePackage.DataObject> objects, String objectId) {
    ConformancePackage.DataObject original = objects.get(objectId);
    assertNotNull(original, objectId);
    byte[] tampered = original.payload.clone();
    tampered[tampered.length / 2] ^= 0x01;
    objects.put(
        objectId,
        new ConformancePackage.DataObject(
            original.id,
            original.label,
            original.modeContact,
            original.modeContactless,
            original.putForm,
            tampered));
  }

  private static void assertObjectAccess(ConformancePackage.DataObject object) {
    byte vci = IcamCardFolder.ACCESS_VCI;
    byte pin = IcamCardFolder.ACCESS_PIN;
    if ("Security Object".equals(object.label)
        || "Card Capability Container".equals(object.label)
        || (object.label.contains("Certificate")
            && !"Card Authentication Certificate".equals(object.label))) {
      assertEquals(IcamCardFolder.ACCESS_ALWAYS, object.modeContact, object.label);
      assertEquals(vci, object.modeContactless, object.label);
    } else if ("Cardholder Fingerprints".equals(object.label)
        || "Cardholder Facial Image".equals(object.label)
        || "Printed Information".equals(object.label)) {
      assertEquals(pin, object.modeContact, object.label);
      assertEquals((byte) (vci | pin), object.modeContactless, object.label);
    } else {
      assertEquals(IcamCardFolder.ACCESS_ALWAYS, object.modeContact, object.label);
      assertEquals(IcamCardFolder.ACCESS_ALWAYS, object.modeContactless, object.label);
    }
  }

  private static void assertKeyAccess(ConformancePackage.KeyMaterial key) {
    byte expectedContact =
        "Digital Signature".equals(key.label)
            ? IcamCardFolder.ACCESS_PIN_ALWAYS
            : ("Card Authentication".equals(key.label)
                ? IcamCardFolder.ACCESS_ALWAYS
                : IcamCardFolder.ACCESS_PIN);
    byte expectedContactless =
        "Card Authentication".equals(key.label)
            ? IcamCardFolder.ACCESS_ALWAYS
            : (byte) (IcamCardFolder.ACCESS_VCI | expectedContact);
    assertEquals(expectedContact, key.modeContact, key.label);
    assertEquals(expectedContactless, key.modeContactless, key.label);
  }

  @Test
  void rejectsMissingDirectory() {
    Path missing = Paths.get("/tmp/openfips201-icam-does-not-exist-" + System.nanoTime());
    try {
      IcamCardFolder.load(missing);
      assertTrue(false, "expected IllegalArgumentException");
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("not a directory"));
    } catch (Exception other) {
      throw new AssertionError("expected IllegalArgumentException", other);
    }
  }

  @Test
  void rejectsFolderMissingRequiredObjects() {
    IllegalArgumentException failure =
        assertThrows(IllegalArgumentException.class, () -> IcamCardFolder.load(temporaryDirectory));
    assertTrue(failure.getMessage().contains("Missing required ICAM object"));
  }

  @Test
  void fileSelectionIsDeterministic() throws Exception {
    Path later = Files.write(temporaryDirectory.resolve("7 - CCC-z.bin"), new byte[] {2});
    Path earlier = Files.write(temporaryDirectory.resolve("7 - CCC-a.bin"), new byte[] {1});
    assertEquals(
        earlier,
        IcamCardFolder.findFile(temporaryDirectory, "7 - CCC", null, ""));
    assertTrue(Files.exists(later));
  }
}
