package dev.mistial.tools.openfips201.provisioning;

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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Offline unit tests for native ICAM folder acceptance. Skips when the GSA ICAM card-builder tree
 * is not present on the machine (not checked into this repo).
 */
class IcamCardFolderTest {

  @TempDir Path temporaryDirectory;

  private static final Path ICAM_46 =
      Paths.get(
          System.getProperty(
              "openfips201.icam46",
              System.getProperty("user.home")
                  + "/Projects/gsa-icam-card-builder/cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV"));

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
