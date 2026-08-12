package dev.mistial.tools.openfips201.vci;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NativeVciProfileTest {
  private static final Path GSA_CARD_46 =
      Paths.get(
          "test-vectors/gsa-icam-card-builder/cards/ICAM_Card_Objects/"
              + "46_Golden_FIPS_201-2_PIV");

  @Test
  void buildsStrictCs2AndCs7ProfilesWithFreshIssuerIntegrity(@TempDir Path tempDir)
      throws Exception {
    for (byte suite : new byte[] {VciSupport.ALG_CS2, VciSupport.ALG_CS7}) {
      String prefix = tempDir.resolve(String.format("native-%02x", suite & 0xFF)).toString();
      NativeVciProfile.Material material =
          NativeVciProfile.build(GSA_CARD_46, prefix, "12345678", suite);

      assertEquals(13, material.profile.dataObjects.size());
      assertEquals(4, material.profile.keys.size());
      assertEquals(suite, material.suite);
      assertTrue(Files.isRegularFile(Paths.get(material.signerCertificatePath)));
      assertTrue(Files.isRegularFile(Paths.get(material.signerKeyPath)));
    }
  }
}
