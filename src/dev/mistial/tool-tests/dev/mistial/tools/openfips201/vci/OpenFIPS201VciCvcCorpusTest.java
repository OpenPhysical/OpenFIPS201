package dev.mistial.tools.openfips201.vci;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * Structural known-answer tests for real-card secure messaging CVCs from the local {@code
 * vci-cvc-corpus} (NIST SD33 captures).
 *
 * <p>These fixtures preserve the exact {@code 7F21} bytes from OPACITY establishment. They are a
 * parsing/interoperability corpus: not every entry has the content-signing material needed for full
 * trust-anchor validation (see {@link OpenFIPS201VciTrustAnchorTest}).
 *
 * <p>Aligned with NIST SP 800-73-5 Part 2 Section 4.1.5 (Secure Messaging CVC format).
 */
class OpenFIPS201VciCvcCorpusTest {

  @TestFactory
  Stream<DynamicTest> cvcStructureMatchesMetadata() throws Exception {
    List<Path> entries = listCorpusEntries();
    assertTrue(entries.size() >= 19, "expected full CVC corpus, found " + entries.size());
    return entries.stream()
        .map(
            dir ->
                DynamicTest.dynamicTest(
                    dir.getFileName().toString(),
                    () -> {
                      byte[] cvc = Files.readAllBytes(dir.resolve("secure-messaging-cvc-7f21.bin"));
                      JsonObject meta =
                          JsonParser.parseString(
                                  new String(
                                      Files.readAllBytes(dir.resolve("metadata.json")),
                                      StandardCharsets.UTF_8))
                              .getAsJsonObject();
                      JsonObject secure = meta.getAsJsonObject("secure_cvc");

                      VciCvcSupport.ParsedCvc parsed = VciCvcSupport.parseCvc(cvc);
                      assertEquals(
                          secure.get("length").getAsInt(), parsed.raw.length, "CVC length");
                      assertEquals(
                          secure.get("iin").getAsString().toUpperCase(),
                          VciCvcSupport.toHex(parsed.iin),
                          "IIN (tag 42)");
                      assertEquals(
                          secure.get("subject_identifier").getAsString().toUpperCase(),
                          VciCvcSupport.toHex(parsed.subjectIdentifier),
                          "subject identifier (5F20)");
                      assertEquals(
                          secure.get("role").getAsString().toUpperCase(),
                          VciCvcSupport.toHex(parsed.role),
                          "role (5F4C)");
                      assertEquals(
                          secure.get("public_key_curve_oid").getAsString(),
                          parsed.publicKeyCurveOid,
                          "curve OID");
                      assertEquals(
                          secure.get("signature_algorithm_oid").getAsString(),
                          parsed.signatureAlgorithmOid,
                          "signature algorithm OID");

                      // Role is key establishment (0x00) on production SM CVCs.
                      assertEquals(1, parsed.role.length);
                      assertEquals(0x00, parsed.role[0] & 0xFF);

                      // Profile identifier 0x80 per SM CVC profile.
                      assertTrue(parsed.profile.length >= 1);
                      assertEquals(0x80, parsed.profile[0] & 0xFF);

                      // idSicc = SHA-256(CVC)[0:8] is well-defined for any CVC bytes.
                      byte[] idSicc = VciSupport.computeIdSicc(cvc);
                      assertEquals(8, idSicc.length);
                      assertFalse(allZero(idSicc), "idSicc should not be all zeros");

                      // Public point is uncompressed 04||X||Y with suite-appropriate length.
                      byte[] point = VciSupport.extractCardPublicPoint(cvc);
                      assertEquals(0x04, point[0] & 0xFF);
                      if (VciCvcSupport.OID_EC_P256.equals(parsed.publicKeyCurveOid)) {
                        assertEquals(65, point.length, "P-256 uncompressed point");
                      } else if (VciCvcSupport.OID_EC_P384.equals(parsed.publicKeyCurveOid)) {
                        assertEquals(97, point.length, "P-384 uncompressed point");
                      }

                      // Cross-check that recomputed idSicc from the same bytes is stable.
                      assertArrayEquals(idSicc, VciSupport.computeIdSicc(parsed.raw));
                    }));
  }

  private static List<Path> listCorpusEntries() throws Exception {
    Path root = corpusRoot();
    try (Stream<Path> stream = Files.list(root)) {
      return stream
          .filter(Files::isDirectory)
          .filter(p -> Files.isRegularFile(p.resolve("secure-messaging-cvc-7f21.bin")))
          .sorted()
          .collect(Collectors.toList());
    }
  }

  private static Path corpusRoot() {
    Path relative =
        Paths.get(
            "src/dev/mistial/tool-tests/dev/mistial/tools/openfips201/vci/vectors/cvc-corpus");
    if (Files.isDirectory(relative)) {
      return relative;
    }
    Path here = Paths.get("").toAbsolutePath();
    while (here != null && !Files.isDirectory(here.resolve(relative))) {
      here = here.getParent();
    }
    if (here == null) {
      throw new IllegalStateException("Could not locate cvc-corpus directory");
    }
    return here.resolve(relative);
  }

  private static boolean allZero(byte[] data) {
    for (byte b : data) {
      if (b != 0) {
        return false;
      }
    }
    return true;
  }
}
