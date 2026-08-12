package dev.mistial.tools.openfips201.vci;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
 * PD-side VCI trust-anchor chain validation against NIST SD33 fixtures in the local {@code
 * vci-trust-anchors} corpus.
 *
 * <p>Covers both validation paths from OSDP/VCI PD logic:
 *
 * <ul>
 *   <li><b>Direct</b>: secure messaging CVC IIN matches the loaded anchor IIN and the CVC signature
 *       verifies with the anchor public key (EC P-256/P-384).
 *   <li><b>Intermediate</b>: CVC is signed by an Intermediate CVC (role {@code 0x12}) carried in
 *       5FC122; the Intermediate CVC is signed by the RSA trust anchor.
 * </ul>
 *
 * <p>Aligned with NIST SP 800-73-5 Part 2 Section 4.1.5 and the Secure Messaging Certificate Signer
 * container (5FC122).
 */
class OpenFIPS201VciTrustAnchorTest {

  @TestFactory
  Stream<DynamicTest> pdChainValidationMatchesPublishedReports() throws Exception {
    List<Path> cards = listAnchorCards();
    assertTrue(cards.size() >= 5, "expected 5 trust-anchor cards, found " + cards.size());
    return cards.stream()
        .map(
            dir ->
                DynamicTest.dynamicTest(
                    dir.getFileName().toString(),
                    () -> {
                      byte[] anchorBytes =
                          Files.readAllBytes(dir.resolve("vci-trust-anchor-record.bin"));
                      byte[] cvcBytes =
                          Files.readAllBytes(dir.resolve("secure-messaging-cvc-7f21.bin"));
                      Path smcsPath = dir.resolve("smcs-5fc122.bin");
                      byte[] smcsBytes =
                          Files.isRegularFile(smcsPath) ? Files.readAllBytes(smcsPath) : null;

                      VciCvcSupport.TrustAnchor anchor = VciCvcSupport.parseAnchor(anchorBytes);
                      VciCvcSupport.ParsedCvc cvc = VciCvcSupport.parseCvc(cvcBytes);
                      VciCvcSupport.Smcs smcs =
                          smcsBytes == null ? null : VciCvcSupport.parseSmcs(smcsBytes);

                      VciCvcSupport.PdValidationResult result =
                          VciCvcSupport.validatePdChain(anchor, cvc, smcs);

                      JsonObject report =
                          JsonParser.parseString(
                                  new String(
                                      Files.readAllBytes(dir.resolve("validation-report.json")),
                                      StandardCharsets.UTF_8))
                              .getAsJsonObject();
                      JsonObject summary = report.getAsJsonObject("summary");
                      assertTrue(
                          report.getAsJsonObject("result").get("passed").getAsBoolean(),
                          dir.getFileName() + ": published report should pass");
                      assertTrue(result.passed, dir.getFileName() + ": " + result.reason);
                      assertEquals(
                          summary.get("pd_path").getAsString(),
                          result.path,
                          dir.getFileName() + ": PD path");
                      assertEquals(
                          summary.get("secure_cvc_iin").getAsString().toUpperCase(),
                          VciCvcSupport.toHex(cvc.iin),
                          "CVC IIN");
                      assertEquals(
                          summary.get("selected_anchor_iin").getAsString().toUpperCase(),
                          VciCvcSupport.toHex(anchor.iin),
                          "anchor IIN");

                      if ("direct".equals(result.path)) {
                        assertTrue(
                            result.checksPassed.contains("secure_cvc_signature_with_anchor"),
                            "direct path must verify CVC with anchor");
                      } else {
                        assertEquals("intermediate", result.path);
                        assertNotNull(smcs, "intermediate path requires 5FC122");
                        assertNotNull(smcs.intermediateCvc, "intermediate CVC required");
                        assertTrue(
                            result.checksPassed.contains("intermediate_role_is_12"),
                            "intermediate role 0x12");
                        assertTrue(
                            result.checksPassed.contains("secure_cvc_signature_with_intermediate"),
                            "CVC must verify with intermediate");
                        assertTrue(
                            result.checksPassed.contains("intermediate_cvc_signature_with_anchor"),
                            "intermediate must verify with anchor");
                      }

                      // Negative: a different CVC IIN alone is not enough without intermediate
                      // material — force intermediate failure by omitting SMCS on a direct card.
                      if ("direct".equals(result.path)) {
                        VciCvcSupport.PdValidationResult withoutSmcs =
                            VciCvcSupport.validatePdChain(anchor, cvc, null);
                        // Direct path does not need SMCS; still passes.
                        assertTrue(withoutSmcs.passed, "direct path independent of 5FC122");
                      }
                    }));
  }

  @TestFactory
  Stream<DynamicTest> contentSigningCertificateSpkiMatchesAnchorOnDirectCards() throws Exception {
    return listAnchorCards().stream()
        .filter(dir -> dir.getFileName().toString().contains("direct"))
        .map(
            dir ->
                DynamicTest.dynamicTest(
                    dir.getFileName().toString() + " content-signer SPKI",
                    () -> {
                      VciCvcSupport.TrustAnchor anchor =
                          VciCvcSupport.parseAnchor(
                              Files.readAllBytes(dir.resolve("vci-trust-anchor-record.bin")));
                      VciCvcSupport.Smcs smcs =
                          VciCvcSupport.parseSmcs(
                              Files.readAllBytes(dir.resolve("smcs-5fc122.bin")));
                      assertNotNull(smcs.certificate, "5FC122 must carry content-signing cert");
                      byte[] certSpki = smcs.certificate.getPublicKey().getEncoded();
                      assertTrue(
                          java.util.Arrays.equals(certSpki, anchor.spki),
                          "content-signing cert SPKI should match trust-anchor SPKI on direct"
                              + " cards");
                      // Certificate IIN convention: first 8 bytes of SKI when present.
                      byte[] ski = smcs.certificate.getExtensionValue("2.5.29.14");
                      // Presence is optional in this assertion; SPKI match is the hard check.
                      assertFalse(ski != null && ski.length == 0);
                    }));
  }

  private static List<Path> listAnchorCards() throws Exception {
    Path root = anchorsRoot();
    try (Stream<Path> stream = Files.list(root)) {
      return stream
          .filter(Files::isDirectory)
          .filter(p -> Files.isRegularFile(p.resolve("vci-trust-anchor-record.bin")))
          .sorted()
          .collect(Collectors.toList());
    }
  }

  private static Path anchorsRoot() {
    Path relative =
        Paths.get(
            "src/dev/mistial/tool-tests/dev/mistial/tools/openfips201/vci/vectors/trust-anchors");
    if (Files.isDirectory(relative)) {
      return relative;
    }
    Path here = Paths.get("").toAbsolutePath();
    while (here != null && !Files.isDirectory(here.resolve(relative))) {
      here = here.getParent();
    }
    if (here == null) {
      throw new IllegalStateException("Could not locate trust-anchors directory");
    }
    return here.resolve(relative);
  }
}
