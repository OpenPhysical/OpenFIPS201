package dev.mistial.tests.issuersam;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * End to end: for each parameter set the SAM issues the first 20 OPIDs exactly as the independent
 * reference computes them (LCG mod 10^8, FF1 over batch | x_n with tweak ASCII(IIN), Luhn), in the
 * certificate and in the ledger entry, and reports the reference paramsDigest v3.
 */
class IssuerSamFpeSequenceTest extends IssuerSamTestSupport {

  static JsonObject vectors() throws Exception {
    String directory = System.getProperty("openfips201.testVectors", "test-vectors");
    byte[] json = Files.readAllBytes(Paths.get(directory, "opid", "fpe.json"));
    JsonObject root =
        JsonParser.parseString(new String(json, StandardCharsets.UTF_8)).getAsJsonObject();
    assertEquals("openphysical.opid-vectors/2", root.get("schema").getAsString());
    return root;
  }

  static Params paramsFor(TestRoot root, JsonObject vector) {
    Params params = Params.variant(root, 0);
    params.issuerId = vector.get("iin").getAsInt();
    params.batch = Long.parseLong(vector.get("batch").getAsString());
    params.a = vector.get("a").getAsLong();
    params.c = vector.get("c").getAsLong();
    params.x0 = vector.get("x0").getAsLong();
    params.fpeKey = hex(vector.get("keyHex").getAsString());
    return params;
  }

  /** The SAM issues every vector sequence's first 20 OPIDs exactly. */
  @ParameterizedTest(name = "vector sequence {0}")
  @ValueSource(ints = {0, 1, 2, 3})
  void issuesTheVectorSequence(int index) throws Exception {
    JsonObject sequence = vectors().getAsJsonArray("sequences").get(index).getAsJsonObject();
    Params params = paramsFor(root, sequence);
    params.quota = 20;
    personalize(params);
    JsonArray issuances = sequence.getAsJsonArray("issuance");
    for (int i = 0; i < 20; i++) {
      JsonObject issuance = issuances.get(i).getAsJsonObject();
      assertEquals(i + 1, issuance.get("n").getAsInt());
      Issued issued = issueOne();
      assertEquals(
          issuance.get("opid").getAsString(),
          IssuerSamIssuanceTest.serialNumberOf(new X509CertificateHolder(issued.certificate)),
          "vector sequence " + index + " n = " + (i + 1));
    }
  }

  @ParameterizedTest(name = "parameter set {0}")
  @ValueSource(ints = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
  void issuesTheReferenceSequence(int variant) throws Exception {
    Params params = Params.variant(root, variant);
    params.quota = 20;
    personalize(params);
    withMockedScp(
        () ->
            assertArrayEquals(
                referenceParamsDigest(params),
                tlvValue(collect(transmit(0x84, 0xCA, 0x00, 0x04), "PARAMS"), 0x93),
                "paramsDigest v3"));
    OpidV2Reference reference = reference(params);
    for (int n = 1; n <= 20; n++) {
      Issued issued = issueOne();
      String expected = reference.opidAt(n);
      assertEquals(17, expected.length());
      String opid =
          IssuerSamIssuanceTest.serialNumberOf(new X509CertificateHolder(issued.certificate));
      assertEquals(expected, opid, "parameter set " + variant + " issuance " + n);
      assertEquals(17, issued.entry[69]);
      assertEquals(
          expected,
          new String(Arrays.copyOfRange(issued.entry, 70, 87), StandardCharsets.US_ASCII));
    }
  }
}
