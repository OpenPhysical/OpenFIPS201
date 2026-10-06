package dev.mistial.tests.issuersam;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.Test;

/**
 * DECIPHER ({@code 84 2C 00 00}, data {@code 80 11 <17 ASCII digits>}): reverses an OPID of this
 * IIN to its batch and, for this SAM's batch, to the issuance count n with x_n = X.
 */
class IssuerSamDecipherTest extends IssuerSamTestSupport {

  private ResponseAPDU decipherRaw(String opid) {
    return transmit(0x84, 0x2C, 0x00, 0x00, tlv(0x80, opid.getBytes(StandardCharsets.US_ASCII)));
  }

  private byte[] decipher(String opid) {
    return withMockedScp(
        () -> {
          assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY");
          return collect(decipherRaw(opid), "DECIPHER " + opid);
        });
  }

  private static String withLuhn(String sixteen) {
    return sixteen + OpidV2Reference.luhn(sixteen);
  }

  @Test
  void reproducesTheDecipherVectorSet() throws Exception {
    JsonObject set = IssuerSamFpeSequenceTest.vectors().getAsJsonObject("decipher");
    Params params = IssuerSamFpeSequenceTest.paramsFor(root, set);
    int issued = set.get("issued").getAsInt();
    params.quota = issued;
    personalize(params);
    for (int n = 0; n < issued; n++) issueOne();
    for (JsonElement element : set.getAsJsonArray("cases")) {
      JsonObject vector = element.getAsJsonObject();
      String opid = vector.get("opid").getAsString();
      byte[] expected =
          concat(
              hex("8104"),
              vector.get("batch").getAsString().getBytes(StandardCharsets.US_ASCII),
              hex("8201"),
              new byte[] {(byte) (vector.get("sameBatch").getAsBoolean() ? 1 : 0)});
      if (vector.get("sameBatch").getAsBoolean()) {
        expected =
            concat(
                expected,
                hex("8304"),
                u32(vector.get("count").getAsLong()),
                hex("8401"),
                new byte[] {(byte) (vector.get("issuedFlag").getAsBoolean() ? 1 : 0)});
      }
      assertArrayEquals(expected, decipher(opid), vector.get("note").getAsString());
    }
    for (JsonElement element : set.getAsJsonArray("rejected")) {
      JsonObject vector = element.getAsJsonObject();
      int sw = Integer.parseInt(vector.get("sw").getAsString(), 16);
      withMockedScp(
          () -> {
            assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY");
            assertSw(sw, decipherRaw(vector.get("opid").getAsString()), vector.toString());
          });
    }
  }

  @Test
  void everyIssuedOpidRoundTripsToBatchAndCount() throws Exception {
    Params params = Params.variant(root, 1);
    params.quota = 12;
    personalize(params);
    List<String> opids = new ArrayList<>();
    for (int n = 0; n < 12; n++) {
      opids.add(
          IssuerSamIssuanceTest.serialNumberOf(new X509CertificateHolder(issueOne().certificate)));
    }
    for (int n = 1; n <= 12; n++) {
      byte[] response = decipher(opids.get(n - 1));
      assertArrayEquals(
          concat(
              hex("8104"),
              String.format("%04d", params.batch).getBytes(StandardCharsets.US_ASCII),
              hex("820101 8304"),
              u32(n),
              hex("840101")),
          response,
          "OPID " + n);
    }
  }

  @Test
  void notYetIssuedSeedAndForeignBatchAreReported() {
    Params params = Params.variant(root, 0);
    params.quota = 5;
    personalize(params);
    issueOne();
    issueOne();
    OpidV2Reference reference = reference(params);

    // Indices beyond `issued` are recovered but flagged as not issued.
    for (long n : new long[] {3, 4, 1000, 99_999_999L}) {
      byte[] response = decipher(reference.opidAt(n));
      assertArrayEquals(u32(n), tlvValue(response, 0x83), "n = " + n);
      assertArrayEquals(hex("00"), tlvValue(response, 0x84), "n = " + n + " not issued");
    }
    // x0 itself has index 0, which is never issued.
    byte[] seed = decipher(reference.opidForX(params.x0));
    assertArrayEquals(u32(0), tlvValue(seed, 0x83));
    assertArrayEquals(hex("00"), tlvValue(seed, 0x84));

    // Another batch under the same IIN key reports the batch only.
    byte[] foreign = decipher(reference.opidFor(4321, 12_345_678L));
    assertArrayEquals(concat(hex("8104"), "4321".getBytes(), hex("820100")), foreign);
  }

  @Test
  void hostReferenceRecoversTheSameCount() {
    Params params = Params.variant(root, 3);
    params.quota = 3;
    personalize(params);
    OpidV2Reference reference = reference(params);
    for (long n : new long[] {1, 2, 3, 77, 123_456, 99_999_998L}) {
      String opid = reference.opidAt(n);
      long[] plain = reference.decipher(opid);
      assertEquals(params.batch, plain[0]);
      assertEquals(n, reference.indexOf(plain[1]), "host index recovery");
      assertArrayEquals(u32(n), tlvValue(decipher(opid), 0x83), "SAM index recovery");
    }
  }

  @Test
  void malformedForeignAndUnauthorizedRequestsAreRefused() {
    Params params = Params.variant(root, 0);
    personalize(params);
    String opid = reference(params).opidAt(1);
    String badLuhn = opid.substring(0, 16) + (char) ('0' + (opid.charAt(16) - '0' + 1) % 10);
    String foreignIin = withLuhn("9999" + opid.substring(4, 16));

    assertSw(0x6982, transmit(0x80, 0x2C, 0x00, 0x00, tlv(0x80, opid.getBytes())), "plaintext");
    withMockedScp(
        () -> {
          assertSw(0x6982, decipherRaw(opid), "no PIN");
          assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY");
          assertSw(0x6A80, decipherRaw(badLuhn), "bad Luhn");
          assertSw(0x6A88, decipherRaw(foreignIin), "foreign IIN");
          assertSw(0x6A80, decipherRaw(opid.substring(0, 16)), "16 digits");
          assertSw(0x6A80, decipherRaw(opid + "0"), "18 digits");
          assertSw(0x6A80, decipherRaw("12345678901234A67"), "non-digit");
          assertSw(
              0x6A80,
              transmit(0x84, 0x2C, 0x00, 0x00, concat(tlv(0x80, opid.getBytes()), hex("00"))),
              "trailing octet");
          assertSw(0x6A80, transmit(0x84, 0x2C, 0x00, 0x00, tlv(0x81, opid.getBytes())), "tag");
          assertSw(0x6A86, transmit(0x84, 0x2C, 0x00, 0x01, tlv(0x80, opid.getBytes())), "P2");
          assertSw(0x9000, decipherRaw(opid), "valid");
        });
  }

  @Test
  void decipherIsUnavailableAfterTerminate() {
    Params params = Params.variant(root, 0);
    personalize(params);
    String opid = reference(params).opidAt(1);
    withMockedScp(
        () -> {
          assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY");
          collect(transmit(0x84, 0xE6, 0x00, 0x00), "TERMINATE");
          assertSw(0x6985, decipherRaw(opid), "after TERMINATE");
        });
  }
}
