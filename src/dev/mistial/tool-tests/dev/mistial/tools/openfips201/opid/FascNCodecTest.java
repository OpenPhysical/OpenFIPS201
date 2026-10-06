/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.opid;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import dev.mistial.tools.openfips201.common.HexUtil;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

class FascNCodecTest {
  @Test
  void vectorsDecodeAndRoundTrip() throws Exception {
    JsonObject root = OpidVectors.load("fascn-codec.json");
    int count = 0;
    for (JsonElement element : root.getAsJsonArray("vectors")) {
      JsonObject v = element.getAsJsonObject();
      byte[] encoded = HexUtil.parse(v.get("hex").getAsString());
      FascN fascN = FascNCodec.decode(encoded);
      assertEquals(v.get("agencyCode").getAsInt(), fascN.agencyCode);
      assertEquals(v.get("systemCode").getAsInt(), fascN.systemCode);
      assertEquals(v.get("credentialNumber").getAsInt(), fascN.credentialNumber);
      assertEquals(v.get("credentialSeries").getAsInt(), fascN.credentialSeries);
      assertEquals(v.get("individualCredentialIssue").getAsInt(), fascN.individualCredentialIssue);
      assertEquals(v.get("personIdentifier").getAsLong(), fascN.personIdentifier);
      assertEquals(v.get("organizationalCategory").getAsInt(), fascN.organizationalCategory);
      assertEquals(v.get("organizationalIdentifier").getAsInt(), fascN.organizationalIdentifier);
      assertEquals(v.get("personAssociation").getAsInt(), fascN.personAssociation);
      assertArrayEquals(encoded, FascNCodec.encode(fascN));
      count++;
    }
    assertTrue(count >= 6);
  }

  @Test
  void decodesPivIReferenceValue() {
    FascN fascN =
        FascNCodec.decode(HexUtil.parse("D4E739DA739CED39CE739D8360D821085A285728CCE73987F0"));
    assertEquals("S9999|9999|999999|0|0|0000681532 3 9999 0 E", fascN.toString());
  }

  @Test
  void invalidVectorsAreRejected() throws Exception {
    JsonObject root = OpidVectors.load("fascn-codec.json");
    int count = 0;
    for (JsonElement element : root.getAsJsonArray("invalid")) {
      JsonObject v = element.getAsJsonObject();
      byte[] encoded = HexUtil.parse(v.get("hex").getAsString());
      IllegalArgumentException error =
          assertThrows(
              IllegalArgumentException.class, () -> FascNCodec.decode(encoded), v.toString());
      String reason = v.get("reason").getAsString();
      assertTrue(error.getMessage().contains(reason), reason + ": " + error.getMessage());
      count++;
    }
    assertTrue(count >= 5);
    assertThrows(IllegalArgumentException.class, () -> FascNCodec.decode(null));
  }

  @Test
  void everySingleBitFlipIsDetected() {
    byte[] encoded =
        FascNCodec.encode(new FascN(1234, 5678, 123456, 7, 8, 1234567890L, 1, 4321, 2));
    for (int bit = 0; bit < 200; bit++) {
      byte[] corrupted = encoded.clone();
      corrupted[bit >>> 3] ^= (byte) (0x80 >>> (bit & 7));
      assertThrows(
          IllegalArgumentException.class, () -> FascNCodec.decode(corrupted), "bit " + bit);
    }
  }

  @Test
  void randomRoundTrip() {
    SecureRandom rnd = new SecureRandom();
    for (int i = 0; i < 2000; i++) {
      FascN fascN =
          new FascN(
              rnd.nextInt(10000),
              rnd.nextInt(10000),
              rnd.nextInt(1000000),
              rnd.nextInt(10),
              rnd.nextInt(10),
              (rnd.nextLong() >>> 1) % 10000000000L,
              rnd.nextInt(10),
              rnd.nextInt(10000),
              rnd.nextInt(10));
      byte[] encoded = FascNCodec.encode(fascN);
      assertEquals(FascNCodec.LENGTH, encoded.length);
      assertEquals(fascN, FascNCodec.decode(encoded));
    }
  }

  @Test
  void opidFascNRoundTripsAndPlacesEncipheredDigits() {
    SecureRandom rnd = new SecureRandom();
    for (int i = 0; i < 500; i++) {
      Opid opid = Opid.of(rnd.nextInt(10000), (rnd.nextLong() >>> 1) % Opid.E_MODULUS);
      FascN derived = OpidIdentifiers.fascN(opid);
      assertEquals(derived, FascNCodec.decode(FascNCodec.encode(derived)));
      String e = opid.toPrinted().substring(4, 16);
      assertEquals(e.charAt(2) - '0', derived.credentialSeries);
      assertEquals(e.charAt(3) - '0', derived.individualCredentialIssue);
      assertEquals(Long.parseLong(e.substring(0, 2) + e.substring(4)), derived.personIdentifier);
      assertEquals(opid.iin, derived.organizationalIdentifier);
      assertEquals(6, derived.personAssociation);
    }
  }

  @Test
  void fieldRangesAreEnforced() {
    assertThrows(IllegalArgumentException.class, () -> new FascN(10000, 0, 0, 0, 0, 0L, 0, 0, 0));
    assertThrows(IllegalArgumentException.class, () -> new FascN(0, 0, 1000000, 0, 0, 0L, 0, 0, 0));
    assertThrows(IllegalArgumentException.class, () -> new FascN(0, 0, 0, 10, 0, 0L, 0, 0, 0));
    assertThrows(
        IllegalArgumentException.class, () -> new FascN(0, 0, 0, 0, 0, 10000000000L, 0, 0, 0));
    assertThrows(IllegalArgumentException.class, () -> new FascN(0, 0, 0, 0, 0, -1L, 0, 0, 0));
  }
}
