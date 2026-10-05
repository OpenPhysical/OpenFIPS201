/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.opid;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import dev.mistial.tools.openfips201.common.HexUtil;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class OpidSequenceTest {
  private static final byte[] KEY =
      HexUtil.parse("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");

  @Test
  void sequenceVectors() throws Exception {
    JsonObject root = OpidVectors.load("fpe.json");
    int count = 0;
    for (JsonElement element : root.getAsJsonArray("sequences")) {
      JsonObject v = element.getAsJsonObject();
      int iin = v.get("iin").getAsInt();
      int batch = v.get("batch").getAsInt();
      Lcg lcg = Lcg.of(v.get("a").getAsLong(), v.get("c").getAsLong(), v.get("x0").getAsLong());
      OpidSequence sequence =
          OpidSequence.of(iin, batch, lcg, HexUtil.parse(v.get("keyHex").getAsString()));
      assertEquals(v.get("tweakHex").getAsString(), HexUtil.format(sequence.tweak()));
      for (JsonElement rowElement : v.getAsJsonArray("issuance")) {
        JsonObject row = rowElement.getAsJsonObject();
        long n = row.get("n").getAsLong();
        assertEquals(row.get("x").getAsLong(), lcg.at(n));
        assertEquals(Long.parseLong(row.get("e").getAsString()), sequence.encipheredAt(n));
        Opid opid = sequence.opidAt(n);
        assertEquals(row.get("opid").getAsString(), opid.toPrinted());
        OpidSequence.Deciphered deciphered = sequence.decrypt(opid);
        assertEquals(batch, deciphered.batch);
        assertEquals(row.get("x").getAsLong(), deciphered.x);
        assertTrue(deciphered.sameBatch);
        assertEquals(n, deciphered.count);
        count++;
      }
    }
    assertTrue(count >= 40);
  }

  @Test
  void decipherVectorsForTheSam() throws Exception {
    JsonObject set = OpidVectors.load("fpe.json").getAsJsonObject("decipher");
    Lcg lcg = Lcg.of(set.get("a").getAsLong(), set.get("c").getAsLong(), set.get("x0").getAsLong());
    int batch = Integer.parseInt(set.get("batch").getAsString());
    OpidSequence sequence =
        OpidSequence.of(
            set.get("iin").getAsInt(), batch, lcg, HexUtil.parse(set.get("keyHex").getAsString()));
    long issued = set.get("issued").getAsLong();
    JsonArray maps = set.getAsJsonArray("jumpMaps");
    for (int j = 1; j <= 8; j++) {
      long[] map = lcg.jumpMap(j);
      assertEquals(maps.get(j - 1).getAsJsonArray().get(0).getAsLong(), map[0]);
      assertEquals(maps.get(j - 1).getAsJsonArray().get(1).getAsLong(), map[1]);
    }
    for (JsonElement element : set.getAsJsonArray("cases")) {
      JsonObject v = element.getAsJsonObject();
      OpidSequence.Deciphered deciphered =
          sequence.decrypt(Opid.parseCanonical(v.get("opid").getAsString()));
      String note = v.get("note").getAsString();
      assertEquals(v.get("batch").getAsString(), Digits.pad(deciphered.batch, 4), note);
      assertEquals(v.get("sameBatch").getAsBoolean(), deciphered.sameBatch, note);
      if (deciphered.sameBatch) {
        assertEquals(v.get("count").getAsLong(), deciphered.count, note);
        assertEquals(v.get("issuedFlag").getAsBoolean(), deciphered.issuedWithin(issued), note);
      } else {
        assertFalse(v.has("count"), note);
        assertEquals(-1L, deciphered.count, note);
        assertFalse(deciphered.issuedWithin(issued), note);
      }
    }
    for (JsonElement element : set.getAsJsonArray("rejected")) {
      String opid = element.getAsJsonObject().get("opid").getAsString();
      assertThrows(
          IllegalArgumentException.class,
          () -> sequence.decrypt(Opid.parseCanonical(opid)),
          element.toString());
    }
  }

  @Test
  void paramsDigestV3Vectors() throws Exception {
    JsonObject root = OpidVectors.load("fpe.json");
    for (JsonElement element : root.getAsJsonArray("paramsDigestV3")) {
      JsonObject v = element.getAsJsonObject();
      Lcg lcg = Lcg.of(v.get("a").getAsLong(), v.get("c").getAsLong(), v.get("x0").getAsLong());
      OpidSequence sequence =
          OpidSequence.of(
              v.get("iin").getAsInt(),
              v.get("batch").getAsInt(),
              lcg,
              HexUtil.parse(v.get("keyHex").getAsString()));
      long quota = v.get("initialQuota").getAsLong();
      long ts = v.get("initialTs").getAsLong();
      byte[] preimage = sequence.paramsPreimage(quota, ts);
      assertEquals(69, preimage.length);
      assertEquals(v.get("fpeKcvHex").getAsString(), HexUtil.format(sequence.fpeKcv()));
      assertEquals(v.get("preimageHex").getAsString(), HexUtil.format(preimage));
      assertEquals(v.get("sha256").getAsString(), HexUtil.format(sequence.paramsDigest(quota, ts)));
      assertFalse(HexUtil.format(preimage).contains(v.get("keyHex").getAsString()));
    }
  }

  @Test
  void decryptRoundTripsAndRecoversCount() {
    SecureRandom rnd = new SecureRandom();
    for (int i = 0; i < 10; i++) {
      Lcg lcg = Lcg.generate(rnd);
      int iin = rnd.nextInt(10000);
      int batch = rnd.nextInt(10000);
      OpidSequence sequence = OpidSequence.of(iin, batch, lcg, OpidCipher.generateKey(rnd));
      for (int t = 0; t < 30; t++) {
        long n = 1 + (rnd.nextLong() >>> 1) % (lcg.m - 1);
        OpidSequence.Deciphered deciphered = sequence.decrypt(sequence.opidAt(n));
        assertEquals(batch, deciphered.batch);
        assertEquals(lcg.at(n), deciphered.x);
        assertTrue(deciphered.sameBatch);
        assertEquals(n, deciphered.count);
        assertTrue(deciphered.issuedWithin(n));
        assertFalse(deciphered.issuedWithin(n - 1));
      }
    }
  }

  @Test
  void foreignBatchUnderTheSameKeyYieldsBatchOnly() {
    Lcg mine = Lcg.of(87654321L, 12345679L, 31415926L);
    Lcg theirs = Lcg.of(12345661L, 7654321L, 1000001L);
    OpidSequence sequence = OpidSequence.of(1234, 42, mine, KEY);
    OpidSequence other = OpidSequence.of(1234, 43, theirs, KEY);
    for (long n = 1; n <= 20; n++) {
      OpidSequence.Deciphered deciphered = sequence.decrypt(other.opidAt(n));
      assertEquals(43, deciphered.batch);
      assertFalse(deciphered.sameBatch);
      assertEquals(-1L, deciphered.count);
      assertEquals(theirs.at(n), deciphered.x);
    }
    OpidSequence foreignIin = OpidSequence.of(1235, 42, mine, KEY);
    assertThrows(IllegalArgumentException.class, () -> sequence.decrypt(foreignIin.opidAt(1)));
  }

  @Test
  void opidsAreUniqueAcrossBatchesOfOneIin() {
    Set<String> seen = new HashSet<>();
    SecureRandom rnd = new SecureRandom();
    byte[] key = OpidCipher.generateKey(rnd);
    for (int batch = 0; batch < 5; batch++) {
      OpidSequence sequence = OpidSequence.of(77, batch, Lcg.generate(rnd), key);
      for (long n = 1; n <= 400; n++) {
        assertTrue(seen.add(sequence.opidAt(n).toPrinted()), "duplicate OPID");
      }
    }
  }

  @Test
  void iinStaysPlaintextAndLuhnBindsTheTypedDigits() {
    SecureRandom rnd = new SecureRandom();
    int samples = 0;
    int plaintextMatches = 0;
    for (int iin : new int[] {0, 1, 1234, 9999}) {
      for (int batch : new int[] {0, 42, 9999}) {
        Lcg lcg = Lcg.generate(rnd);
        OpidSequence sequence = OpidSequence.of(iin, batch, lcg, OpidCipher.generateKey(rnd));
        String prefix = Digits.pad(iin, 4);
        for (long n = 1; n <= 100; n++) {
          Opid opid = sequence.opidAt(n);
          String printed = opid.toPrinted();
          assertEquals(17, printed.length());
          assertTrue(printed.startsWith(prefix), printed);
          assertEquals(iin, opid.iin);
          assertEquals(sequence.encipheredAt(n), opid.e);
          String typed = printed.substring(0, 16);
          assertEquals(prefix + Digits.pad(opid.e, 12), typed);
          assertEquals(Luhn.checkDigit(typed), opid.check);
          assertTrue(Luhn.isValid(printed));
          String plaintext = prefix + Digits.pad(batch, 4) + Digits.pad(lcg.at(n), 8);
          if (Luhn.checkDigit(plaintext) == opid.check) {
            plaintextMatches++;
          }
          samples++;
        }
      }
    }
    // A Luhn digit over the plaintext batch || x_n agrees only by chance (about 1 in 10).
    assertTrue(plaintextMatches * 10 < samples * 2, plaintextMatches + "/" + samples);
  }

  @Test
  void rejectsBadInputs() {
    Lcg lcg = Lcg.of(87654321L, 12345679L, 0);
    assertThrows(IllegalArgumentException.class, () -> OpidSequence.of(10000, 1, lcg, KEY));
    assertThrows(IllegalArgumentException.class, () -> OpidSequence.of(1, 10000, lcg, KEY));
    assertThrows(IllegalArgumentException.class, () -> OpidSequence.of(1, -1, lcg, KEY));
    assertThrows(
        IllegalArgumentException.class, () -> OpidSequence.of(1, 1, Lcg.of(4, 2341, 7777, 0), KEY));
    assertThrows(IllegalArgumentException.class, () -> OpidSequence.of(1, 1, lcg, new byte[16]));
    OpidSequence sequence = OpidSequence.of(1, 1, lcg, KEY);
    assertThrows(IllegalArgumentException.class, () -> sequence.opidAt(0));
    assertThrows(IllegalArgumentException.class, () -> sequence.paramsDigest(100000001L, 1));
    assertThrows(IllegalArgumentException.class, () -> sequence.paramsDigest(-1, 1));
    assertThrows(IllegalArgumentException.class, () -> sequence.decrypt(null));
    assertEquals("OpidSequence(iin=0001)", sequence.toString());
    sequence.destroy();
    assertThrows(IllegalStateException.class, () -> sequence.opidAt(1));
    assertThrows(IllegalStateException.class, () -> sequence.paramsDigest(1, 1));
  }
}
