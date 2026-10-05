/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.opid;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import dev.mistial.tools.openfips201.common.HexUtil;
import java.util.function.Function;

/**
 * Every {@code fpe.json} vector that involves an AES-256 FF1 key, run through ciphers built by a
 * caller-supplied factory (key bytes to {@link OpidCipher}), so the in-memory and the token-backed
 * {@link dev.mistial.tools.openfips201.crypto.AesBlock} give the same answers.
 */
final class FpeVectorChecks {
  private FpeVectorChecks() {}

  /** Runs every vector set; returns the number of individual checks. */
  static int runAll(Function<byte[], OpidCipher> factory) throws Exception {
    JsonObject root = OpidVectors.load("fpe.json");
    int checks = 0;
    for (JsonElement element : root.getAsJsonArray("nistFf1")) {
      JsonObject v = element.getAsJsonObject();
      byte[] key = HexUtil.parse(v.get("keyHex").getAsString());
      if (key.length != OpidCipher.KEY_LENGTH) {
        continue;
      }
      String tweakHex = v.get("tweakHex").getAsString();
      byte[] tweak = tweakHex.isEmpty() ? new byte[0] : HexUtil.parse(tweakHex);
      byte[] plaintext = digits(v.get("plaintext").getAsString());
      OpidCipher cipher = factory.apply(key);
      byte[] enciphered = cipher.ff1(true, plaintext, tweak);
      assertEquals(
          v.get("ciphertext").getAsString(), text(enciphered), "sample " + v.get("sample"));
      assertArrayEquals(plaintext, cipher.ff1(false, enciphered, tweak));
      checks++;
    }
    for (JsonElement element : root.getAsJsonArray("kcv")) {
      JsonObject v = element.getAsJsonObject();
      OpidCipher cipher = factory.apply(HexUtil.parse(v.get("keyHex").getAsString()));
      assertEquals(v.get("kcvHex").getAsString(), HexUtil.format(cipher.kcv()));
      checks++;
    }
    for (JsonElement element : root.getAsJsonArray("ff1")) {
      JsonObject v = element.getAsJsonObject();
      OpidCipher cipher = factory.apply(HexUtil.parse(v.get("keyHex").getAsString()));
      int iin = v.get("iin").getAsInt();
      long plain = Long.parseLong(v.get("plaintext").getAsString());
      long e = Long.parseLong(v.get("enciphered").getAsString());
      assertEquals(e, cipher.encipher(iin, plain), v.toString());
      assertEquals(plain, cipher.decipher(iin, e), v.toString());
      checks++;
    }
    for (JsonElement element : root.getAsJsonArray("sequences")) {
      JsonObject v = element.getAsJsonObject();
      int batch = v.get("batch").getAsInt();
      Lcg lcg = Lcg.of(v.get("a").getAsLong(), v.get("c").getAsLong(), v.get("x0").getAsLong());
      OpidSequence sequence =
          OpidSequence.of(
              v.get("iin").getAsInt(),
              batch,
              lcg,
              factory.apply(HexUtil.parse(v.get("keyHex").getAsString())));
      for (JsonElement rowElement : v.getAsJsonArray("issuance")) {
        JsonObject row = rowElement.getAsJsonObject();
        long n = row.get("n").getAsLong();
        assertEquals(Long.parseLong(row.get("e").getAsString()), sequence.encipheredAt(n));
        Opid opid = sequence.opidAt(n);
        assertEquals(row.get("opid").getAsString(), opid.toPrinted());
        OpidSequence.Deciphered deciphered = sequence.decrypt(opid);
        assertEquals(batch, deciphered.batch);
        assertEquals(n, deciphered.count);
        checks++;
      }
    }
    JsonObject set = root.getAsJsonObject("decipher");
    Lcg lcg = Lcg.of(set.get("a").getAsLong(), set.get("c").getAsLong(), set.get("x0").getAsLong());
    OpidSequence sequence =
        OpidSequence.of(
            set.get("iin").getAsInt(),
            Integer.parseInt(set.get("batch").getAsString()),
            lcg,
            factory.apply(HexUtil.parse(set.get("keyHex").getAsString())));
    long issued = set.get("issued").getAsLong();
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
      }
      checks++;
    }
    for (JsonElement element : set.getAsJsonArray("rejected")) {
      String opid = element.getAsJsonObject().get("opid").getAsString();
      assertThrows(
          IllegalArgumentException.class, () -> sequence.decrypt(Opid.parseCanonical(opid)));
      checks++;
    }
    for (JsonElement element : root.getAsJsonArray("paramsDigestV3")) {
      JsonObject v = element.getAsJsonObject();
      OpidSequence digest =
          OpidSequence.of(
              v.get("iin").getAsInt(),
              v.get("batch").getAsInt(),
              Lcg.of(v.get("a").getAsLong(), v.get("c").getAsLong(), v.get("x0").getAsLong()),
              factory.apply(HexUtil.parse(v.get("keyHex").getAsString())));
      long quota = v.get("initialQuota").getAsLong();
      long ts = v.get("initialTs").getAsLong();
      assertEquals(v.get("fpeKcvHex").getAsString(), HexUtil.format(digest.fpeKcv()));
      assertEquals(
          v.get("preimageHex").getAsString(), HexUtil.format(digest.paramsPreimage(quota, ts)));
      assertEquals(v.get("sha256").getAsString(), HexUtil.format(digest.paramsDigest(quota, ts)));
      assertFalse(
          HexUtil.format(digest.paramsPreimage(quota, ts)).contains(v.get("keyHex").getAsString()));
      checks++;
    }
    return checks;
  }

  private static byte[] digits(String text) {
    byte[] out = new byte[text.length()];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) (text.charAt(i) - '0');
    }
    return out;
  }

  private static String text(byte[] digits) {
    StringBuilder out = new StringBuilder();
    for (byte digit : digits) {
      out.append((char) ('0' + digit));
    }
    return out.toString();
  }
}
