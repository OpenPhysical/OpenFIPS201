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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import dev.mistial.tools.openfips201.common.HexUtil;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.fpe.FPEFF1Engine;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Test;

class OpidCipherTest {
  private static final byte[] KEY =
      HexUtil.parse("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");

  @Test
  void nistSp80038gFf1Radix10Samples() throws Exception {
    JsonObject root = OpidVectors.load("fpe.json");
    int aes256 = 0;
    for (JsonElement element : root.getAsJsonArray("nistFf1")) {
      JsonObject v = element.getAsJsonObject();
      byte[] key = HexUtil.parse(v.get("keyHex").getAsString());
      String tweakHex = v.get("tweakHex").getAsString();
      byte[] tweak = tweakHex.isEmpty() ? new byte[0] : HexUtil.parse(tweakHex);
      byte[] plaintext = digits(v.get("plaintext").getAsString());
      String expected = v.get("ciphertext").getAsString();

      FPEFF1Engine engine = new FPEFF1Engine(AESEngine.newInstance());
      engine.init(true, new FPEParameters(new KeyParameter(key), 10, tweak));
      byte[] out = new byte[plaintext.length];
      engine.processBlock(plaintext, 0, plaintext.length, out, 0);
      assertEquals(expected, text(out), "sample " + v.get("sample"));

      if (key.length == OpidCipher.KEY_LENGTH) {
        OpidCipher cipher = OpidCipher.of(key);
        byte[] enciphered = cipher.ff1(true, plaintext, tweak);
        assertEquals(expected, text(enciphered));
        assertArrayEquals(plaintext, cipher.ff1(false, enciphered, tweak));
        aes256++;
      }
    }
    assertEquals(2, aes256, "SP 800-38G samples 7 and 8");
  }

  @Test
  void keyCheckValues() throws Exception {
    JsonObject root = OpidVectors.load("fpe.json");
    for (JsonElement element : root.getAsJsonArray("kcv")) {
      JsonObject v = element.getAsJsonObject();
      OpidCipher cipher = OpidCipher.of(HexUtil.parse(v.get("keyHex").getAsString()));
      assertEquals(v.get("kcvHex").getAsString(), HexUtil.format(cipher.kcv()));
    }
  }

  @Test
  void twelveDigitFieldVectors() throws Exception {
    JsonObject root = OpidVectors.load("fpe.json");
    int count = 0;
    for (JsonElement element : root.getAsJsonArray("ff1")) {
      JsonObject v = element.getAsJsonObject();
      OpidCipher cipher = OpidCipher.of(HexUtil.parse(v.get("keyHex").getAsString()));
      int iin = v.get("iin").getAsInt();
      assertEquals(v.get("tweakHex").getAsString(), HexUtil.format(OpidCipher.tweak(iin)));
      long plain = Long.parseLong(v.get("plaintext").getAsString());
      long e = Long.parseLong(v.get("enciphered").getAsString());
      assertEquals(e, cipher.encipher(iin, plain), v.toString());
      assertEquals(plain, cipher.decipher(iin, e), v.toString());
      count++;
    }
    assertTrue(count >= 6);
  }

  @Test
  void encipherIsAPermutationOnSampledInputs() {
    OpidCipher cipher = OpidCipher.of(KEY);
    SecureRandom rnd = new SecureRandom();
    for (int i = 0; i < 2000; i++) {
      long plain = (rnd.nextLong() >>> 1) % Opid.E_MODULUS;
      long e = cipher.encipher(1234, plain);
      assertTrue(e >= 0 && e < Opid.E_MODULUS);
      assertEquals(plain, cipher.decipher(1234, e));
    }
    // Consecutive inputs map to distinct outputs.
    Set<Long> outputs = new HashSet<>();
    for (long plain = 0; plain < 5000; plain++) {
      assertTrue(outputs.add(cipher.encipher(42, plain)), "collision at " + plain);
    }
  }

  @Test
  void tweakIsAsciiIin() {
    assertArrayEquals(ascii("1234"), OpidCipher.tweak(1234));
    assertArrayEquals(ascii("0042"), OpidCipher.tweak(42));
    assertArrayEquals(ascii("0000"), OpidCipher.tweak(0));
    assertThrows(IllegalArgumentException.class, () -> OpidCipher.tweak(10000));
    assertThrows(IllegalArgumentException.class, () -> OpidCipher.tweak(-1));
  }

  @Test
  void tweakAndKeySeparateOutputs() {
    OpidCipher cipher = OpidCipher.of(KEY);
    long a = cipher.encipher(1234, 4200012345678L % Opid.E_MODULUS);
    long b = cipher.encipher(1235, 4200012345678L % Opid.E_MODULUS);
    long c = OpidCipher.of(new byte[32]).encipher(1234, 4200012345678L % Opid.E_MODULUS);
    assertNotEquals(a, b);
    assertNotEquals(a, c);
  }

  @Test
  void rejectsBadInputs() {
    assertThrows(IllegalArgumentException.class, () -> OpidCipher.of(new byte[16]));
    assertThrows(IllegalArgumentException.class, () -> OpidCipher.of((byte[]) null));
    OpidCipher cipher = OpidCipher.of(KEY);
    assertThrows(IllegalArgumentException.class, () -> cipher.encipher(1, Opid.E_MODULUS));
    assertThrows(IllegalArgumentException.class, () -> cipher.encipher(1, -1));
    assertThrows(IllegalArgumentException.class, () -> cipher.decipher(1, Opid.E_MODULUS));
    assertThrows(IllegalArgumentException.class, () -> cipher.encipher(10000, 0));
    cipher.destroy();
    assertThrows(IllegalStateException.class, () -> cipher.encipher(1, 0));
    assertThrows(IllegalStateException.class, cipher::kcv);
  }

  @Test
  void keyCopyIsIndependentOfCaller() {
    byte[] key = KEY.clone();
    OpidCipher cipher = OpidCipher.of(key);
    byte[] kcv = cipher.kcv();
    key[0] ^= 1;
    assertArrayEquals(kcv, cipher.kcv());
  }

  @Test
  void generatedKeysAre256Bit() {
    SecureRandom rnd = new SecureRandom();
    byte[] first = OpidCipher.generateKey(rnd);
    byte[] second = OpidCipher.generateKey(rnd);
    assertEquals(32, first.length);
    assertFalse(Arrays.equals(first, second));
    assertEquals(16, OpidCipher.of(first).kcv().length);
  }

  private static byte[] ascii(String value) {
    return value.getBytes(StandardCharsets.US_ASCII);
  }

  private static byte[] digits(String value) {
    byte[] out = new byte[value.length()];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) (value.charAt(i) - '0');
    }
    return out;
  }

  private static String text(byte[] digits) {
    StringBuilder out = new StringBuilder(digits.length);
    for (byte digit : digits) {
      out.append((char) ('0' + digit));
    }
    return out.toString();
  }
}
