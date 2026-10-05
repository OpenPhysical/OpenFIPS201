package dev.mistial.openphysical.sam;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import dev.mistial.tests.issuersam.OpidV2Reference;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import javacard.framework.JCSystem;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * White-box FF1, LCG and digest tests against test-vectors/opid/fpe.json (schema v2): the AES-256
 * SP 800-38G samples, every 12-digit OPID FF1 case in both directions, every sequence issuance
 * (including n = 1000, 12345678 and 99999999), the FF1 key check values, the paramsDigest v3 cases,
 * and the DECIPHER jump maps and index recovery. AES-128 and AES-192 samples are skipped: the SAM
 * is AES-256-only.
 */
class Ff1Test {
  private AutoCloseable engineContext;
  private MockedStatic<JCSystem> system;

  @BeforeEach
  void enter() throws Exception {
    engineContext = WhiteBox.engineContext();
    system = Mockito.mockStatic(JCSystem.class);
    WhiteBox.mockTransientStorage(system);
  }

  @AfterEach
  void leave() throws Exception {
    system.close();
    engineContext.close();
  }

  static JsonObject vectors() throws Exception {
    String directory = System.getProperty("openfips201.testVectors", "test-vectors");
    byte[] json = Files.readAllBytes(Paths.get(directory, "opid", "fpe.json"));
    JsonObject root =
        JsonParser.parseString(new String(json, StandardCharsets.UTF_8)).getAsJsonObject();
    assertEquals("openphysical.opid-vectors/2", root.get("schema").getAsString());
    return root;
  }

  private static SamCrypto crypto(String keyHex) {
    SamCrypto crypto = new SamCrypto(new byte[SamConst.LENGTH_IO_BUFFER]);
    crypto.fpeKey.setKey(U32Test.hex(keyHex), (short) 0);
    return crypto;
  }

  static byte[] digitsOf(String numeral) {
    byte[] out = new byte[numeral.length()];
    for (int i = 0; i < out.length; i++) out[i] = (byte) (numeral.charAt(i) - '0');
    return out;
  }

  private static byte[] ff1(boolean encrypt, SamCrypto crypto, byte[] tweak, String numeral) {
    byte[] digits = digitsOf(numeral);
    byte[] work = new byte[Ff1.LENGTH_WORK];
    if (encrypt) {
      Ff1.encrypt(
          crypto,
          digits,
          (short) 0,
          (short) digits.length,
          tweak,
          (short) 0,
          (short) tweak.length,
          work,
          (short) 0);
    } else {
      Ff1.decrypt(
          crypto,
          digits,
          (short) 0,
          (short) digits.length,
          tweak,
          (short) 0,
          (short) tweak.length,
          work,
          (short) 0);
    }
    assertTrue(WhiteBox.isZero(work), "FF1 work area zeroized");
    return digits;
  }

  private static SamState state(int iin, int batch, long a, long c, long x0) {
    SamState state = new SamState();
    byte[] iinDigits = digitsOf(String.format("%04d", iin));
    System.arraycopy(iinDigits, 0, state.issuerDigits, 0, 4);
    System.arraycopy(digitsOf(String.format("%04d", batch)), 0, state.batchDigits, 0, 4);
    System.arraycopy(DecimalLcgTest.digits(a, 8), 0, state.lcgA, 0, 8);
    System.arraycopy(DecimalLcgTest.digits(c, 8), 0, state.lcgC, 0, 8);
    System.arraycopy(DecimalLcgTest.digits(x0, 8), 0, state.lcgX0, 0, 8);
    return state;
  }

  @Test
  void nistAes256SamplesMatchInBothDirections() throws Exception {
    int checked = 0;
    for (JsonElement element : vectors().getAsJsonArray("nistFf1")) {
      JsonObject sample = element.getAsJsonObject();
      String keyHex = sample.get("keyHex").getAsString();
      if (keyHex.length() != 64) continue;
      SamCrypto crypto = crypto(keyHex);
      byte[] tweak = U32Test.hex(sample.get("tweakHex").getAsString());
      String plaintext = sample.get("plaintext").getAsString();
      String ciphertext = sample.get("ciphertext").getAsString();
      assertArrayEquals(digitsOf(ciphertext), ff1(true, crypto, tweak, plaintext));
      assertArrayEquals(digitsOf(plaintext), ff1(false, crypto, tweak, ciphertext));
      checked++;
    }
    assertEquals(2, checked, "AES-256 samples 7 and 8");
  }

  @Test
  void everyTwelveDigitCaseMatchesInBothDirections() throws Exception {
    JsonArray cases = vectors().getAsJsonArray("ff1");
    for (JsonElement element : cases) {
      JsonObject vector = element.getAsJsonObject();
      SamCrypto crypto = crypto(vector.get("keyHex").getAsString());
      SamState state = state(vector.get("iin").getAsInt(), 0, 21, 1, 0);
      byte[] tweak = new byte[4];
      assertEquals(4, Ff1.writeTweak(state, tweak, (short) 0));
      assertArrayEquals(U32Test.hex(vector.get("tweakHex").getAsString()), tweak);
      String plaintext = vector.get("plaintext").getAsString();
      String enciphered = vector.get("enciphered").getAsString();
      assertArrayEquals(digitsOf(enciphered), ff1(true, crypto, tweak, plaintext), plaintext);
      assertArrayEquals(digitsOf(plaintext), ff1(false, crypto, tweak, enciphered), enciphered);
    }
    assertEquals(18, cases.size());
  }

  @Test
  void everySequenceIssuanceMatches() throws Exception {
    int checked = 0;
    for (JsonElement element : vectors().getAsJsonArray("sequences")) {
      JsonObject sequence = element.getAsJsonObject();
      SamCrypto crypto = crypto(sequence.get("keyHex").getAsString());
      SamState state =
          state(
              sequence.get("iin").getAsInt(),
              sequence.get("batch").getAsInt(),
              sequence.get("a").getAsLong(),
              sequence.get("c").getAsLong(),
              sequence.get("x0").getAsLong());
      OpidV2Reference reference =
          new OpidV2Reference(
              sequence.get("iin").getAsInt(),
              sequence.get("batch").getAsInt(),
              sequence.get("a").getAsLong(),
              sequence.get("c").getAsLong(),
              sequence.get("x0").getAsLong(),
              U32Test.hex(sequence.get("keyHex").getAsString()));
      byte[] tweak = new byte[4];
      Ff1.writeTweak(state, tweak, (short) 0);
      assertArrayEquals(U32Test.hex(sequence.get("tweakHex").getAsString()), tweak);
      for (JsonElement entry : sequence.getAsJsonArray("issuance")) {
        JsonObject issuance = entry.getAsJsonObject();
        long n = issuance.get("n").getAsLong();
        long x = issuance.get("x").getAsLong();
        assertEquals(x, reference.x(n), "reference x_n");
        byte[] numeral = new byte[12];
        Ff1.writeNumeral(state, DecimalLcgTest.digits(x, 8), (short) 0, numeral, (short) 0);
        assertArrayEquals(digitsOf(issuance.get("plaintext").getAsString()), numeral);
        byte[] e = ff1(true, crypto, tweak, issuance.get("plaintext").getAsString());
        assertArrayEquals(digitsOf(issuance.get("e").getAsString()), e, "E for n = " + n);
        byte[] opid = new byte[17];
        Opid.render(state, e, (short) 0, opid, (short) 0);
        assertEquals(
            issuance.get("opid").getAsString(), new String(opid, StandardCharsets.US_ASCII));
        assertEquals(issuance.get("opid").getAsString(), reference.opidAt(n));
        checked++;
      }
    }
    assertEquals(92, checked);
  }

  @Test
  void sequenceStepsMatchTheOnCardLcg() throws Exception {
    for (JsonElement element : vectors().getAsJsonArray("sequences")) {
      JsonObject sequence = element.getAsJsonObject();
      SamState state =
          state(
              0,
              0,
              sequence.get("a").getAsLong(),
              sequence.get("c").getAsLong(),
              sequence.get("x0").getAsLong());
      byte[] x = state.lcgX0.clone();
      byte[] next = new byte[8];
      long n = 0;
      for (JsonElement entry : sequence.getAsJsonArray("issuance")) {
        JsonObject issuance = entry.getAsJsonObject();
        if (issuance.get("n").getAsLong() > 20) break;
        DecimalLcg.step(
            state.lcgA, (short) 0, x, (short) 0, state.lcgC, (short) 0, (short) 8, next, (short) 0);
        System.arraycopy(next, 0, x, 0, 8);
        n++;
        assertEquals(issuance.get("n").getAsLong(), n);
        assertEquals(issuance.get("x").getAsLong(), DecimalLcgTest.value(x, 0, 8));
      }
    }
  }

  @Test
  void keyCheckValuesMatch() throws Exception {
    for (JsonElement element : vectors().getAsJsonArray("kcv")) {
      JsonObject vector = element.getAsJsonObject();
      SamCrypto crypto = crypto(vector.get("keyHex").getAsString());
      byte[] work = new byte[60];
      crypto.fpeKcv(work, (short) 0);
      assertArrayEquals(U32Test.hex(vector.get("kcvHex").getAsString()), Arrays.copyOf(work, 16));
      assertTrue(WhiteBox.isZero(Arrays.copyOfRange(work, 16, 60)));
    }
  }

  @Test
  void paramsDigestV3CasesMatch() throws Exception {
    int checked = 0;
    for (JsonElement element : vectors().getAsJsonArray("paramsDigestV3")) {
      JsonObject vector = element.getAsJsonObject();
      SamCrypto crypto = crypto(vector.get("keyHex").getAsString());
      SamState state =
          state(
              vector.get("iin").getAsInt(),
              vector.get("batch").getAsInt(),
              vector.get("a").getAsLong(),
              vector.get("c").getAsLong(),
              vector.get("x0").getAsLong());
      System.arraycopy(U32Test.u32(vector.get("initialQuota").getAsLong()), 0, state.quota, 0, 4);
      byte[] ts = new BigInteger(vector.get("initialTs").getAsString()).toByteArray();
      byte[] ts8 = new byte[8];
      int length = Math.min(8, ts.length);
      System.arraycopy(ts, ts.length - length, ts8, 8 - length, length);
      System.arraycopy(ts8, 0, state.lastTopUpTs, 0, 8);
      SamLedger ledger = new SamLedger(state, crypto, new byte[1024], new byte[320], new byte[33]);
      byte[] work = new byte[160];
      crypto.fpeKcv(work, (short) 0);
      assertArrayEquals(
          U32Test.hex(vector.get("fpeKcvHex").getAsString()), Arrays.copyOf(work, 16), "KCV");
      byte[] out = new byte[32];
      ledger.paramsDigest(work, (short) 64, work, (short) 0, out, (short) 0);
      assertArrayEquals(U32Test.hex(vector.get("sha256").getAsString()), out, vector.toString());
      checked++;
    }
    assertEquals(3, checked);
  }

  @Test
  void jumpMapsAndIndexRecoveryMatchTheDecipherSet() throws Exception {
    JsonObject set = vectors().getAsJsonObject("decipher");
    SamCrypto crypto = crypto(set.get("keyHex").getAsString());
    SamState state =
        state(
            set.get("iin").getAsInt(),
            Integer.parseInt(set.get("batch").getAsString()),
            set.get("a").getAsLong(),
            set.get("c").getAsLong(),
            set.get("x0").getAsLong());
    DecimalLcg.jumpMaps(state.lcgA, state.lcgC, state.jumpA, state.jumpC, new byte[40], (short) 0);
    JsonArray maps = set.getAsJsonArray("jumpMaps");
    for (int j = 0; j < 8; j++) {
      JsonArray pair = maps.get(j).getAsJsonArray();
      assertEquals(pair.get(0).getAsLong(), DecimalLcgTest.value(state.jumpA, 8 * j, 8), "A" + j);
      assertEquals(pair.get(1).getAsLong(), DecimalLcgTest.value(state.jumpC, 8 * j, 8), "C" + j);
    }
    byte[] tweak = new byte[4];
    Ff1.writeTweak(state, tweak, (short) 0);
    for (JsonElement element : set.getAsJsonArray("cases")) {
      JsonObject vector = element.getAsJsonObject();
      String opid = vector.get("opid").getAsString();
      byte[] plain = ff1(false, crypto, tweak, opid.substring(4, 16));
      String batch = OpidV2Reference.numeral(Arrays.copyOf(plain, 4));
      assertEquals(vector.get("batch").getAsString(), batch, opid);
      if (!vector.get("sameBatch").getAsBoolean()) continue;
      byte[] x = new byte[8];
      for (int i = 0; i < 8; i++) x[i] = plain[11 - i];
      byte[] n = new byte[8];
      byte[] work = new byte[16];
      assertTrue(
          DecimalLcg.recoverIndex(
              state.jumpA, state.jumpC, state.lcgX0, x, (short) 0, work, (short) 0, n, (short) 0));
      assertTrue(WhiteBox.isZero(work));
      assertEquals(vector.get("count").getAsLong(), DecimalLcgTest.value(n, 0, 8), opid);
    }
  }
}
