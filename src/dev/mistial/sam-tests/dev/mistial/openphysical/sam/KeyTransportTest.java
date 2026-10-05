package dev.mistial.openphysical.sam;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
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
 * Known-answer tests of the FF1-key transport against test-vectors/sam/transport.json, produced by
 * the independent Python reference sam_transport_vectors.py: RFC 3394 Section 4.6 unwrap, the X9.63
 * SHA-256 KDF, and ECDH + KDF + unwrap end to end.
 */
class KeyTransportTest {
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
    byte[] json = Files.readAllBytes(Paths.get(directory, "sam", "transport.json"));
    JsonObject root =
        JsonParser.parseString(new String(json, StandardCharsets.UTF_8)).getAsJsonObject();
    assertEquals("openphysical.sam-transport-vectors/1", root.get("schema").getAsString());
    return root;
  }

  private static byte[] hex(JsonObject object, String name) {
    return U32Test.hex(object.get(name).getAsString());
  }

  @Test
  void rfc3394Section46UnwrapAndIntegrityFailure() throws Exception {
    JsonObject vector = vectors().getAsJsonObject("rfc3394");
    SamCrypto crypto = new SamCrypto(new byte[SamConst.LENGTH_IO_BUFFER]);
    byte[] register = new byte[40];
    byte[] block = new byte[16];
    assertTrue(
        crypto.aesKeyUnwrap(
            hex(vector, "kekHex"),
            (short) 0,
            hex(vector, "wrappedHex"),
            (short) 0,
            register,
            (short) 0,
            block,
            (short) 0));
    assertArrayEquals(hex(vector, "keyHex"), Arrays.copyOfRange(register, 8, 40));
    assertTrue(WhiteBox.isZero(block));
    assertFalse(crypto.kek.isInitialized(), "KEK cleared after use");

    for (int position = 0; position < 40; position += 13) {
      byte[] tampered = hex(vector, "wrappedHex");
      tampered[position] ^= 0x01;
      assertFalse(
          crypto.aesKeyUnwrap(
              hex(vector, "kekHex"),
              (short) 0,
              tampered,
              (short) 0,
              register,
              (short) 0,
              block,
              (short) 0),
          "tampered octet " + position);
    }
    byte[] wrongKek = hex(vector, "kekHex");
    wrongKek[31] ^= 0x80;
    assertFalse(
        crypto.aesKeyUnwrap(
            wrongKek,
            (short) 0,
            hex(vector, "wrappedHex"),
            (short) 0,
            register,
            (short) 0,
            block,
            (short) 0));
  }

  @Test
  void x963KdfVectorsMatch() throws Exception {
    SamCrypto crypto = new SamCrypto(new byte[SamConst.LENGTH_IO_BUFFER]);
    int checked = 0;
    for (JsonElement element : vectors().getAsJsonArray("x963")) {
      JsonObject vector = element.getAsJsonObject();
      byte[] iin =
          String.format("%04d", vector.get("iin").getAsInt()).getBytes(StandardCharsets.US_ASCII);
      byte[] out = new byte[32];
      crypto.x963Kdf(
          hex(vector, "zHex"),
          (short) 0,
          hex(vector, "transportPubHex"),
          (short) 0,
          hex(vector, "hostEphPubHex"),
          (short) 0,
          iin,
          (short) 0,
          out,
          (short) 0);
      assertArrayEquals(hex(vector, "kekHex"), out);
      checked++;
    }
    assertEquals(3, checked);
  }

  @Test
  void endToEndEcdhKdfUnwrapVectorsMatch() throws Exception {
    int checked = 0;
    for (JsonElement element : vectors().getAsJsonArray("endToEnd")) {
      JsonObject vector = element.getAsJsonObject();
      SamCrypto crypto = new SamCrypto(new byte[SamConst.LENGTH_IO_BUFFER]);
      crypto.transportPrivate.setS(hex(vector, "transportPrivHex"), (short) 0, (short) 32);
      crypto.transportPublic.setW(hex(vector, "transportPubHex"), (short) 0, (short) 65);
      byte[] in = WhiteBox.concat(hex(vector, "hostEphPubHex"), hex(vector, "wrappedHex"));
      byte[] iin =
          String.format("%04d", vector.get("iin").getAsInt()).getBytes(StandardCharsets.US_ASCII);
      byte[] work = new byte[SamConst.LENGTH_SCRATCH];
      assertTrue(crypto.unwrapTransportedKey(in, (short) 0, in, (short) 65, iin, (short) 0, work));
      assertArrayEquals(
          hex(vector, "fpeKeyHex"),
          Arrays.copyOfRange(work, SamConst.S_KW_KEY, SamConst.S_KW_KEY + 32));
      Arrays.fill(work, SamConst.S_KW_KEY, SamConst.S_KW_KEY + 32, (byte) 0);
      assertTrue(WhiteBox.isZero(work), "every intermediate zeroized");

      // The KDF binds the IIN: the same wrap under another IIN fails the integrity check.
      byte[] otherIin = "9998".getBytes(StandardCharsets.US_ASCII);
      assertFalse(
          crypto.unwrapTransportedKey(in, (short) 0, in, (short) 65, otherIin, (short) 0, work));
      assertTrue(WhiteBox.isZero(work), "zeroized on failure");
      checked++;
    }
    assertEquals(3, checked);
  }
}
