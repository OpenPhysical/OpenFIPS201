package dev.mistial.tools.openfips201.vci;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * Known-answer conformance tests that replay real-card PIV VCI (OPACITY CS2) test vectors against
 * {@link VciSupport}, the host-side mirror of the applet's secure-messaging crypto.
 *
 * <p>The vectors are independent captures from real PIV cards (NIST cipher suite 2: P-256 /
 * AES-128 / SHA-256). The applet's card-side establishment cannot be replayed directly because the
 * vectors do not expose the card's SM private key, but {@link VciSupport} implements the exact same
 * byte-level OPACITY KDF and SM wire format as the applet
 * ({@code PIV.deriveCs2SessionKeys}/{@code PIVSecureMessaging}). Validating VciSupport against
 * real-card vectors here, together with {@link OpenFIPS201VciEndToEndTest} proving the live applet
 * interoperates with VciSupport, transitively validates the applet against the vectors.
 *
 * <p>Three known-answer checks per vector:
 *
 * <ol>
 *   <li><b>OPACITY KDF</b>: derive the four CS2 session keys + idSicc + authentication cryptogram
 *       from the captured ECDH inputs and assert they equal the card-reported values.
 *   <li><b>SM response chain</b>: unwrap every secure-messaging response in sequence, asserting the
 *       R-MAC verifies, the protected status word matches, and the response MAC chaining value and
 *       encryption counter reach the card-reported checkpoints.
 *   <li><b>SM command wrap</b>: wrap the two well-defined VERIFY commands (pairing code, PIN) and
 *       assert the produced APDU and command MAC chaining value match the captured bytes.
 * </ol>
 */
class OpenFIPS201VciVectorTest {

  private static final byte[] TRANSPORT_SW = Hex.decode("9000");

  @TestFactory
  Stream<DynamicTest> opacityKdfMatchesCardReportedKeys() throws Exception {
    return forEachVector(
        (name, v) -> {
          JsonObject o = v.getAsJsonObject("opacity");
          byte[] sharedSecret = hex(o, "shared_secret_Z");
          byte[] idH = hex(o, "id_sH");
          byte[] nIcc = hex(o, "n_ICC");
          byte[] cvcRaw = hex(o, "cvc_raw");
          byte[] hostPoint = concat(new byte[] {0x04}, hex(o, "ephemeral_public_key_x"), hex(o, "ephemeral_public_key_y"));

          // idSicc = SHA-256(CVC)[0:8] must match the card-reported value.
          assertArrayEquals(hex(o, "id_sICC"), VciSupport.computeIdSicc(cvcRaw), name + ": idSicc");
          byte[] idSicc = hex(o, "id_sICC");

          VciSupport.SessionKeys keys =
              VciSupport.deriveSessionKeys(sharedSecret, idH, hostPoint, idSicc, nIcc);
          assertArrayEquals(hex(o, "sk_cfrm"), keys.skCfrm, name + ": SK_CFRM");
          assertArrayEquals(hex(o, "sk_mac"), keys.skMac, name + ": SK_MAC");
          assertArrayEquals(hex(o, "sk_enc"), keys.skEnc, name + ": SK_ENC");
          assertArrayEquals(hex(o, "sk_rmac"), keys.skRmac, name + ": SK_RMAC");

          byte[] cryptogram =
              VciSupport.computeAuthCryptogram(keys.skCfrm, idSicc, idH, hostPoint);
          assertArrayEquals(
              hex(o, "auth_cryptogram"),
              java.util.Arrays.copyOf(cryptogram, 16),
              name + ": authentication cryptogram");
        });
  }

  @TestFactory
  Stream<DynamicTest> smResponseChainMatchesCardReportedState() throws Exception {
    return forEachVector(
        (name, v) -> {
          VciSupport.SmSession session = sessionFromVector(v);
          JsonObject s = v.getAsJsonObject("sm_session");
          boolean sawPairing = false;
          boolean sawPin = false;

          for (Exchange ex : secureMessagingExchanges(v)) {
            // The card increments the counter once per command/response pair; emulate the command
            // class/instruction so the host-side counter advances identically (never GET RESPONSE
            // or a chained 0x1C command in these captures).
            session.lastCla = (byte) 0x0C;
            session.lastIns = (byte) 0x00;

            // unwrapResponse throws on any R-MAC mismatch; reaching here means the response MAC
            // verified against the chained response MCV (the core known-answer for the response
            // side). The protected status word carried in the '99' tag is the application result:
            // 0x9000, or 0x6982 when a PIN-protected object (e.g. the facial image or printed
            // information, whose contactless rule is "VCI and PIN" per SP 800-73-5 Table 2) is read
            // before the PIN is verified over the channel, as happens in the contactless vectors.
            // The vector's top-level "sw" is the transport SW (always 0x9000 for successful SM) and
            // is intentionally not compared here.
            VciSupport.SmResponse resp =
                VciSupport.unwrapResponse(session, concat(ex.response, TRANSPORT_SW));
            assertTrue(
                resp.statusWord == 0x9000 || resp.statusWord == 0x6982,
                name + " [" + ex.description + "]: unexpected protected SW 0x"
                    + Integer.toHexString(resp.statusWord));
            if (resp.statusWord == 0x9000 && containsTag(ex.response, 0x87)) {
              assertTrue(
                  resp.data.length > 0,
                  name + " [" + ex.description + "]: decrypted payload should be non-empty");
            }

            // Anchor the response chain at the two checkpoints the card published. (In contactless
            // vectors there may be further exchanges after the PIN verify, so assert at the
            // matching exchange rather than at end-of-loop.)
            if (ex.description.contains("Pairing Code")) {
              assertResponseState(
                  name + " after pairing verify", session, s.getAsJsonObject("verify_pairing_state_after"));
              sawPairing = true;
            } else if (ex.description.contains("PIN") && (ex.command[1] & 0xFF) == 0x20) {
              assertResponseState(
                  name + " after PIN verify", session, s.getAsJsonObject("verify_pin_state_after"));
              sawPin = true;
            }
          }

          assertTrue(sawPairing, name + ": no wrapped pairing VERIFY exchange found");
          assertTrue(sawPin, name + ": no wrapped PIN VERIFY exchange found");
        });
  }

  @TestFactory
  Stream<DynamicTest> smCommandWrapMatchesCapturedApdus() throws Exception {
    return forEachVector(
        (name, v) -> {
          JsonObject s = v.getAsJsonObject("sm_session");
          List<Exchange> exchanges = secureMessagingExchanges(v);

          // Pairing-code VERIFY is the first SM command: counter starts at the initial state.
          Exchange pairing = requireExchange(exchanges, "Pairing Code", name);
          VciSupport.SmSession session = sessionFromVector(v);
          byte[] pairingCode = hex(s, "pairing_code_hex");
          byte[] wrapped =
              VciSupport.wrapCommand(session, (byte) 0x20, (byte) 0x00, (byte) 0x98, pairingCode, false);
          assertArrayEquals(pairing.command, wrapped, name + ": wrapped pairing VERIFY");
          assertArrayEquals(
              hex(s.getAsJsonObject("verify_pairing_state_after"), "cmd_mcv"),
              session.commandMcv,
              name + ": command MCV after pairing VERIFY");

          // The wrapped Global PIN VERIFY appears deep in the sequence; seed the session to the
          // card-reported pre-state so the single-command wrap is a precise known-answer check.
          Exchange pin = wrappedPinVerify(exchanges);
          if (pin != null) {
            VciSupport.SmSession pinSession = sessionFromVector(v);
            seedState(pinSession, s.getAsJsonObject("verify_pin_state_before"));
            byte[] pinData = hex(s, "pin_hex");
            byte pinRef = (byte) Integer.parseInt(stripHexPrefix(s.get("pin_key_ref").getAsString()), 16);
            byte[] wrappedPin =
                VciSupport.wrapCommand(pinSession, (byte) 0x20, (byte) 0x00, pinRef, pinData, false);
            assertArrayEquals(pin.command, wrappedPin, name + ": wrapped PIN VERIFY");
            assertArrayEquals(
                hex(s.getAsJsonObject("verify_pin_state_after"), "cmd_mcv"),
                pinSession.commandMcv,
                name + ": command MCV after PIN VERIFY");
          }
        });
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------------------------

  private interface VectorAssertion {
    void run(String name, JsonObject vector) throws Exception;
  }

  private static Stream<DynamicTest> forEachVector(VectorAssertion assertion) throws Exception {
    List<Path> vectors = listVectors();
    assertTrue(vectors.size() >= 8, "expected at least 8 CS2 vectors, found " + vectors.size());
    return vectors.stream()
        .map(
            path ->
                DynamicTest.dynamicTest(
                    path.getFileName().toString(),
                    () -> {
                      JsonObject v = load(path);
                      // Defensive: every fixture must be CS2 (alg 0x27).
                      String suite = v.getAsJsonObject("opacity").get("cipher_suite_id").getAsString();
                      assertTrue("0x27".equals(suite), path.getFileName() + " is not CS2 (was " + suite + ")");
                      assertion.run(path.getFileName().toString(), v);
                    }));
  }

  private static List<Path> listVectors() throws Exception {
    Path dir = vectorDir();
    try (Stream<Path> files = Files.list(dir)) {
      return files
          .filter(p -> p.getFileName().toString().endsWith(".json"))
          .sorted()
          .collect(Collectors.toList());
    }
  }

  private static Path vectorDir() {
    Path relative =
        Paths.get("src/dev/mistial/tool-tests/dev/mistial/tools/openfips201/vci/vectors");
    if (Files.isDirectory(relative)) {
      return relative;
    }
    // Fall back to a path relative to this class file when the CWD is not the repo root.
    Path here = Paths.get("").toAbsolutePath();
    while (here != null && !Files.isDirectory(here.resolve(relative))) {
      here = here.getParent();
    }
    if (here == null) {
      throw new IllegalStateException("Could not locate VCI vector directory");
    }
    return here.resolve(relative);
  }

  private static JsonObject load(Path path) throws Exception {
    try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
      return JsonParser.parseReader(reader).getAsJsonObject();
    }
  }

  private static VciSupport.SmSession sessionFromVector(JsonObject v) {
    JsonObject s = v.getAsJsonObject("sm_session");
    JsonObject o = v.getAsJsonObject("opacity");
    VciSupport.SessionKeys keys =
        new VciSupport.SessionKeys(hex(o, "sk_cfrm"), hex(s, "sk_mac"), hex(s, "sk_enc"), hex(s, "sk_rmac"));
    return new VciSupport.SmSession(keys);
  }

  private static List<Exchange> secureMessagingExchanges(JsonObject v) {
    List<Exchange> out = new ArrayList<>();
    for (com.google.gson.JsonElement el : v.getAsJsonArray("apdu_exchanges")) {
      JsonObject e = el.getAsJsonObject();
      byte[] command = hex(e, "command");
      if ((command[0] & 0xFF) != 0x0C) {
        continue; // Only secure-messaging-wrapped exchanges.
      }
      out.add(
          new Exchange(
              e.get("description").getAsString(),
              command,
              hex(e, "response"),
              Integer.parseInt(e.get("sw").getAsString(), 16)));
    }
    return out;
  }

  private static Exchange requireExchange(List<Exchange> exchanges, String marker, String name) {
    return exchanges.stream()
        .filter(e -> e.description.contains(marker))
        .findFirst()
        .orElseThrow(() -> new IllegalStateException(name + ": no SM exchange matching " + marker));
  }

  private static Exchange wrappedPinVerify(List<Exchange> exchanges) {
    return exchanges.stream()
        .filter(e -> e.description.contains("PIN") && (e.command[1] & 0xFF) == 0x20)
        .reduce((first, second) -> second) // the wrapped (last) PIN verify
        .orElse(null);
  }

  /**
   * Asserts the response-side state reached by replaying SM responses: the encryption counter and
   * the response MAC chaining value. The command MAC chaining value is a command-side quantity and
   * is validated separately by the command-wrap test.
   */
  private static void assertResponseState(String context, VciSupport.SmSession session, JsonObject state) {
    assertArrayEquals(hex(state, "counter"), session.encCounter, context + ": counter");
    assertArrayEquals(hex(state, "resp_mcv"), session.responseMcv, context + ": response MCV");
  }

  private static void seedState(VciSupport.SmSession session, JsonObject state) {
    System.arraycopy(hex(state, "counter"), 0, session.encCounter, 0, 16);
    System.arraycopy(hex(state, "cmd_mcv"), 0, session.commandMcv, 0, 16);
    System.arraycopy(hex(state, "resp_mcv"), 0, session.responseMcv, 0, 16);
  }

  private static byte[] hex(JsonObject obj, String field) {
    return Hex.decode(stripHexPrefix(obj.get(field).getAsString()));
  }

  private static String stripHexPrefix(String value) {
    return value.startsWith("0x") || value.startsWith("0X") ? value.substring(2) : value;
  }

  /** True if the response SM data field contains a top-level TLV with the given (1-byte) tag. */
  private static boolean containsTag(byte[] data, int tag) {
    int cursor = 0;
    while (cursor < data.length) {
      int t = data[cursor++] & 0xFF;
      int lengthByte = data[cursor++] & 0xFF;
      int length;
      if (lengthByte < 0x80) {
        length = lengthByte;
      } else if (lengthByte == 0x81) {
        length = data[cursor++] & 0xFF;
      } else if (lengthByte == 0x82) {
        length = ((data[cursor++] & 0xFF) << 8) | (data[cursor++] & 0xFF);
      } else {
        return false;
      }
      if (t == tag) {
        return true;
      }
      cursor += length;
    }
    return false;
  }

  private static byte[] concat(byte[]... arrays) {
    int total = 0;
    for (byte[] a : arrays) {
      total += a.length;
    }
    byte[] out = new byte[total];
    int off = 0;
    for (byte[] a : arrays) {
      System.arraycopy(a, 0, out, off, a.length);
      off += a.length;
    }
    return out;
  }

  private static final class Exchange {
    final String description;
    final byte[] command;
    final byte[] response;
    final int sw;

    Exchange(String description, byte[] command, byte[] response, int sw) {
      this.description = description;
      this.command = command;
      this.response = response;
      this.sw = sw;
    }
  }
}
