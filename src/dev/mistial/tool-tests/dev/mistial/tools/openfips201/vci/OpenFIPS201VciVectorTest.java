package dev.mistial.tools.openfips201.vci;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * Known-answer conformance tests that replay real-card PIV VCI / Secure Messaging test vectors
 * against {@link VciSupport}, the host-side mirror of the applet's secure-messaging crypto.
 *
 * <p>Vectors are independent captures from NIST Special Database 33 cards covering OPACITY Cipher
 * Suite 2 (P-256 / AES-128 / SHA-256) and Cipher Suite 7 (P-384 / AES-256 / SHA-384). The applet
 * covers CS2 and CS7 host-side OPACITY/SM wire format against
 * real cards; live CS7 E2E is covered by OpenFIPS201VciEndToEndTest.
 *
 * <p>The applet's card-side establishment cannot be replayed directly because the vectors do not
 * expose the card's SM private key, but {@link VciSupport} implements the exact same byte-level
 * OPACITY KDF and SM wire format as the applet ({@code PIV.deriveCs2SessionKeys} /
 * {@code PIVSecureMessaging}). Validating VciSupport against real-card vectors here, together with
 * {@link OpenFIPS201VciEndToEndTest} proving the live applet interoperates with VciSupport,
 * transitively validates the applet against the vectors for CS2.
 *
 * <p>Checks per vector (aligned with OpenPhysical.Net {@code verify_vectors.py}):
 *
 * <ol>
 *   <li><b>OPACITY KDF</b>: OtherInfo construction, KDF rounds, four session keys, authentication
 *       cryptogram.
 *   <li><b>Full SM session replay</b>: re-wrap every plain command (after transport-chain
 *       reassembly), unwrap every response, match plaintext payloads and chaining state.
 *   <li><b>Legacy checkpoints</b>: pairing-code and PIN VERIFY wrap still match the published
 *       post-state snapshots when present.
 * </ol>
 *
 * <p>Standards: NIST SP 800-73-5 Part 2 Sections 4.1–4.2; SP 800-56A concatenation KDF; ISO 7816-4
 * SM TLV encoding and command chaining.
 */
class OpenFIPS201VciVectorTest {

  private static final byte[] TRANSPORT_SW = Hex.decode("9000");

  /**
   * Verifies OPACITY session-key derivation against card-reported values.
   *
   * <p>Aligned with NIST SP 800-73-5 Part 2, Section 4.1.6 (Key Derivation) and Section 4.1.7
   * (Key Confirmation).
   */
  @TestFactory
  Stream<DynamicTest> opacityKdfMatchesCardReportedKeys() throws Exception {
    return forEachVector(
        (name, v) -> {
          JsonObject o = v.getAsJsonObject("opacity");
          byte suite = parseSuite(o);
          byte[] sharedSecret = hex(o, "shared_secret_Z");
          byte[] idH = hex(o, "id_sH");
          byte[] nIcc = hex(o, "n_ICC");
          byte[] cvcRaw = hex(o, "cvc_raw");
          byte[] hostPoint =
              concat(new byte[] {0x04}, hex(o, "ephemeral_public_key_x"), hex(o, "ephemeral_public_key_y"));

          assertArrayEquals(hex(o, "id_sICC"), VciSupport.computeIdSicc(cvcRaw), name + ": idSicc");
          byte[] idSicc = hex(o, "id_sICC");

          if (o.has("other_info")) {
            byte[] otherInfo = VciSupport.buildOtherInfo(suite, idH, hostPoint, idSicc, nIcc);
            assertArrayEquals(hex(o, "other_info"), otherInfo, name + ": OtherInfo");
          }

          int rounds = VciSupport.isCs2(suite) ? 2 : 3;
          if (o.has("kdf_round_1_input")) {
            byte[] otherInfo = VciSupport.buildOtherInfo(suite, idH, hostPoint, idSicc, nIcc);
            for (int i = 1; i <= rounds; i++) {
              String inputKey = "kdf_round_" + i + "_input";
              String hashKey = "kdf_round_" + i + "_hash";
              if (!o.has(inputKey)) {
                break;
              }
              byte[] roundHash = VciSupport.kdfRound(suite, i, sharedSecret, otherInfo);
              // Rebuild the exact KDF input to match the published round input.
              byte[] expectedInput = hex(o, inputKey);
              byte[] actualInput = buildKdfInput(i, sharedSecret, otherInfo);
              assertArrayEquals(expectedInput, actualInput, name + ": KDF round " + i + " input");
              assertArrayEquals(hex(o, hashKey), roundHash, name + ": KDF round " + i + " hash");
            }
          }

          VciSupport.SessionKeys keys =
              VciSupport.deriveSessionKeys(suite, sharedSecret, idH, hostPoint, idSicc, nIcc);
          assertArrayEquals(hex(o, "sk_cfrm"), keys.skCfrm, name + ": SK_CFRM");
          assertArrayEquals(hex(o, "sk_mac"), keys.skMac, name + ": SK_MAC");
          assertArrayEquals(hex(o, "sk_enc"), keys.skEnc, name + ": SK_ENC");
          assertArrayEquals(hex(o, "sk_rmac"), keys.skRmac, name + ": SK_RMAC");

          byte[] cryptogram =
              VciSupport.computeAuthCryptogram(keys.skCfrm, idSicc, idH, hostPoint);
          assertArrayEquals(
              hex(o, "auth_cryptogram"),
              Arrays.copyOf(cryptogram, 16),
              name + ": authentication cryptogram");
        });
  }

  /**
   * Full SM session replay: re-wrap every plain command and unwrap every response.
   *
   * <p>Aligned with NIST SP 800-73-5 Part 2 Sections 4.2.3–4.2.6. This is the primary coverage
   * expansion over the original VERIFY-only known-answer checks.
   */
  @TestFactory
  Stream<DynamicTest> fullSmSessionReplayMatchesCapturedExchanges() throws Exception {
    return forEachVector(
        (name, v) -> {
          List<Exchange> exchanges = mergeTransportChains(allExchanges(v));
          List<Exchange> sm = new ArrayList<>();
          for (Exchange ex : exchanges) {
            if ((ex.command[0] & 0xFF) == 0x0C || (ex.command[0] & 0xFF) == 0x1C) {
              sm.add(ex);
            }
          }
          assertTrue(sm.size() >= 2, name + ": expected multiple SM exchanges, found " + sm.size());

          VciSupport.SmSession session = sessionFromVector(v);
          int wrapped = 0;
          int unwrapped = 0;

          for (Exchange ex : sm) {
            int cla = ex.command[0] & 0xFF;
            // Intermediate transport chunks (CLA 1C) are already merged; any leftover 1C is an error.
            assertEquals(0x0C, cla, name + " [" + ex.description + "]: expected CLA 0x0C after merge");

            if (ex.plainCommand != null && ex.plainCommand.length >= 4) {
              Object[] parsed = VciSupport.parsePlainCommand(ex.plainCommand);
              byte ins = (Byte) parsed[0];
              byte p1 = (Byte) parsed[1];
              byte p2 = (Byte) parsed[2];
              byte[] data = (byte[]) parsed[3];
              boolean hasLe = (Boolean) parsed[4];
              byte[] wrappedCmd = VciSupport.wrapCommand(session, ins, p1, p2, data, hasLe);
              assertArrayEquals(
                  ex.command, wrappedCmd, name + " [" + ex.description + "]: re-wrapped command");
              wrapped++;
            } else {
              // Still advance command MCV / lastCla by verifying MAC via unwrap-side state only:
              // seed lastCla/Ins from the captured SM header so response counter rules match.
              session.lastCla = (byte) 0x0C;
              session.lastIns = ex.command[1];
              // Advance command MCV by extracting the full CMAC from the captured command.
              advanceCommandMcvFromCaptured(session, ex.command);
            }

            if (ex.sw == 0x9000 && ex.response != null && ex.response.length > 0) {
              VciSupport.SmResponse resp =
                  VciSupport.unwrapResponse(session, concat(ex.response, TRANSPORT_SW));
              // Transport SW is always 0x9000 for successful SM; application SW lives in tag 99.
              assertTrue(
                  resp.statusWord == 0x9000
                      || resp.statusWord == 0x6982
                      || resp.statusWord == 0x6A82
                      || resp.statusWord == 0x6A88
                      || (resp.statusWord & 0xFF00) == 0x6300,
                  name
                      + " ["
                      + ex.description
                      + "]: unexpected protected SW 0x"
                      + Integer.toHexString(resp.statusWord));
              if (ex.plainResponse != null) {
                assertArrayEquals(
                    ex.plainResponse,
                    resp.data,
                    name + " [" + ex.description + "]: decrypted response payload");
              }
              unwrapped++;
            } else if (ex.sw == 0x9000) {
              // Empty response body with transport 9000 can still carry 99/8E; try unwrap if body
              // present.
              if (ex.response != null && ex.response.length > 0) {
                VciSupport.unwrapResponse(session, concat(ex.response, TRANSPORT_SW));
                unwrapped++;
              }
            }
          }

          assertTrue(wrapped >= 2, name + ": expected to re-wrap at least 2 SM commands, did " + wrapped);
          assertTrue(
              unwrapped >= 2, name + ": expected to unwrap at least 2 SM responses, did " + unwrapped);
        });
  }

  /**
   * Verifies that secure messaging response unwrapping matches captured card-reported states at the
   * pairing-code and PIN VERIFY checkpoints.
   *
   * <p>Aligned with NIST SP 800-73-5 Part 2, Section 4.2.5 (Response Integrity) and Section 4.2.6
   * (Response with PIV Secure Messaging).
   */
  @TestFactory
  Stream<DynamicTest> smResponseChainMatchesCardReportedState() throws Exception {
    return forEachVector(
        (name, v) -> {
          VciSupport.SmSession session = sessionFromVector(v);
          JsonObject s = v.getAsJsonObject("sm_session");
          boolean sawPairing = false;
          boolean sawPin = false;
          boolean hasPairingCheckpoint =
              s.has("verify_pairing_state_after") && s.get("verify_pairing_state_after").isJsonObject();
          boolean hasPinCheckpoint =
              s.has("verify_pin_state_after") && s.get("verify_pin_state_after").isJsonObject();

          for (Exchange ex : mergeTransportChains(secureMessagingExchanges(v))) {
            session.lastCla = (byte) 0x0C;
            session.lastIns = (byte) 0x00;

            if (ex.sw != 0x9000 || ex.response == null || ex.response.length == 0) {
              continue;
            }
            VciSupport.SmResponse resp =
                VciSupport.unwrapResponse(session, concat(ex.response, TRANSPORT_SW));
            assertTrue(
                resp.statusWord == 0x9000 || resp.statusWord == 0x6982,
                name
                    + " ["
                    + ex.description
                    + "]: unexpected protected SW 0x"
                    + Integer.toHexString(resp.statusWord));
            if (resp.statusWord == 0x9000 && containsTag(ex.response, 0x87)) {
              assertTrue(
                  resp.data.length > 0,
                  name + " [" + ex.description + "]: decrypted payload should be non-empty");
            }

            if (ex.description.contains("Pairing Code") && (ex.command[1] & 0xFF) == 0x20) {
              if (hasPairingCheckpoint) {
                assertResponseState(
                    name + " after pairing verify",
                    session,
                    s.getAsJsonObject("verify_pairing_state_after"));
              }
              sawPairing = true;
            } else if (ex.description.contains("PIN") && (ex.command[1] & 0xFF) == 0x20) {
              if (hasPinCheckpoint) {
                assertResponseState(
                    name + " after PIN verify", session, s.getAsJsonObject("verify_pin_state_after"));
              }
              sawPin = true;
            }
          }

          if (hasPairingCheckpoint) {
            assertTrue(sawPairing, name + ": no wrapped pairing VERIFY exchange found");
          }
          if (hasPinCheckpoint) {
            assertTrue(sawPin, name + ": no wrapped PIN VERIFY exchange found");
          }
        });
  }

  /**
   * Verifies that secure messaging command wrapping generates byte-for-byte identical APDUs for the
   * pairing-code and PIN VERIFY commands.
   *
   * <p>Aligned with NIST SP 800-73-5 Part 2, Section 4.2.3 (Command Integrity) and Section 4.2.4
   * (Command with PIV Secure Messaging).
   */
  @TestFactory
  Stream<DynamicTest> smCommandWrapMatchesCapturedApdus() throws Exception {
    return forEachVector(
        (name, v) -> {
          JsonObject s = v.getAsJsonObject("sm_session");
          List<Exchange> exchanges = mergeTransportChains(secureMessagingExchanges(v));

          Exchange pairing =
              findExchange(
                  exchanges,
                  e -> e.description.contains("Pairing Code") && (e.command[1] & 0xFF) == 0x20);
          if (pairing != null) {
            // Pairing may not be the first SM command (some captures read CHUID first). Seed the
            // published pre-state when present; otherwise start from the session initial counter.
            VciSupport.SmSession session = sessionFromVector(v);
            if (s.has("verify_pairing_state_before")
                && s.get("verify_pairing_state_before").isJsonObject()) {
              seedState(session, s.getAsJsonObject("verify_pairing_state_before"));
            }
            // Prefer the recorded plain_command so PIN/pairing padding matches the wire exactly
            // (some CS7 captures store pin_hex without the 0xFF trailer).
            byte[] wrapped;
            if (pairing.plainCommand != null) {
              Object[] parsed = VciSupport.parsePlainCommand(pairing.plainCommand);
              wrapped =
                  VciSupport.wrapCommand(
                      session,
                      (Byte) parsed[0],
                      (Byte) parsed[1],
                      (Byte) parsed[2],
                      (byte[]) parsed[3],
                      (Boolean) parsed[4]);
            } else if (s.has("pairing_code_hex")) {
              wrapped =
                  VciSupport.wrapCommand(
                      session, (byte) 0x20, (byte) 0x00, (byte) 0x98, hex(s, "pairing_code_hex"), false);
            } else {
              wrapped = null;
            }
            if (wrapped != null) {
              assertArrayEquals(pairing.command, wrapped, name + ": wrapped pairing VERIFY");
              if (s.has("verify_pairing_state_after")) {
                assertArrayEquals(
                    hex(s.getAsJsonObject("verify_pairing_state_after"), "cmd_mcv"),
                    session.commandMcv,
                    name + ": command MCV after pairing VERIFY");
              }
            }
          }

          Exchange pin = wrappedPinVerify(exchanges);
          if (pin != null && s.has("verify_pin_state_before")) {
            VciSupport.SmSession pinSession = sessionFromVector(v);
            seedState(pinSession, s.getAsJsonObject("verify_pin_state_before"));
            byte[] wrappedPin;
            if (pin.plainCommand != null) {
              Object[] parsed = VciSupport.parsePlainCommand(pin.plainCommand);
              wrappedPin =
                  VciSupport.wrapCommand(
                      pinSession,
                      (Byte) parsed[0],
                      (Byte) parsed[1],
                      (Byte) parsed[2],
                      (byte[]) parsed[3],
                      (Boolean) parsed[4]);
            } else if (s.has("pin_hex") && s.has("pin_key_ref")) {
              byte[] pinData = hex(s, "pin_hex");
              // PIV PIN reference data is 8 bytes; pad short hex with 0xFF as ISO 7816/PIV does.
              if (pinData.length < 8) {
                byte[] padded = new byte[8];
                Arrays.fill(padded, (byte) 0xFF);
                System.arraycopy(pinData, 0, padded, 0, pinData.length);
                pinData = padded;
              }
              byte pinRef =
                  (byte) Integer.parseInt(stripHexPrefix(s.get("pin_key_ref").getAsString()), 16);
              wrappedPin =
                  VciSupport.wrapCommand(pinSession, (byte) 0x20, (byte) 0x00, pinRef, pinData, false);
            } else {
              wrappedPin = null;
            }
            if (wrappedPin != null) {
              assertArrayEquals(pin.command, wrappedPin, name + ": wrapped PIN VERIFY");
              if (s.has("verify_pin_state_after")) {
                assertArrayEquals(
                    hex(s.getAsJsonObject("verify_pin_state_after"), "cmd_mcv"),
                    pinSession.commandMcv,
                    name + ": command MCV after PIN VERIFY");
              }
            }
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
    assertTrue(vectors.size() >= 8, "expected at least 8 VCI vectors, found " + vectors.size());
    return vectors.stream()
        .map(
            path ->
                DynamicTest.dynamicTest(
                    path.getFileName().toString(),
                    () -> {
                      JsonObject v = load(path);
                      JsonObject opacity = v.getAsJsonObject("opacity");
                      String suite = opacity.get("cipher_suite_id").getAsString();
                      assertTrue(
                          "0x27".equalsIgnoreCase(suite) || "0x2E".equalsIgnoreCase(suite),
                          path.getFileName() + " has unexpected suite " + suite);
                      assertion.run(path.getFileName().toString(), v);
                    }));
  }

  private static List<Path> listVectors() throws Exception {
    Path dir = vectorDir();
    try (Stream<Path> files = Files.list(dir)) {
      return files
          .filter(p -> {
            String name = p.getFileName().toString();
            return name.startsWith("vci_") && name.endsWith(".json");
          })
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

  private static byte parseSuite(JsonObject opacity) {
    String raw = stripHexPrefix(opacity.get("cipher_suite_id").getAsString());
    return (byte) Integer.parseInt(raw, 16);
  }

  private static VciSupport.SmSession sessionFromVector(JsonObject v) {
    JsonObject s = v.getAsJsonObject("sm_session");
    JsonObject o = v.getAsJsonObject("opacity");
    VciSupport.SessionKeys keys =
        new VciSupport.SessionKeys(
            hex(o, "sk_cfrm"), hex(s, "sk_mac"), hex(s, "sk_enc"), hex(s, "sk_rmac"));
    return new VciSupport.SmSession(keys);
  }

  private static List<Exchange> allExchanges(JsonObject v) {
    List<Exchange> out = new ArrayList<>();
    JsonArray arr = v.getAsJsonArray("apdu_exchanges");
    for (JsonElement el : arr) {
      JsonObject e = el.getAsJsonObject();
      out.add(exchangeFromJson(e));
    }
    return out;
  }

  private static List<Exchange> secureMessagingExchanges(JsonObject v) {
    List<Exchange> out = new ArrayList<>();
    for (Exchange ex : allExchanges(v)) {
      int cla = ex.command[0] & 0xFF;
      if (cla == 0x0C || cla == 0x1C) {
        out.add(ex);
      }
    }
    return out;
  }

  private static Exchange exchangeFromJson(JsonObject e) {
    byte[] command = hex(e, "command");
    byte[] response =
        e.has("response") && !e.get("response").isJsonNull() && e.get("response").getAsString().length() > 0
            ? hex(e, "response")
            : new byte[0];
    int sw =
        e.has("sw")
            ? Integer.parseInt(stripHexPrefix(e.get("sw").getAsString()), 16)
            : 0x9000;
    byte[] plainCommand =
        e.has("plain_command")
                && !e.get("plain_command").isJsonNull()
                && e.get("plain_command").getAsString().length() > 0
            ? hex(e, "plain_command")
            : null;
    byte[] plainResponse =
        e.has("plain_response")
                && !e.get("plain_response").isJsonNull()
                && e.get("plain_response").getAsString().length() > 0
            ? hex(e, "plain_response")
            : null;
    return new Exchange(
        e.get("description").getAsString(), command, response, sw, plainCommand, plainResponse);
  }

  /**
   * Merges CLA {@code 1C} transport intermediates with the following CLA {@code 0C} final chunk into
   * a single logical SM command (mirrors {@code verify_vectors._merge_transport_chains}).
   */
  private static List<Exchange> mergeTransportChains(List<Exchange> exchanges) {
    List<Exchange> merged = new ArrayList<>();
    List<byte[]> pendingChunks = new ArrayList<>();

    for (Exchange ex : exchanges) {
      int cla = ex.command[0] & 0xFF;
      if (cla == 0x1C) {
        // Intermediate: buffer SM data field (short form CLA INS P1 P2 Lc Data)
        byte[] cmd = ex.command;
        int lc = cmd[4] & 0xFF;
        pendingChunks.add(Arrays.copyOfRange(cmd, 5, 5 + lc));
        continue;
      }
      if (!pendingChunks.isEmpty() && cla == 0x0C) {
        byte[] cmd = ex.command;
        byte ins = cmd[1];
        byte p1 = cmd[2];
        byte p2 = cmd[3];
        int lc;
        byte[] finalData;
        byte[] trailingLe;
        if ((cmd[4] & 0xFF) == 0x00 && cmd.length > 7) {
          lc = ((cmd[5] & 0xFF) << 8) | (cmd[6] & 0xFF);
          finalData = Arrays.copyOfRange(cmd, 7, 7 + lc);
          trailingLe = Arrays.copyOfRange(cmd, 7 + lc, cmd.length);
        } else {
          lc = cmd[4] & 0xFF;
          finalData = Arrays.copyOfRange(cmd, 5, 5 + lc);
          trailingLe = Arrays.copyOfRange(cmd, 5 + lc, cmd.length);
        }
        int total = 0;
        for (byte[] c : pendingChunks) {
          total += c.length;
        }
        total += finalData.length;
        byte[] fullPayload = new byte[total];
        int off = 0;
        for (byte[] c : pendingChunks) {
          System.arraycopy(c, 0, fullPayload, off, c.length);
          off += c.length;
        }
        System.arraycopy(finalData, 0, fullPayload, off, finalData.length);

        byte[] reassembled;
        if (fullPayload.length <= 255) {
          reassembled =
              concat(
                  new byte[] {0x0C, ins, p1, p2, (byte) fullPayload.length},
                  fullPayload,
                  trailingLe.length > 0 ? trailingLe : new byte[] {0x00});
        } else {
          // Prefer the trailing Le from the final chunk when it is already extended (2 bytes);
          // otherwise use Le=0x0100 (256), matching VciSupport.wrapCommand.
          byte[] le =
              trailingLe.length >= 2 ? trailingLe : new byte[] {0x01, 0x00};
          reassembled =
              concat(
                  new byte[] {
                    0x0C,
                    ins,
                    p1,
                    p2,
                    0x00,
                    (byte) ((fullPayload.length >> 8) & 0xFF),
                    (byte) (fullPayload.length & 0xFF)
                  },
                  fullPayload,
                  le);
        }
        String base = ex.description;
        int bracket = base.toLowerCase(Locale.ROOT).lastIndexOf(" [transport");
        if (bracket > 0) {
          base = base.substring(0, bracket);
        }
        merged.add(
            new Exchange(
                base + " (reassembled)",
                reassembled,
                ex.response,
                ex.sw,
                ex.plainCommand,
                ex.plainResponse));
        pendingChunks.clear();
      } else {
        pendingChunks.clear();
        merged.add(ex);
      }
    }
    return merged;
  }

  /**
   * Advances the command MCV from a captured SM APDU by recomputing the full C-MAC (used when
   * plain_command is absent so we cannot re-wrap).
   */
  private static void advanceCommandMcvFromCaptured(VciSupport.SmSession session, byte[] command) {
    // Re-derive via wrap is preferred; this path keeps MCV chaining correct for response-only
    // verification. We recompute the MAC input from the captured TLV field.
    int lc;
    byte[] dataField;
    if ((command[4] & 0xFF) == 0x00 && command.length > 7) {
      lc = ((command[5] & 0xFF) << 8) | (command[6] & 0xFF);
      dataField = Arrays.copyOfRange(command, 7, 7 + lc);
    } else {
      lc = command[4] & 0xFF;
      dataField = Arrays.copyOfRange(command, 5, 5 + lc);
    }

    java.io.ByteArrayOutputStream macInput = new java.io.ByteArrayOutputStream();
    macInput.write(session.commandMcv, 0, 16);
    byte[] header = new byte[16];
    header[0] = 0x0C;
    header[1] = command[1];
    header[2] = command[2];
    header[3] = command[3];
    header[4] = (byte) 0x80;
    macInput.write(header, 0, 16);

    // Include 87 and 97 TLVs (everything except 8E) in MAC order.
    int cursor = 0;
    while (cursor < dataField.length) {
      int tag = dataField[cursor] & 0xFF;
      int hdr = cursor;
      cursor++; // tag (1-byte tags only in SM data field)
      int lengthByte = dataField[cursor++] & 0xFF;
      int length;
      if (lengthByte < 0x80) {
        length = lengthByte;
      } else if (lengthByte == 0x81) {
        length = dataField[cursor++] & 0xFF;
      } else if (lengthByte == 0x82) {
        length = ((dataField[cursor++] & 0xFF) << 8) | (dataField[cursor++] & 0xFF);
      } else {
        throw new IllegalStateException("Unsupported TLV length in SM command");
      }
      int next = cursor + length;
      if (tag == 0x87 || tag == 0x97) {
        macInput.write(dataField, hdr, next - hdr);
      }
      cursor = next;
    }
    byte[] fullMac = VciSupport.aesCmac(session.skMac, macInput.toByteArray());
    System.arraycopy(fullMac, 0, session.commandMcv, 0, 16);
  }

  private static Exchange findExchange(
      List<Exchange> exchanges, java.util.function.Predicate<Exchange> pred) {
    return exchanges.stream().filter(pred).findFirst().orElse(null);
  }

  private static Exchange wrappedPinVerify(List<Exchange> exchanges) {
    return exchanges.stream()
        .filter(e -> e.description.contains("PIN") && (e.command[1] & 0xFF) == 0x20)
        .reduce((first, second) -> second)
        .orElse(null);
  }

  private static void assertResponseState(
      String context, VciSupport.SmSession session, JsonObject state) {
    assertArrayEquals(hex(state, "counter"), session.encCounter, context + ": counter");
    assertArrayEquals(hex(state, "resp_mcv"), session.responseMcv, context + ": response MCV");
  }

  private static void seedState(VciSupport.SmSession session, JsonObject state) {
    System.arraycopy(hex(state, "counter"), 0, session.encCounter, 0, 16);
    System.arraycopy(hex(state, "cmd_mcv"), 0, session.commandMcv, 0, 16);
    System.arraycopy(hex(state, "resp_mcv"), 0, session.responseMcv, 0, 16);
  }

  private static byte[] buildKdfInput(int counter, byte[] sharedSecret, byte[] otherInfo) {
    byte[] input = new byte[4 + sharedSecret.length + otherInfo.length];
    input[0] = (byte) ((counter >> 24) & 0xFF);
    input[1] = (byte) ((counter >> 16) & 0xFF);
    input[2] = (byte) ((counter >> 8) & 0xFF);
    input[3] = (byte) (counter & 0xFF);
    System.arraycopy(sharedSecret, 0, input, 4, sharedSecret.length);
    System.arraycopy(otherInfo, 0, input, 4 + sharedSecret.length, otherInfo.length);
    return input;
  }

  private static byte[] hex(JsonObject obj, String field) {
    return Hex.decode(stripHexPrefix(obj.get(field).getAsString()));
  }

  private static String stripHexPrefix(String value) {
    return value.startsWith("0x") || value.startsWith("0X") ? value.substring(2) : value;
  }

  private static boolean containsTag(byte[] data, int tag) {
    int cursor = 0;
    while (cursor < data.length) {
      int t = data[cursor++] & 0xFF;
      if (cursor >= data.length) {
        return false;
      }
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
    final byte[] plainCommand;
    final byte[] plainResponse;

    Exchange(
        String description,
        byte[] command,
        byte[] response,
        int sw,
        byte[] plainCommand,
        byte[] plainResponse) {
      this.description = description;
      this.command = command;
      this.response = response;
      this.sw = sw;
      this.plainCommand = plainCommand;
      this.plainResponse = plainResponse;
    }
  }
}
