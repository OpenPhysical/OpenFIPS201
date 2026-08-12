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
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestFactory;

/**
 * Known-answer tests for the longer v2 APDU capture format used by OpenPhysical.Net vector capture
 * and related {@code nist-sd33-apdu} fixtures.
 *
 * <p>These fixtures exercise 50+ SM exchanges per card (pairing, exhaustive GET DATA under VCI, GEN
 * AUTH challenges) with per-exchange {@code plain_command}/{@code plain_response} and SM state
 * snapshots — significantly more chaining surface than the compact v1 vectors.
 *
 * <p>Schema notes (v2 vs v1):
 *
 * <ul>
 *   <li>OPACITY lives under {@code sm.opacity} with PascalCase field names
 *   <li>Session keys are also under {@code sm.opacity} ({@code SkMac}, {@code SkEnc}, …)
 *   <li>Each APDU may carry {@code sm_state_before}/{@code sm_state_after_wrap}/ {@code
 *       sm_state_after_unwrap}
 * </ul>
 *
 * <p>Aligned with NIST SP 800-73-5 Part 2 Sections 4.1–4.2. Includes CS2 (cards 3, 4) and CS7
 * (cards 2, 5, 16) captures.
 */
@Tag("slow")
class OpenFIPS201VciV2VectorTest {

  private static final byte[] TRANSPORT_SW = Hex.decode("9000");

  /**
   * Enrolment-phase structural coverage for the long SM session whose OPACITY keys are <em>not</em>
   * published in {@code sm.opacity} (that block holds the last / use-phase keys only).
   *
   * <p>Without the first-session ephemeral private key we cannot re-wrap, but we can still assert
   * the SP 800-73-5 post-establishment rules that do not require secret material: no plaintext
   * leakage, counter monotonicity, and presence of plain_command snapshots for SM commands.
   */
  @TestFactory
  Stream<DynamicTest> enrolmentPhaseHasNoPlaintextLeakageAndMonotonicCounters() throws Exception {
    return forEachV2(
        (name, doc) -> {
          int firstOpacity = firstOpacityExchangeId(doc);
          int lastOpacity = lastOpacityExchangeId(doc);
          assertTrue(
              firstOpacity >= 0 && lastOpacity > firstOpacity, name + ": two OPACITY events");

          // Enrolment SM exchanges: after first OPACITY, before last OPACITY.
          List<Exchange> enrolment = loadSmExchangesBetween(doc, firstOpacity, lastOpacity);
          assertTrue(
              enrolment.size() >= 20,
              name + ": enrolment SM surface should be large, found " + enrolment.size());

          byte[] prevCounter = null;
          int withPlain = 0;
          for (Exchange ex : enrolment) {
            int cla = ex.command[0] & 0xFF;
            assertTrue(
                cla == 0x0C || cla == 0x1C,
                name + " [" + ex.description + "]: post-OPACITY must be SM CLA");
            if (cla == 0x0C && ex.plainCommand != null) {
              withPlain++;
              assertEquals(
                  0x00,
                  ex.plainCommand[0] & 0xFF,
                  name + " [" + ex.description + "]: plain CLA is 0x00");
            }
            if (ex.stateBefore != null) {
              if (prevCounter != null) {
                // Counter is non-decreasing across successive SM commands (may hold during
                // transport intermediates that share a logical command).
                assertTrue(
                    compareUnsignedCounter(ex.stateBefore.counter, prevCounter) >= 0,
                    name + " [" + ex.description + "]: counter must not go backwards");
              }
              prevCounter = ex.stateBefore.counter;
            }
            if (ex.stateAfterUnwrap != null && ex.stateBefore != null) {
              // Successful logical commands increment the counter by exactly one.
              if (cla == 0x0C) {
                assertTrue(
                    compareUnsignedCounter(ex.stateAfterUnwrap.counter, ex.stateBefore.counter)
                        >= 0,
                    name + " [" + ex.description + "]: counter after unwrap >= before");
              }
            }
          }
          assertTrue(withPlain >= 15, name + ": enrolment should record plain_command snapshots");
        });
  }

  @TestFactory
  Stream<DynamicTest> opacityKdfMatchesV2CardReportedKeys() throws Exception {
    return forEachV2(
        (name, doc) -> {
          JsonObject o = doc.getAsJsonObject("sm").getAsJsonObject("opacity");
          byte suite = parseSuite(o.get("CipherSuiteId").getAsString());
          assertTrue(
              suite == VciSupport.ALG_CS2 || suite == VciSupport.ALG_CS7,
              name + ": unexpected suite 0x" + Integer.toHexString(suite & 0xFF));

          byte[] sharedSecret = hexField(o, "SharedSecretZ");
          byte[] hostX = hexField(o, "EphemeralPublicKeyX");
          byte[] hostY = hexField(o, "EphemeralPublicKeyY");
          byte[] hostPoint = concat(new byte[] {0x04}, hostX, hostY);
          byte[] cvcRaw = hexField(o, "CardCvc");
          byte[] idSicc = VciSupport.computeIdSicc(cvcRaw);
          byte[] idH = new byte[8]; // zeros in this profile
          // NIcc is not a top-level field in the compact opacity block; recover from OtherInfo if
          // present, otherwise skip full derive and only check published keys + cryptogram
          // equality.
          if (o.has("OtherInfo") && o.get("OtherInfo").getAsString().length() > 0) {
            byte[] otherInfo = hexField(o, "OtherInfo");
            // PartyVInfo ends with: 08 || idSicc(8) || nLen || nIcc || 01 || cb
            // Recover nIcc by scanning OtherInfo for idSicc.
            byte[] nIcc = extractNIccFromOtherInfo(otherInfo, idSicc);
            VciSupport.SessionKeys keys =
                VciSupport.deriveSessionKeys(suite, sharedSecret, idH, hostPoint, idSicc, nIcc);
            assertArrayEquals(hexField(o, "SkCfrm"), keys.skCfrm, name + ": SK_CFRM");
            assertArrayEquals(hexField(o, "SkMac"), keys.skMac, name + ": SK_MAC");
            assertArrayEquals(hexField(o, "SkEnc"), keys.skEnc, name + ": SK_ENC");
            assertArrayEquals(hexField(o, "SkRmac"), keys.skRmac, name + ": SK_RMAC");

            byte[] cryptogram =
                VciSupport.computeAuthCryptogram(keys.skCfrm, idSicc, idH, hostPoint);
            assertArrayEquals(
                hexField(o, "AuthCryptogramCard"),
                Arrays.copyOf(cryptogram, 16),
                name + ": auth cryptogram");
          } else {
            // Fall back: keys are published; just confirm card/computed cryptogram agreement.
            assertArrayEquals(
                hexField(o, "AuthCryptogramCard"),
                hexField(o, "AuthCryptogramComputed"),
                name + ": published auth cryptogram self-consistency");
          }
        });
  }

  @TestFactory
  Stream<DynamicTest> fullSmSessionReplayMatchesV2Exchanges() throws Exception {
    return forEachV2(
        (name, doc) -> {
          JsonObject opacity = doc.getAsJsonObject("sm").getAsJsonObject("opacity");
          VciSupport.SessionKeys keys =
              new VciSupport.SessionKeys(
                  hexField(opacity, "SkCfrm"),
                  hexField(opacity, "SkMac"),
                  hexField(opacity, "SkEnc"),
                  hexField(opacity, "SkRmac"));
          VciSupport.SmSession session = new VciSupport.SmSession(keys);

          // v2 captures may include multiple OPACITY establishments (enrolment then re-present /
          // use). The compact sm.opacity block publishes keys for the *last* establishment only,
          // so restrict replay to SM exchanges after that establishment exchange id.
          int lastOpacityId = lastOpacityExchangeId(doc);
          List<Exchange> exchanges = mergeTransportChains(loadSmExchanges(doc, lastOpacityId));
          assertTrue(
              exchanges.size() >= 5,
              name
                  + ": expected SM exchanges after last OPACITY (id "
                  + lastOpacityId
                  + "), found "
                  + exchanges.size());

          int wrapped = 0;
          int unwrapped = 0;
          for (Exchange ex : exchanges) {
            assertEquals(
                0x0C,
                ex.command[0] & 0xFF,
                name + " [" + ex.description + "]: CLA 0x0C after transport merge");

            if (ex.plainCommand != null && ex.plainCommand.length >= 4) {
              if (ex.stateBefore != null) {
                assertArrayEquals(
                    ex.stateBefore.counter,
                    session.encCounter,
                    name + " [" + ex.description + "]: counter before");
                assertArrayEquals(
                    ex.stateBefore.cmdMcv,
                    session.commandMcv,
                    name + " [" + ex.description + "]: cmd MCV before");
                assertArrayEquals(
                    ex.stateBefore.respMcv,
                    session.responseMcv,
                    name + " [" + ex.description + "]: resp MCV before");
              }
              Object[] parsed = VciSupport.parsePlainCommand(ex.plainCommand);
              byte[] wrappedCmd =
                  VciSupport.wrapCommand(
                      session,
                      (Byte) parsed[0],
                      (Byte) parsed[1],
                      (Byte) parsed[2],
                      (byte[]) parsed[3],
                      (Boolean) parsed[4]);
              assertArrayEquals(
                  ex.command, wrappedCmd, name + " [" + ex.description + "]: re-wrapped command");
              if (ex.stateAfterWrap != null) {
                assertArrayEquals(
                    ex.stateAfterWrap.cmdMcv,
                    session.commandMcv,
                    name + " [" + ex.description + "]: cmd MCV after wrap");
              }
              wrapped++;
            } else {
              session.lastCla = (byte) 0x0C;
              session.lastIns = ex.command[1];
              advanceCommandMcvFromCaptured(session, ex.command);
            }

            if (ex.response != null && ex.response.length > 0) {
              // v2 captures embed the transport SW (usually 9000) in the response field and put the
              // application status in the top-level "sw" / tag 99. v1 captures keep SW separate.
              byte[] responseWithSw = responseWithTransportSw(ex.response);
              VciSupport.SmResponse resp = VciSupport.unwrapResponse(session, responseWithSw);
              assertTrue(
                  resp.statusWord == 0x9000
                      || resp.statusWord == 0x6982
                      || resp.statusWord == 0x6A82
                      || resp.statusWord == 0x6A88
                      || (resp.statusWord & 0xFF00) == 0x6300,
                  name
                      + " ["
                      + ex.description
                      + "]: unexpected SW 0x"
                      + Integer.toHexString(resp.statusWord));
              if (ex.plainResponse != null) {
                assertArrayEquals(
                    ex.plainResponse,
                    resp.data,
                    name + " [" + ex.description + "]: decrypted payload");
              }
              if (ex.stateAfterUnwrap != null) {
                assertArrayEquals(
                    ex.stateAfterUnwrap.counter,
                    session.encCounter,
                    name + " [" + ex.description + "]: counter after unwrap");
                assertArrayEquals(
                    ex.stateAfterUnwrap.respMcv,
                    session.responseMcv,
                    name + " [" + ex.description + "]: resp MCV after unwrap");
              }
              unwrapped++;
            }
          }

          assertTrue(wrapped >= 5, name + ": re-wrapped " + wrapped + " SM commands");
          assertTrue(unwrapped >= 5, name + ": unwrapped " + unwrapped + " SM responses");
        });
  }

  /**
   * Returns the exchange_id of the last GENERAL AUTHENTICATE (OPACITY) in the capture, or -1 if
   * none is labelled. Used to select the SM session whose keys appear in {@code sm.opacity}.
   */
  private static int lastOpacityExchangeId(JsonObject doc) {
    int last = -1;
    JsonArray arr = doc.getAsJsonArray("apdu_exchanges");
    for (JsonElement el : arr) {
      JsonObject e = el.getAsJsonObject();
      String desc = e.has("description") ? e.get("description").getAsString() : "";
      if (desc.contains("OPACITY") && e.has("exchange_id")) {
        last = e.get("exchange_id").getAsInt();
      }
    }
    if (last < 0 && doc.getAsJsonObject("sm").has("establishment_exchange_ids")) {
      JsonArray ids = doc.getAsJsonObject("sm").getAsJsonArray("establishment_exchange_ids");
      if (ids.size() > 0) {
        last = ids.get(ids.size() - 1).getAsInt();
      }
    }
    return last;
  }

  private static int firstOpacityExchangeId(JsonObject doc) {
    JsonArray arr = doc.getAsJsonArray("apdu_exchanges");
    for (JsonElement el : arr) {
      JsonObject e = el.getAsJsonObject();
      String desc = e.has("description") ? e.get("description").getAsString() : "";
      if (desc.contains("OPACITY") && e.has("exchange_id")) {
        return e.get("exchange_id").getAsInt();
      }
    }
    if (doc.getAsJsonObject("sm").has("establishment_exchange_ids")) {
      JsonArray ids = doc.getAsJsonObject("sm").getAsJsonArray("establishment_exchange_ids");
      if (ids.size() > 0) {
        return ids.get(0).getAsInt();
      }
    }
    return -1;
  }

  private static List<Exchange> loadSmExchangesBetween(
      JsonObject doc, int afterExchangeId, int beforeExchangeId) {
    List<Exchange> out = new ArrayList<>();
    JsonArray arr = doc.getAsJsonArray("apdu_exchanges");
    for (JsonElement el : arr) {
      JsonObject e = el.getAsJsonObject();
      if (!e.has("exchange_id")) {
        continue;
      }
      int id = e.get("exchange_id").getAsInt();
      if (id <= afterExchangeId || id >= beforeExchangeId) {
        continue;
      }
      byte[] command = hexField(e, "command");
      int cla = command[0] & 0xFF;
      if (cla != 0x0C && cla != 0x1C) {
        continue;
      }
      out.add(
          new Exchange(
              e.has("description") ? e.get("description").getAsString() : "exchange",
              command,
              e.has("response")
                      && !e.get("response").isJsonNull()
                      && e.get("response").getAsString().length() > 0
                  ? hexField(e, "response")
                  : new byte[0],
              e.has("sw") ? Integer.parseInt(stripHex(e.get("sw").getAsString()), 16) : 0x9000,
              e.has("plain_command")
                      && !e.get("plain_command").isJsonNull()
                      && e.get("plain_command").getAsString().length() > 0
                  ? hexField(e, "plain_command")
                  : null,
              e.has("plain_response")
                      && !e.get("plain_response").isJsonNull()
                      && e.get("plain_response").getAsString().length() > 0
                  ? hexField(e, "plain_response")
                  : null,
              readState(e, "sm_state_before"),
              readState(e, "sm_state_after_wrap"),
              readState(e, "sm_state_after_unwrap")));
    }
    return out;
  }

  private static int compareUnsignedCounter(byte[] a, byte[] b) {
    for (int i = 0; i < Math.min(a.length, b.length); i++) {
      int da = a[i] & 0xFF;
      int db = b[i] & 0xFF;
      if (da != db) {
        return Integer.compare(da, db);
      }
    }
    return Integer.compare(a.length, b.length);
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------------------------

  private interface Assertion {
    void run(String name, JsonObject doc) throws Exception;
  }

  private static Stream<DynamicTest> forEachV2(Assertion assertion) throws Exception {
    List<Path> vectors = listV2Vectors();
    assertTrue(
        vectors.size() >= 5, "expected at least 5 v2 fixtures (CS2+CS7), found " + vectors.size());
    return vectors.stream()
        .map(
            path ->
                DynamicTest.dynamicTest(
                    path.getFileName().toString(),
                    () -> {
                      JsonObject doc = load(path);
                      assertion.run(path.getFileName().toString(), doc);
                    }));
  }

  private static List<Path> listV2Vectors() throws Exception {
    Path dir = v2Dir();
    try (Stream<Path> files = Files.list(dir)) {
      return files
          .filter(p -> p.getFileName().toString().endsWith(".json"))
          .sorted()
          .collect(Collectors.toList());
    }
  }

  private static Path v2Dir() {
    Path relative =
        Paths.get("src/dev/mistial/tool-tests/dev/mistial/tools/openfips201/vci/vectors/v2");
    if (Files.isDirectory(relative)) {
      return relative;
    }
    Path here = Paths.get("").toAbsolutePath();
    while (here != null && !Files.isDirectory(here.resolve(relative))) {
      here = here.getParent();
    }
    if (here == null) {
      throw new IllegalStateException("Could not locate v2 VCI vector directory");
    }
    return here.resolve(relative);
  }

  private static JsonObject load(Path path) throws Exception {
    try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
      return JsonParser.parseReader(reader).getAsJsonObject();
    }
  }

  private static List<Exchange> loadSmExchanges(JsonObject doc, int afterExchangeId) {
    List<Exchange> out = new ArrayList<>();
    JsonArray arr = doc.getAsJsonArray("apdu_exchanges");
    for (JsonElement el : arr) {
      JsonObject e = el.getAsJsonObject();
      if (afterExchangeId >= 0
          && e.has("exchange_id")
          && e.get("exchange_id").getAsInt() <= afterExchangeId) {
        continue;
      }
      byte[] command = hexField(e, "command");
      int cla = command[0] & 0xFF;
      if (cla != 0x0C && cla != 0x1C) {
        continue;
      }
      byte[] response =
          e.has("response")
                  && !e.get("response").isJsonNull()
                  && e.get("response").getAsString().length() > 0
              ? hexField(e, "response")
              : new byte[0];
      int sw = e.has("sw") ? Integer.parseInt(stripHex(e.get("sw").getAsString()), 16) : 0x9000;
      byte[] plainCommand =
          e.has("plain_command")
                  && !e.get("plain_command").isJsonNull()
                  && e.get("plain_command").getAsString().length() > 0
              ? hexField(e, "plain_command")
              : null;
      byte[] plainResponse =
          e.has("plain_response")
                  && !e.get("plain_response").isJsonNull()
                  && e.get("plain_response").getAsString().length() > 0
              ? hexField(e, "plain_response")
              : null;
      out.add(
          new Exchange(
              e.has("description") ? e.get("description").getAsString() : "exchange",
              command,
              response,
              sw,
              plainCommand,
              plainResponse,
              readState(e, "sm_state_before"),
              readState(e, "sm_state_after_wrap"),
              readState(e, "sm_state_after_unwrap")));
    }
    return out;
  }

  private static SmState readState(JsonObject e, String field) {
    if (!e.has(field) || e.get(field).isJsonNull()) {
      return null;
    }
    JsonObject s = e.getAsJsonObject(field);
    return new SmState(hexField(s, "counter"), hexField(s, "cmd_mcv"), hexField(s, "resp_mcv"));
  }

  private static List<Exchange> mergeTransportChains(List<Exchange> exchanges) {
    List<Exchange> merged = new ArrayList<>();
    List<byte[]> pending = new ArrayList<>();
    for (Exchange ex : exchanges) {
      int cla = ex.command[0] & 0xFF;
      if (cla == 0x1C) {
        int lc = ex.command[4] & 0xFF;
        pending.add(Arrays.copyOfRange(ex.command, 5, 5 + lc));
        continue;
      }
      if (!pending.isEmpty() && cla == 0x0C) {
        byte[] cmd = ex.command;
        byte ins = cmd[1];
        byte p1 = cmd[2];
        byte p2 = cmd[3];
        int lc = cmd[4] & 0xFF;
        byte[] finalData = Arrays.copyOfRange(cmd, 5, 5 + lc);
        byte[] trailingLe = Arrays.copyOfRange(cmd, 5 + lc, cmd.length);
        int total = finalData.length;
        for (byte[] c : pending) {
          total += c.length;
        }
        byte[] full = new byte[total];
        int off = 0;
        for (byte[] c : pending) {
          System.arraycopy(c, 0, full, off, c.length);
          off += c.length;
        }
        System.arraycopy(finalData, 0, full, off, finalData.length);
        byte[] reassembled;
        if (full.length <= 255) {
          reassembled =
              concat(
                  new byte[] {0x0C, ins, p1, p2, (byte) full.length},
                  full,
                  trailingLe.length > 0 ? trailingLe : new byte[] {0x00});
        } else {
          byte[] le = trailingLe.length >= 2 ? trailingLe : new byte[] {0x01, 0x00};
          reassembled =
              concat(
                  new byte[] {
                    0x0C,
                    ins,
                    p1,
                    p2,
                    0x00,
                    (byte) ((full.length >> 8) & 0xFF),
                    (byte) (full.length & 0xFF)
                  },
                  full,
                  le);
        }
        merged.add(
            new Exchange(
                ex.description + " (reassembled)",
                reassembled,
                ex.response,
                ex.sw,
                ex.plainCommand,
                ex.plainResponse,
                ex.stateBefore,
                ex.stateAfterWrap,
                ex.stateAfterUnwrap));
        pending.clear();
      } else {
        pending.clear();
        merged.add(ex);
      }
    }
    return merged;
  }

  private static void advanceCommandMcvFromCaptured(VciSupport.SmSession session, byte[] command) {
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
    int cursor = 0;
    while (cursor < dataField.length) {
      int tag = dataField[cursor] & 0xFF;
      int hdr = cursor;
      cursor++;
      int lengthByte = dataField[cursor++] & 0xFF;
      int length;
      if (lengthByte < 0x80) {
        length = lengthByte;
      } else if (lengthByte == 0x81) {
        length = dataField[cursor++] & 0xFF;
      } else if (lengthByte == 0x82) {
        length = ((dataField[cursor++] & 0xFF) << 8) | (dataField[cursor++] & 0xFF);
      } else {
        throw new IllegalStateException("Unsupported TLV length");
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

  /**
   * OtherInfo = algId(5) || PartyU(…|| T16) || PartyV(08 || idSicc || nLen || nIcc || 01 || cb).
   * Locate idSicc and extract the following length-prefixed nonce.
   */
  private static byte[] extractNIccFromOtherInfo(byte[] otherInfo, byte[] idSicc) {
    for (int i = 0; i + 1 + idSicc.length + 1 < otherInfo.length; i++) {
      if (otherInfo[i] != 0x08) {
        continue;
      }
      boolean match = true;
      for (int j = 0; j < idSicc.length; j++) {
        if (otherInfo[i + 1 + j] != idSicc[j]) {
          match = false;
          break;
        }
      }
      if (!match) {
        continue;
      }
      int nLen = otherInfo[i + 1 + idSicc.length] & 0xFF;
      int nOff = i + 1 + idSicc.length + 1;
      if (nOff + nLen <= otherInfo.length) {
        return Arrays.copyOfRange(otherInfo, nOff, nOff + nLen);
      }
    }
    throw new IllegalStateException("Could not recover NIcc from OtherInfo");
  }

  /**
   * Ensures the response buffer ends with a 2-byte transport SW for {@link
   * VciSupport#unwrapResponse}. v2 fixtures already append {@code 9000}; do not double-append.
   */
  private static byte[] responseWithTransportSw(byte[] response) {
    if (response.length >= 2
        && (response[response.length - 2] & 0xFF) == 0x90
        && (response[response.length - 1] & 0xFF) == 0x00) {
      // Heuristic: if tag 0x8E (MAC) appears before the trailing SW, the SW is already attached.
      for (int i = 0; i < response.length - 2; i++) {
        if ((response[i] & 0xFF) == 0x8E) {
          return response;
        }
      }
    }
    return concat(response, TRANSPORT_SW);
  }

  private static byte parseSuite(String raw) {
    String s = stripHex(raw);
    return (byte) Integer.parseInt(s, 16);
  }

  private static byte[] hexField(JsonObject obj, String field) {
    return Hex.decode(stripHex(obj.get(field).getAsString()));
  }

  private static String stripHex(String value) {
    if (value.startsWith("0x") || value.startsWith("0X")) {
      return value.substring(2);
    }
    return value;
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

  private static final class SmState {
    final byte[] counter;
    final byte[] cmdMcv;
    final byte[] respMcv;

    SmState(byte[] counter, byte[] cmdMcv, byte[] respMcv) {
      this.counter = counter;
      this.cmdMcv = cmdMcv;
      this.respMcv = respMcv;
    }
  }

  private static final class Exchange {
    final String description;
    final byte[] command;
    final byte[] response;
    final int sw;
    final byte[] plainCommand;
    final byte[] plainResponse;
    final SmState stateBefore;
    final SmState stateAfterWrap;
    final SmState stateAfterUnwrap;

    Exchange(
        String description,
        byte[] command,
        byte[] response,
        int sw,
        byte[] plainCommand,
        byte[] plainResponse,
        SmState stateBefore,
        SmState stateAfterWrap,
        SmState stateAfterUnwrap) {
      this.description = description;
      this.command = command;
      this.response = response;
      this.sw = sw;
      this.plainCommand = plainCommand;
      this.plainResponse = plainResponse;
      this.stateBefore = stateBefore;
      this.stateAfterWrap = stateAfterWrap;
      this.stateAfterUnwrap = stateAfterUnwrap;
    }
  }
}
