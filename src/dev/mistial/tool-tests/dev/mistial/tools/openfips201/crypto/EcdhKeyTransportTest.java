/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import dev.mistial.tools.openfips201.common.HexUtil;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;

/** {@link EcdhKeyTransport} against {@code test-vectors/sam/host-keytransport.json}. */
class EcdhKeyTransportTest {
  static JsonObject vectors() throws Exception {
    Path path =
        Paths.get(
            System.getProperty("openfips201.testVectors", "test-vectors"),
            "sam",
            "host-keytransport.json");
    JsonObject root =
        JsonParser.parseString(new String(Files.readAllBytes(path), StandardCharsets.UTF_8))
            .getAsJsonObject();
    assertEquals("openphysical.host-keytransport-vectors/1", root.get("schema").getAsString());
    return root;
  }

  @Test
  void rfc3394Section46() throws Exception {
    JsonObject v = vectors().getAsJsonObject("rfc3394");
    byte[] kek = hex(v, "kekHex");
    byte[] wrapped = EcdhKeyTransport.wrap(kek, hex(v, "keyHex"));
    assertArrayEquals(hex(v, "wrappedHex"), wrapped);
    assertArrayEquals(hex(v, "keyHex"), EcdhKeyTransport.unwrap(kek, wrapped));
    wrapped[5] ^= 1;
    assertThrows(IllegalArgumentException.class, () -> EcdhKeyTransport.unwrap(kek, wrapped));
  }

  @Test
  void samTransportHandoffAndBackupCases() throws Exception {
    JsonObject root = vectors();
    int cases = 0;
    for (String set : new String[] {"samTransport", "handoff", "backup"}) {
      for (JsonElement element : root.getAsJsonArray(set)) {
        JsonObject v = element.getAsJsonObject();
        BigInteger recipient = new BigInteger(1, hex(v, "recipientPrivHex"));
        BigInteger ephemeral = new BigInteger(1, hex(v, "ephemeralPrivHex"));
        byte[] recipientPub = hex(v, "recipientPubHex");
        byte[] ephemeralPub = hex(v, "ephemeralPubHex");
        assertArrayEquals(recipientPub, EcdhKeyTransport.publicPoint(recipient));
        assertArrayEquals(ephemeralPub, EcdhKeyTransport.publicPoint(ephemeral));
        byte[] sharedInfo;
        if ("samTransport".equals(set)) {
          sharedInfo =
              EcdhKeyTransport.samTransportSharedInfo(
                  recipientPub, ephemeralPub, v.get("iin").getAsInt());
        } else if ("handoff".equals(set)) {
          sharedInfo =
              EcdhKeyTransport.handoffSharedInfo(hex(v, "samIdHex"), hex(v, "stationSkiHex"));
        } else {
          sharedInfo = EcdhKeyTransport.backupSharedInfo(recipientPub, v.get("iin").getAsInt());
        }
        assertArrayEquals(hex(v, "sharedInfoHex"), sharedInfo, set);
        byte[] z = EcdhKeyTransport.ecdh(ephemeral, recipientPub);
        assertArrayEquals(hex(v, "zHex"), z);
        assertArrayEquals(z, EcdhKeyTransport.ecdh(recipient, ephemeralPub));
        assertArrayEquals(hex(v, "kekHex"), EcdhKeyTransport.x963Sha256(z, sharedInfo));
        byte[] wrapped =
            EcdhKeyTransport.wrapWith(ephemeral, recipientPub, hex(v, "keyHex"), sharedInfo);
        assertArrayEquals(hex(v, "wrappedHex"), wrapped);
        assertArrayEquals(
            hex(v, "keyHex"),
            EcdhKeyTransport.unwrapFrom(recipient, ephemeralPub, wrapped, sharedInfo));
        cases++;
      }
    }
    assertEquals(4, cases);
  }

  @Test
  void invalidPointsAreRefused() {
    byte[] offCurve = new byte[65];
    offCurve[0] = 0x04;
    offCurve[64] = 1;
    assertThrows(IllegalArgumentException.class, () -> EcdhKeyTransport.requireP256Point(offCurve));
    assertThrows(
        IllegalArgumentException.class, () -> EcdhKeyTransport.requireP256Point(new byte[33]));
    assertThrows(IllegalArgumentException.class, () -> EcdhKeyTransport.iinAscii(10000));
  }

  private static byte[] hex(JsonObject v, String name) {
    return HexUtil.parse(v.get(name).getAsString());
  }
}
