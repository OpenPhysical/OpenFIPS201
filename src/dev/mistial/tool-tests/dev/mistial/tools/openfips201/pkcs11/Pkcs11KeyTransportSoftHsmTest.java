/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.SecureFiles;
import dev.mistial.tools.openfips201.crypto.EcdhKeyTransport;
import dev.mistial.tools.openfips201.opid.OpidCipher;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Token key transport ({@link Pkcs11KeyTransport}), the IIN FF1 key and CKO_DATA objects against
 * SoftHSM2, cross-checked with the independent vectors and the software reference.
 */
@Tag("softhsm")
class Pkcs11KeyTransportSoftHsmTest {
  private static final byte[] USER_PIN = "kt-user-pin-1".getBytes(StandardCharsets.US_ASCII);

  @TempDir Path temp;

  private Pkcs11Config config;

  @BeforeEach
  void initializeToken() throws Exception {
    SoftHsmFixture.requireSoftHsm();
    config = SoftHsmFixture.config(SoftHsmFixture.uniqueLabel("kt-"));
    Pkcs11AdminService.initializeToken(
        config, "kt-so-pin-00000".getBytes(StandardCharsets.US_ASCII), USER_PIN.clone());
    config.pinFile = SecureFiles.writeNew(temp.resolve("pin"), USER_PIN).toString();
  }

  @Test
  void wrapForSamReproducesTheIndependentVector() throws Exception {
    JsonObject v = vectors().getAsJsonArray("samTransport").get(0).getAsJsonObject();
    byte[] key = hex(v, "keyHex");
    int iin = v.get("iin").getAsInt();
    try (Pkcs11Session session = Pkcs11Session.open(config)) {
      String label =
          new Pkcs11AdminService()
              .importIinFpeKey(session, "vec", iin, key, OpidCipher.of(key).kcv())
              .label;
      Pkcs11KeyTransport transport = new Pkcs11KeyTransport(session, true);
      Pkcs11KeyTransport.Wrapped wrapped =
          transport.wrapForSamWithEphemeral(
              hex(v, "ephemeralPrivHex"),
              hex(v, "ephemeralPubHex"),
              label,
              hex(v, "recipientPubHex"),
              iin);
      assertArrayEquals(hex(v, "wrappedHex"), wrapped.wrappedKey);
      assertArrayEquals(hex(v, "ephemeralPubHex"), wrapped.ephemeralPublicKey);
      System.out.println("SoftHSM key transport KDF path: " + wrapped.kdfPath);
    }
  }

  @Test
  void tokenWrapMatchesEverySamKatAndUnwrapsWithTheSamReference() throws Exception {
    Path path =
        Paths.get(
            System.getProperty("openfips201.testVectors", "test-vectors"), "sam", "transport.json");
    JsonObject kat =
        JsonParser.parseString(new String(Files.readAllBytes(path), StandardCharsets.UTF_8))
            .getAsJsonObject();
    int cases = 0;
    try (Pkcs11Session session = Pkcs11Session.open(config)) {
      Pkcs11KeyTransport transport = new Pkcs11KeyTransport(session, true);
      for (com.google.gson.JsonElement element : kat.getAsJsonArray("endToEnd")) {
        JsonObject v = element.getAsJsonObject();
        byte[] key = hex(v, "fpeKeyHex");
        int iin = v.get("iin").getAsInt();
        String label =
            new Pkcs11AdminService()
                .importIinFpeKey(session, "sam" + cases, iin, key, OpidCipher.of(key).kcv())
                .label;
        byte[] samPub = hex(v, "transportPubHex");
        Pkcs11KeyTransport.Wrapped fixed =
            transport.wrapForSamWithEphemeral(
                hex(v, "hostEphPrivHex"), hex(v, "hostEphPubHex"), label, samPub, iin);
        assertArrayEquals(hex(v, "wrappedHex"), fixed.wrappedKey, "case " + cases);

        // A fresh token ephemeral must unwrap with the SAM-side reference (transport private key).
        Pkcs11KeyTransport.Wrapped fresh = transport.wrapForSam(label, samPub, iin);
        BigInteger samPriv = new BigInteger(1, hex(v, "transportPrivHex"));
        assertArrayEquals(
            key,
            EcdhKeyTransport.unwrapFrom(
                samPriv,
                fresh.ephemeralPublicKey,
                fresh.wrappedKey,
                EcdhKeyTransport.samTransportSharedInfo(samPub, fresh.ephemeralPublicKey, iin)));
        cases++;
      }
    }
    assertEquals(3, cases);
  }

  @Test
  void wrapForSamWithAFreshEphemeralUnwrapsAtTheSam() throws Exception {
    BigInteger samPriv = new BigInteger(255, new SecureRandom()).add(BigInteger.ONE);
    byte[] samPub = EcdhKeyTransport.publicPoint(samPriv);
    try (Pkcs11Session session = Pkcs11Session.open(config)) {
      Pkcs11AdminService.IinFpeKey fpe =
          new Pkcs11AdminService().ensureIinFpeKey(session, "p", 1234);
      Pkcs11KeyTransport.Wrapped wrapped =
          new Pkcs11KeyTransport(session, true).wrapForSam(fpe.label, samPub, 1234);
      assertEquals(40, wrapped.wrappedKey.length);
      byte[] sharedInfo =
          EcdhKeyTransport.samTransportSharedInfo(samPub, wrapped.ephemeralPublicKey, 1234);
      byte[] key =
          EcdhKeyTransport.unwrapFrom(
              samPriv, wrapped.ephemeralPublicKey, wrapped.wrappedKey, sharedInfo);
      assertArrayEquals(fpe.kcv(), OpidCipher.of(key).kcv());
      assertThrows(
          IllegalArgumentException.class,
          () ->
              EcdhKeyTransport.unwrapFrom(
                  samPriv,
                  wrapped.ephemeralPublicKey,
                  wrapped.wrappedKey,
                  EcdhKeyTransport.samTransportSharedInfo(
                      samPub, wrapped.ephemeralPublicKey, 1235)));
    }
  }

  @Test
  void hostKdfIsRefusedWithoutDevCustodyWhenTheTokenLacksAnX963Kdf() throws Exception {
    byte[] samPub = EcdhKeyTransport.publicPoint(BigInteger.valueOf(7));
    try (Pkcs11Session session = Pkcs11Session.open(config)) {
      Pkcs11AdminService.IinFpeKey fpe = new Pkcs11AdminService().ensureIinFpeKey(session, "p", 1);
      Pkcs11KeyTransport probe = new Pkcs11KeyTransport(session, true);
      probe.wrapForSam(fpe.label, samPub, 1);
      Pkcs11KeyTransport hardware = new Pkcs11KeyTransport(session, false);
      if (probe.kdfPath() == Pkcs11KeyTransport.KdfPath.HOST_X963) {
        IllegalStateException refused =
            assertThrows(
                IllegalStateException.class, () -> hardware.wrapForSam(fpe.label, samPub, 1));
        assertTrue(refused.getMessage().contains("--dev-softhsm"), refused.getMessage());
      } else {
        hardware.wrapForSam(fpe.label, samPub, 1);
        assertEquals(probe.kdfPath(), hardware.kdfPath());
      }
    }
  }

  @Test
  void stationHandoffRoundTripsThroughTheToken() throws Exception {
    byte[] samId = HexUtil.parse("0102030405060708");
    byte[] secret = new byte[56];
    new SecureRandom().nextBytes(secret);
    try (Pkcs11Session session = Pkcs11Session.open(config)) {
      byte[] stationPub = new Pkcs11AdminService().ensureEcdhKey(session, "station");
      assertArrayEquals(stationPub, new Pkcs11AdminService().ensureEcdhKey(session, "station"));
      byte[] ski = new byte[20];
      ski[0] = 9;
      byte[] sharedInfo = EcdhKeyTransport.handoffSharedInfo(samId, ski);
      Pkcs11KeyTransport transport = new Pkcs11KeyTransport(session, true);
      Pkcs11KeyTransport.Wrapped wrapped = transport.wrapBytesTo(secret, stationPub, sharedInfo);
      assertEquals(64, wrapped.wrappedKey.length);
      assertArrayEquals(
          secret,
          transport.unwrapBytesFrom(
              "station", wrapped.ephemeralPublicKey, wrapped.wrappedKey, sharedInfo));
      byte[] tampered = wrapped.wrappedKey.clone();
      tampered[3] ^= 1;
      assertThrows(
          Pkcs11Exception.class,
          () ->
              transport.unwrapBytesFrom(
                  "station", wrapped.ephemeralPublicKey, tampered, sharedInfo));
      byte[] otherInfo = EcdhKeyTransport.handoffSharedInfo(samId, new byte[20]);
      assertThrows(
          Pkcs11Exception.class,
          () ->
              transport.unwrapBytesFrom(
                  "station", wrapped.ephemeralPublicKey, wrapped.wrappedKey, otherInfo));
    }
  }

  @Test
  void iinFpeKeyIsIdempotentWithKcvAsId() throws Exception {
    Pkcs11AdminService admin = new Pkcs11AdminService();
    try (Pkcs11Session session = Pkcs11Session.open(config)) {
      Pkcs11AdminService.IinFpeKey first = admin.ensureIinFpeKey(session, "prod", 42);
      Pkcs11AdminService.IinFpeKey second = admin.ensureIinFpeKey(session, "prod", 42);
      assertTrue(first.created);
      assertFalse(second.created);
      assertEquals("prod-iin-0042-fpe", first.label);
      assertArrayEquals(first.kcv(), second.kcv());
      Pkcs11Token.KeyHandle key = session.token().findAesKeys(first.label).get(0);
      assertArrayEquals(first.kcv(), key.id);
      assertArrayEquals(first.kcv(), Pkcs11AdminService.iinCipher(session, first.label).kcv());
      assertThrows(
          IllegalStateException.class,
          () ->
              admin.importIinFpeKey(
                  session, "prod", 42, new byte[32], OpidCipher.of(new byte[32]).kcv()));
      assertThrows(
          IllegalArgumentException.class,
          () -> admin.importIinFpeKey(session, "other", 42, new byte[32], new byte[16]));
    }
  }

  @Test
  void dataObjectsAreCreatedReadAndUpdated() throws Exception {
    try (Pkcs11Session session = Pkcs11Session.open(config)) {
      assertNull(Pkcs11AdminService.readData(session, "registry", "openfips201"));
      Pkcs11AdminService.writeData(session, "registry", "openfips201", new byte[] {1, 2, 3});
      assertArrayEquals(
          new byte[] {1, 2, 3}, Pkcs11AdminService.readData(session, "registry", "openfips201"));
      Pkcs11AdminService.writeData(session, "registry", "openfips201", new byte[32]);
      assertArrayEquals(
          new byte[32], Pkcs11AdminService.readData(session, "registry", "openfips201"));
      assertEquals(1, session.token().findData("registry", "openfips201").size());
    }
    try (Pkcs11Session session = Pkcs11Session.open(config)) {
      assertArrayEquals(
          new byte[32], Pkcs11AdminService.readData(session, "registry", "openfips201"));
    }
  }

  static JsonObject vectors() throws Exception {
    Path path =
        Paths.get(
            System.getProperty("openfips201.testVectors", "test-vectors"),
            "sam",
            "host-keytransport.json");
    return JsonParser.parseString(new String(Files.readAllBytes(path), StandardCharsets.UTF_8))
        .getAsJsonObject();
  }

  private static byte[] hex(JsonObject v, String name) {
    return HexUtil.parse(v.get(name).getAsString());
  }
}
