/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.producer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.crypto.EcdhKeyTransport;
import dev.mistial.tools.openfips201.opid.OpidCipher;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11Session;
import dev.mistial.tools.openfips201.pkcs11.SoftHsmFixture;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** {@code producer iin import-key} and {@code backup-key} against a SoftHSM2 root token. */
@Tag("softhsm")
class IinKeyServiceSoftHsmTest {
  @TempDir Path temp;

  private String name;

  @BeforeEach
  void createProducer() throws Exception {
    SoftHsmFixture.requireSoftHsm();
    name = SoftHsmFixture.uniqueLabel("iin-");
    ProducerSetupService.Request request = new ProducerSetupService.Request();
    request.name = name;
    request.module = SoftHsmFixture.module();
    request.rootSubject = "CN=" + name + " Root";
    request.devSoftHsm = true;
    request.soPinDisplay = soPin -> {};
    new ProducerSetupService().setup(request);
  }

  @Test
  void importKeyMovesThePlaintextKeyIntoTheTokenAndDestroysTheFile() throws Exception {
    String kcv = IinKeyStore.ensure(name, 1234, new SecureRandom());
    Path file = IinKeyStore.file(name, 1234);
    byte[] key = IinKeyStore.read(name, 1234, kcv);
    assertTrue(Files.exists(file));
    IinKeyService.requireNoPlaintextKey(name, 1234);

    try (Pkcs11Session session = Pkcs11Session.open(IinKeyService.profile(name).pkcs11)) {
      assertEquals(kcv, new IinKeyService().importKey(session, name, 1234));
      assertFalse(Files.exists(file));
      OpidCipher token = new IinKeyService().cipher(session, name, 1234, kcv);
      OpidCipher software = OpidCipher.of(key);
      for (long plain = 0; plain < 20; plain++) {
        assertEquals(software.encipher(1234, plain * 7919L), token.encipher(1234, plain * 7919L));
      }
      assertEquals(kcv, new IinKeyService().ensureKey(session, name, 1234));
      assertThrows(
          IllegalStateException.class,
          () ->
              new IinKeyService().cipher(session, name, 1234, "00000000000000000000000000000000"));
      assertThrows(
          IllegalArgumentException.class, () -> new IinKeyService().importKey(session, name, 1234));
    }
  }

  @Test
  void backupKeyWrapsToTheRecipientWithoutWritingThePlaintext() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair backup = generator.generateKeyPair();
    Path out = temp.resolve("backup.json");
    String kcv;
    try (Pkcs11Session session = Pkcs11Session.open(IinKeyService.profile(name).pkcs11)) {
      kcv = new IinKeyService().ensureKey(session, name, 77);
      new IinKeyService().backupKey(session, name, 77, backup.getPublic(), out, true);
      assertThrows(
          IllegalArgumentException.class,
          () -> new IinKeyService().backupKey(session, name, 77, backup.getPublic(), out, true));
    }
    assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(out)));
    JsonObject document =
        JsonParser.parseString(new String(Files.readAllBytes(out), StandardCharsets.UTF_8))
            .getAsJsonObject();
    assertEquals(IinKeyService.BACKUP_SCHEMA, document.get("schema").getAsString());
    assertEquals(kcv, document.get("kcv").getAsString());
    byte[] ephemeral = HexUtil.parse(document.get("ephemeralPublicKey").getAsString());
    byte[] wrapped = HexUtil.parse(document.get("wrappedKey").getAsString());
    byte[] recipient = EcdhKeyTransport.point(backup.getPublic());
    BigInteger d = ((ECPrivateKey) backup.getPrivate()).getS();
    byte[] key =
        EcdhKeyTransport.unwrapFrom(
            d, ephemeral, wrapped, EcdhKeyTransport.backupSharedInfo(recipient, 77));
    assertEquals(kcv, HexUtil.format(OpidCipher.of(key).kcv()));
    assertFalse(
        new String(Files.readAllBytes(out), StandardCharsets.UTF_8).contains(HexUtil.format(key)));
    assertArrayEquals(key, key.clone());
  }
}
