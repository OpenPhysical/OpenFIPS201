package dev.mistial.tools.openfips201.nist;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import apdu4j.core.BIBO;
import com.makina.security.openfips201.OpenFIPS201;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.provisioning.ConformancePackage;
import dev.mistial.tools.openfips201.provisioning.ConformanceProvisioner;
import dev.mistial.tools.openfips201.provisioning.IcamCardFolder;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import pro.javacard.engine.JavaCardEngine;

/** Headless positive-path checks equivalent to the GSA CCT card-access smoke. */
class GsaIcam46HeadlessSmokeTest {
  private static final byte[] PIV_AID = hex("A000000308000010000100");
  private static final Path ICAM_ROOT =
      Paths.get("test-vectors/gsa-icam-card-builder/cards/ICAM_Card_Objects");
  private static final String[] VENDORED_POSITIVE_CARDS = {
    "01_Golden_PIV",
    "02_Golden_PIV-I",
    "37_Golden_FIPS_201-2_PIV_PPS_F=512_D=64",
    "39_Golden_FIPS_201-2_Fed_PIV-I",
    "46_Golden_FIPS_201-2_PIV",
    "47_Golden_FIPS_201-2_PIV_SAN_Order",
    "54_Golden_FIPS_201-2_NFI_PIV-I"
  };
  private static final String[] FIPS_PIV_POSITIVE_CARDS = {
    "37_Golden_FIPS_201-2_PIV_PPS_F=512_D=64",
    "46_Golden_FIPS_201-2_PIV",
    "47_Golden_FIPS_201-2_PIV_SAN_Order"
  };
  private static final Path ICAM_46 =
      Paths.get(
          System.getProperty(
              "openfips201.icam46",
              "test-vectors/gsa-icam-card-builder/cards/ICAM_Card_Objects/"
                  + "46_Golden_FIPS_201-2_PIV"));

  @Test
  @Timeout(45)
  void provisionsAndExercisesGoldenCard46() throws Exception {
    assumeTrue(Files.isDirectory(ICAM_46), "ICAM card 46 not present at " + ICAM_46);
    ConformancePackage profile = IcamCardFolder.load(ICAM_46);
    ConformancePackage.KeyMaterial cardAuthentication = findKey(profile, (byte) 0x9E);

    JavaCardEngine engine = JavaCardEngine.create();
    AID aid = new AID(PIV_AID, (short) 0, (byte) PIV_AID.length);
    engine.installApplet(aid, OpenFIPS201.class, new byte[0]);
    ConformanceProvisioner.ProvisionReport report =
        ConformanceProvisioner.provision(
            () -> engine.connect("T=1", true), ScpConfig.defaultTestScp03(), profile, null);
    assertEquals(11, report.objectsCreated);
    assertEquals(4, report.keysImported);

    try (BIBO bibo = engine.connect("T=1", true)) {
      assertSw(0x9000, transmit(bibo, new CommandAPDU(0x00, 0xA4, 0x04, 0x00, PIV_AID, 256)));
      assertSw(0x9000, transmit(bibo, new CommandAPDU(0x00, 0x20, 0x00, 0x80, profile.pin)));

      assertObjectReadable(bibo, "5FC107"); // CCC
      assertObjectReadable(bibo, "5FC102"); // CHUID
      assertObjectReadable(bibo, "5FC101"); // Card Authentication certificate
      verifyCardAuthentication(bibo, cardAuthentication);
    }
  }

  @Test
  @Timeout(120)
  void provisionsAndReadsEveryVendoredPositiveProfileInStandardBuild() throws Exception {
    assumeFalse(Boolean.getBoolean("fips.mode"), "legacy GSA profiles are interoperability inputs");
    assumeTrue(Files.isDirectory(ICAM_ROOT), "vendored GSA corpus not present at " + ICAM_ROOT);
    for (String card : VENDORED_POSITIVE_CARDS) {
      ConformancePackage profile = IcamCardFolder.load(ICAM_ROOT.resolve(card));
      JavaCardEngine engine = JavaCardEngine.create();
      AID aid = new AID(PIV_AID, (short) 0, (byte) PIV_AID.length);
      engine.installApplet(aid, OpenFIPS201.class, new byte[0]);
      ConformanceProvisioner.ProvisionReport report =
          ConformanceProvisioner.provision(
              () -> engine.connect("T=1", true), ScpConfig.defaultTestScp03(), profile, null);
      assertEquals(profile.dataObjects.size(), report.objectsCreated, card);
      assertEquals(profile.keys.size(), report.keysImported, card);
      try (BIBO bibo = engine.connect("T=1", true)) {
        assertSw(0x9000, transmit(bibo, new CommandAPDU(0x00, 0xA4, 0x04, 0x00, PIV_AID, 256)));
        assertSw(0x9000, transmit(bibo, new CommandAPDU(0x00, 0x20, 0x00, 0x80, profile.pin)));
        assertObjectReadable(bibo, "5FC107");
        assertObjectReadable(bibo, "5FC102");
        assertObjectReadable(bibo, "5FC101");
      }
    }
  }

  @Test
  @Timeout(120)
  void provisionsEveryVendoredFipsPivProfileInFipsBuild() throws Exception {
    assumeTrue(Boolean.getBoolean("fips.mode"), "strict-profile coverage runs in FIPS builds");
    for (String card : FIPS_PIV_POSITIVE_CARDS) {
      provisionAndReadCoreObjects(ICAM_ROOT.resolve(card), card);
    }
  }

  private static void provisionAndReadCoreObjects(Path path, String card) throws Exception {
    ConformancePackage profile = IcamCardFolder.load(path);
    JavaCardEngine engine = JavaCardEngine.create();
    AID aid = new AID(PIV_AID, (short) 0, (byte) PIV_AID.length);
    engine.installApplet(aid, OpenFIPS201.class, new byte[0]);
    ConformanceProvisioner.ProvisionReport report =
        ConformanceProvisioner.provision(
            () -> engine.connect("T=1", true), ScpConfig.defaultTestScp03(), profile, null);
    assertEquals(profile.dataObjects.size(), report.objectsCreated, card);
    assertEquals(profile.keys.size(), report.keysImported, card);
    try (BIBO bibo = engine.connect("T=1", true)) {
      assertSw(0x9000, transmit(bibo, new CommandAPDU(0x00, 0xA4, 0x04, 0x00, PIV_AID, 256)));
      assertSw(0x9000, transmit(bibo, new CommandAPDU(0x00, 0x20, 0x00, 0x80, profile.pin)));
      assertObjectReadable(bibo, "5FC107");
      assertObjectReadable(bibo, "5FC102");
      assertObjectReadable(bibo, "5FC101");
    }
  }

  private static void assertObjectReadable(BIBO bibo, String objectId) throws Exception {
    byte[] id = hex(objectId);
    ResponseAPDU response =
        transmit(
            bibo,
            new CommandAPDU(
                0x00,
                0xCB,
                0x3F,
                0xFF,
                concat(new byte[] {(byte) 0x5C, (byte) id.length}, id),
                256));
    byte[] body = collect(bibo, response, "GET DATA " + objectId);
    assertTrue(body.length > 2, objectId + " must return a non-empty TLV");
  }

  private static void verifyCardAuthentication(
      BIBO bibo, ConformancePackage.KeyMaterial cardAuthentication) throws Exception {
    RSAPublicKey publicKey = (RSAPublicKey) cardAuthentication.certificate.getPublicKey();
    int blockLength = (publicKey.getModulus().bitLength() + 7) / 8;
    byte[] representative = new byte[blockLength];
    Arrays.fill(representative, (byte) 0x4A);
    representative[0] = 0;
    byte[] request =
        tlv((byte) 0x7C, concat(tlv((byte) 0x82, new byte[0]), tlv((byte) 0x81, representative)));
    byte[] first = Arrays.copyOfRange(request, 0, 200);
    byte[] last = Arrays.copyOfRange(request, 200, request.length);

    assertSw(0x9000, transmit(bibo, new CommandAPDU(0x10, 0x87, 0x07, 0x9E, first)));
    byte[] response =
        collect(
            bibo,
            transmit(bibo, new CommandAPDU(0x00, 0x87, 0x07, 0x9E, last, 256)),
            "GENERAL AUTHENTICATE 9E");
    byte[] signature = findTlv(findTlv(response, (byte) 0x7C), (byte) 0x82);
    byte[] recovered =
        fixed(
            new BigInteger(1, signature)
                .modPow(publicKey.getPublicExponent(), publicKey.getModulus()),
            blockLength);
    assertArrayEquals(
        representative, recovered, "9E signature must verify with the ICAM certificate");
  }

  private static ConformancePackage.KeyMaterial findKey(ConformancePackage profile, byte slot) {
    for (ConformancePackage.KeyMaterial key : profile.keys) {
      if (key.slot == slot) return key;
    }
    throw new AssertionError("Missing ICAM key slot " + Integer.toHexString(slot & 0xFF));
  }

  private static ResponseAPDU transmit(BIBO bibo, CommandAPDU command) throws Exception {
    return new ResponseAPDU(bibo.transceive(command.getBytes()));
  }

  private static byte[] collect(BIBO bibo, ResponseAPDU response, String context) throws Exception {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ResponseAPDU current = response;
    while (current.getSW1() == 0x61) {
      out.write(current.getData());
      int le = current.getSW2() == 0 ? 256 : current.getSW2();
      current = transmit(bibo, new CommandAPDU(0x00, 0xC0, 0x00, 0x00, le));
    }
    assertSw(0x9000, current);
    out.write(current.getData());
    assertTrue(out.size() > 0, context + " must return data");
    return out.toByteArray();
  }

  private static void assertSw(int expected, ResponseAPDU response) {
    assertEquals(expected, response.getSW(), "Unexpected status word");
  }

  private static byte[] tlv(byte tag, byte[] value) {
    byte[] length = derLength(value.length);
    return concat(new byte[] {tag}, length, value);
  }

  private static byte[] findTlv(byte[] encoded, byte tag) {
    int offset = 0;
    while (offset < encoded.length) {
      byte current = encoded[offset++];
      int firstLength = encoded[offset++] & 0xFF;
      int length = firstLength;
      if ((firstLength & 0x80) != 0) {
        int count = firstLength & 0x7F;
        length = 0;
        for (int i = 0; i < count; i++) length = (length << 8) | (encoded[offset++] & 0xFF);
      }
      if (current == tag) return Arrays.copyOfRange(encoded, offset, offset + length);
      offset += length;
    }
    throw new IllegalArgumentException("Missing TLV tag " + Integer.toHexString(tag & 0xFF));
  }

  private static byte[] derLength(int length) {
    if (length < 0x80) return new byte[] {(byte) length};
    if (length < 0x100) return new byte[] {(byte) 0x81, (byte) length};
    return new byte[] {(byte) 0x82, (byte) (length >>> 8), (byte) length};
  }

  private static byte[] concat(byte[]... values) {
    int length = 0;
    for (byte[] value : values) length += value.length;
    byte[] result = new byte[length];
    int offset = 0;
    for (byte[] value : values) {
      System.arraycopy(value, 0, result, offset, value.length);
      offset += value.length;
    }
    return result;
  }

  private static byte[] fixed(BigInteger value, int length) {
    byte[] encoded = value.toByteArray();
    byte[] result = new byte[length];
    int sourceOffset = Math.max(0, encoded.length - length);
    int copyLength = Math.min(encoded.length, length);
    System.arraycopy(encoded, sourceOffset, result, length - copyLength, copyLength);
    return result;
  }

  private static byte[] hex(String value) {
    byte[] result = new byte[value.length() / 2];
    for (int i = 0; i < value.length(); i += 2) {
      result[i / 2] =
          (byte)
              ((Character.digit(value.charAt(i), 16) << 4)
                  | Character.digit(value.charAt(i + 1), 16));
    }
    return result;
  }
}
