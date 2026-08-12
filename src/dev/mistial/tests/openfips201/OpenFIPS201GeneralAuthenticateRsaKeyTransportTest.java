package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.Assumptions;

@Timeout(value = 10, unit = TimeUnit.SECONDS)
class OpenFIPS201GeneralAuthenticateRsaKeyTransportTest extends OpenFIPS201TestSupport {
  private static final byte ALG_RSA_1024 = (byte) 0x06;
  private static final byte ALG_RSA_2048 = (byte) 0x07;
  private static final byte ALG_RSA_3072 = (byte) 0x05;
  private static final byte SLOT_RETIRED_KEY_MANAGEMENT = (byte) 0x82;
  private static final byte SLOT_KEY_MANAGEMENT = (byte) 0x9D;
  private static final byte ROLE_KEY_ESTABLISH = (byte) 0x02;
  private static final byte ATTR_NONE = (byte) 0x00;
  private static final int RSA_1024_BYTES = 128;

  @Test
  void rsaKeyEstablishmentUsesKeyTransportBranch() {
    Assumptions.assumeFalse(
        Boolean.getBoolean("fips.mode"),
        "The simulator APDU buffer cannot carry an unchained RSA-2048 transport block");
    provisionGeneratedRsaKey(SLOT_RETIRED_KEY_MANAGEMENT);
    assertSw(
        0x9000,
        transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN),
        "VERIFY before retired-key use");

    byte[] malformedTransportBlock = new byte[RSA_1024_BYTES];
    ResponseAPDU response =
        transmit(
            new CommandAPDU(
                0x00,
                0x87,
                ALG_RSA_1024 & 0xFF,
                SLOT_RETIRED_KEY_MANAGEMENT & 0xFF,
                keyTransportTemplate(malformedTransportBlock),
                256));

    assertSw(
        0x6A80,
        response,
        "Malformed RSA transport block should reach RSA key transport, not SM key routing");
  }

  @Test
  void rsa2048KeyTransportRecoversEncryptedRepresentative() throws Exception {
    assertPositiveKeyTransport(SLOT_KEY_MANAGEMENT, ALG_RSA_2048, 256);
  }

  @Test
  void rsa3072KeyTransportRecoversEncryptedRepresentative() throws Exception {
    assertPositiveKeyTransport(SLOT_KEY_MANAGEMENT, ALG_RSA_3072, 384);
  }

  @Test
  void rsa2048KeyTransportWorksAtRetiredKeyReference() throws Exception {
    assertPositiveKeyTransport(SLOT_RETIRED_KEY_MANAGEMENT, ALG_RSA_2048, 256);
  }

  private void assertPositiveKeyTransport(byte slot, byte algorithm, int blockLength)
      throws Exception {
    byte[][] publicComponents = provisionGeneratedRsaKey(slot, algorithm);
    assertSw(
        0x9000,
        transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN),
        "VERIFY before RSA key transport");

    PublicKey publicKey =
        KeyFactory.getInstance("RSA")
            .generatePublic(
                new RSAPublicKeySpec(
                    new BigInteger(1, publicComponents[0]),
                    new BigInteger(1, publicComponents[1])));
    byte[] representative = new byte[blockLength];
    Arrays.fill(representative, (byte) 0x39);
    representative[0] = 0;
    Cipher rsa = Cipher.getInstance("RSA/ECB/NoPadding");
    rsa.init(Cipher.ENCRYPT_MODE, publicKey);
    byte[] ciphertext = rsa.doFinal(representative);

    byte[] request = keyTransportTemplate(ciphertext);
    byte[] first = Arrays.copyOfRange(request, 0, 200);
    byte[] last = Arrays.copyOfRange(request, 200, request.length);
    assertSw(
        0x9000,
        transmit(0x10, 0x87, algorithm & 0xFF, slot & 0xFF, first),
        "First chained RSA key-transport fragment");
    byte[] response =
        collect(
            transmit(
                new CommandAPDU(
                    0x00,
                    0x87,
                    algorithm & 0xFF,
                    slot & 0xFF,
                    last,
                    256)),
            "RSA key transport");
    byte[] plaintext = tlvValue(tlvValue(response, (byte) 0x7C), (byte) 0x82);
    assertTrue(
        Arrays.equals(representative, fixed(new BigInteger(1, plaintext), blockLength)),
        "RSA key transport must recover the encrypted representative");
  }

  private void provisionGeneratedRsaKey(final byte slot) {
    provisionGeneratedRsaKey(slot, ALG_RSA_1024);
  }

  private byte[][] provisionGeneratedRsaKey(final byte slot, final byte algorithm) {
    final byte[][] publicComponents = new byte[2][];
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before RSA key provisioning");
          byte[] definition =
              new byte[] {
                (byte) 0x66,
                (byte) 0x12,
                (byte) 0x8B,
                (byte) 0x01,
                slot,
                (byte) 0x8C,
                (byte) 0x01,
                (byte) 0x01,
                (byte) 0x8D,
                (byte) 0x01,
                (byte) 0x09,
                (byte) 0x8E,
                (byte) 0x01,
                algorithm,
                (byte) 0x8F,
                (byte) 0x01,
                ROLE_KEY_ESTABLISH,
                (byte) 0x90,
                (byte) 0x01,
                ATTR_NONE
              };
          assertSw(0x9000, transmit(0x84, 0xDB, 0x3F, 0x00, definition), "Create RSA key");
          byte[] generated =
              collect(
                  transmit(
                      0x84,
                      0x47,
                      0x00,
                      slot & 0xFF,
                      new byte[] {(byte) 0xAC, 0x03, (byte) 0x80, 0x01, algorithm},
                      256),
                  "Generate RSA key");
          publicComponents[0] = tlvValue(generated, (byte) 0x81);
          publicComponents[1] = tlvValue(generated, (byte) 0x82);
        });
    return publicComponents;
  }

  private byte[] keyTransportTemplate(byte[] challenge) {
    return tlv((byte) 0x7C, concat(tlv((byte) 0x82, new byte[0]), tlv((byte) 0x81, challenge)));
  }

  private byte[] collect(ResponseAPDU response, String context) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ResponseAPDU current = response;
    while (current.getSW1() == 0x61) {
      out.write(current.getData(), 0, current.getData().length);
      int le = current.getSW2() == 0 ? 256 : current.getSW2();
      current = transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00, le));
    }
    assertSw(0x9000, current, context);
    out.write(current.getData(), 0, current.getData().length);
    return out.toByteArray();
  }

  private static byte[] fixed(BigInteger value, int length) {
    byte[] encoded = value.toByteArray();
    byte[] result = new byte[length];
    int sourceOffset = Math.max(0, encoded.length - length);
    int copyLength = Math.min(encoded.length, length);
    System.arraycopy(encoded, sourceOffset, result, length - copyLength, copyLength);
    return result;
  }
}
