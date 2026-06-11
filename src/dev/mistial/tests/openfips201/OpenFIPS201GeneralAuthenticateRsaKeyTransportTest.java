package dev.mistial.tests.openfips201;

import java.io.ByteArrayOutputStream;
import java.util.concurrent.TimeUnit;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

@Timeout(value = 35, unit = TimeUnit.SECONDS)
class OpenFIPS201GeneralAuthenticateRsaKeyTransportTest extends OpenFIPS201TestSupport {
  private static final byte ALG_RSA_1024 = (byte) 0x06;
  private static final byte SLOT_KEY_MANAGEMENT = (byte) 0x9D;
  private static final byte ROLE_KEY_ESTABLISH = (byte) 0x02;
  private static final byte ATTR_NONE = (byte) 0x00;
  private static final int RSA_1024_BYTES = 128;

  @Test
  void rsaKeyEstablishmentUsesKeyTransportBranch() {
    provisionGeneratedRsaKey(SLOT_KEY_MANAGEMENT);

    byte[] malformedTransportBlock = new byte[RSA_1024_BYTES];
    ResponseAPDU response =
        transmit(
            new CommandAPDU(
                0x00,
                0x87,
                ALG_RSA_1024 & 0xFF,
                SLOT_KEY_MANAGEMENT & 0xFF,
                keyTransportTemplate(malformedTransportBlock),
                256));

    assertSw(
        0x6A80,
        response,
        "Malformed RSA transport block should reach RSA key transport, not SM key routing");
  }

  private void provisionGeneratedRsaKey(final byte slot) {
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
                (byte) 0x7F,
                (byte) 0x8D,
                (byte) 0x01,
                (byte) 0x00,
                (byte) 0x8E,
                (byte) 0x01,
                ALG_RSA_1024,
                (byte) 0x8F,
                (byte) 0x01,
                ROLE_KEY_ESTABLISH,
                (byte) 0x90,
                (byte) 0x01,
                ATTR_NONE
              };
          assertSw(0x9000, transmit(0x84, 0xDB, 0x3F, 0x00, definition), "Create RSA key");
          collect(
              transmit(0x84, 0x47, 0x00, slot & 0xFF, hex("AC03800106"), 256),
              "Generate RSA key");
        });
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
}
