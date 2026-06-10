package dev.mistial.tests.openfips201;

import org.junit.jupiter.api.Test;

import javax.smartcardio.ResponseAPDU;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OpenFIPS201VciConformanceTest extends OpenFIPS201TestSupport {
  private static final byte ACCESS_MODE_NEVER = (byte) 0x00;
  private static final byte ACCESS_MODE_ALWAYS = (byte) 0x7F;
  private static final byte KEY_REF_SECURE_MESSAGING = (byte) 0x04;
  private static final byte ALG_CS2 = (byte) 0x27;
  private static final byte ROLE_KEY_ESTABLISH = (byte) 0x02;
  private static final byte ATTR_NONE = (byte) 0x00;
  private static final byte ATTR_IMPORTABLE = (byte) 0x10;

  @Test
  void invalidVciModeIsRejectedByConfiguration() {
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before VCI config update");
            ResponseAPDU response = transmit(0x84, 0xDB, 0x3F, 0x00, hex("68 05 A2 03 80 01 03"));
            assertSw(0x6984, response, "VCI mode must be disabled, enabled, or pairing-code");
          }
        });
  }

  @Test
  void discoveryObjectAdvertisesVciAndPairingPolicy() {
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before VCI pairing-required config");
            assertSw(
                0x9000,
                transmit(0x84, 0xDB, 0x3F, 0x00, hex("68 05 A2 03 80 01 02")),
                "Enable VCI with pairing code");
            createDiscoveryObject();
          }
        });

    ResponseAPDU pairingRequired = transmit(0x00, 0xCB, 0x3F, 0xFF, hex("5C017E"));
    assertSw(0x9000, pairingRequired, "Read Discovery Object with VCI pairing-required");
    byte[] pairingPolicy = policyBytes(pairingRequired.getData());
    assertTrue((pairingPolicy[0] & 0x08) != 0, "Discovery Object must set VCI implemented bit");
    assertFalse((pairingPolicy[0] & 0x04) != 0, "Pairing-required VCI must clear no-pairing bit");

    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(
                0x9000,
                transmit(0x84, 0xDB, 0x3F, 0x00, hex("68 05 A2 03 80 01 01")),
                "Enable VCI without pairing code");
          }
        });

    ResponseAPDU noPairing = transmit(0x00, 0xCB, 0x3F, 0xFF, hex("5C017E"));
    assertSw(0x9000, noPairing, "Read Discovery Object with VCI no-pairing");
    byte[] noPairingPolicy = policyBytes(noPairing.getData());
    assertTrue((noPairingPolicy[0] & 0x08) != 0, "Discovery Object must keep VCI implemented bit");
    assertTrue((noPairingPolicy[0] & 0x04) != 0, "No-pairing VCI must set no-pairing bit");
  }

  @Test
  void applicationPropertyTemplateAdvertisesCs2OnlyAfterKeyMaterialAndCvc() {
    assertSw(0x9000, selectApplet(), "Initial SELECT");
    assertFalse(contains(selectAppletWithData().getData(), hex("800127")), "APT must not advertise CS2 by default");

    configureVciMode((byte) 0x02);
    createVciKeyOverScp(ATTR_IMPORTABLE);
    importVciPrivateKeyOverScp(p256ScalarOne());
    importVciPublicKeyOverScp(p256BasePoint());
    assertFalse(contains(selectAppletWithData().getData(), hex("800127")), "APT requires CVC as well as key material");

    loadVciCvcOverScp(hex("7F2181100102030405060708090A0B0C0D0E0F10"));
    assertTrue(contains(selectAppletWithData().getData(), hex("800127")), "APT must advertise CS2 after key and CVC");
  }

  @Test
  void nonImportableVciKeyAcceptsCvcButRejectsPrivateKeyImport() {
    configureVciMode((byte) 0x02);
    createVciKeyOverScp(ATTR_NONE);

    loadVciCvcOverScp(hex("7F210401020304"));
    ResponseAPDU privateImport =
        changeVciReferenceDataOverScp(tlv((byte) 0x30, tlv((byte) 0x87, fixed((byte) 0x44, 32))));
    assertSw(0x6982, privateImport, "Generated non-importable VCI key must reject private import");
  }

  @Test
  void importedVciKeyRequiresCvcBeforeAptAdvertisement() {
    configureVciMode((byte) 0x01);
    createVciKeyOverScp(ATTR_IMPORTABLE);
    importVciPrivateKeyOverScp(p256ScalarOne());
    importVciPublicKeyOverScp(p256BasePoint());
    assertFalse(contains(selectAppletWithData().getData(), hex("800127")), "Imported VCI key still requires CVC");

    loadVciCvcOverScp(hex("7F210401020304"));
    assertTrue(contains(selectAppletWithData().getData(), hex("800127")), "Imported VCI key advertises after CVC");
  }

  private void configureVciMode(final byte mode) {
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before VCI config");
            assertSw(
                0x9000,
                transmit(0x84, 0xDB, 0x3F, 0x00, hex("68 05 A2 03 80 01 " + String.format("%02X", mode))),
                "Update VCI mode");
          }
        });
  }

  private void createVciKeyOverScp(final byte attributes) {
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before VCI key create");
            byte[] request =
                tlv(
                    (byte) 0x66,
                    concat(
                        new byte[] {
                          (byte) 0x8B, (byte) 0x01, KEY_REF_SECURE_MESSAGING,
                          (byte) 0x8C, (byte) 0x01, ACCESS_MODE_ALWAYS,
                          (byte) 0x8D, (byte) 0x01, ACCESS_MODE_ALWAYS,
                          (byte) 0x91, (byte) 0x01, (byte) 0x9B,
                          (byte) 0x8E, (byte) 0x01, ALG_CS2,
                          (byte) 0x8F, (byte) 0x01, ROLE_KEY_ESTABLISH,
                          (byte) 0x90, (byte) 0x01, attributes
                        }));
            assertSw(0x9000, transmit(0x84, 0xDB, 0x3F, 0x00, request), "Create VCI key");
          }
        });
  }

  private void createDiscoveryObject() {
    byte[] request =
        tlv(
            (byte) 0x64,
            new byte[] {
              (byte) 0x8B, (byte) 0x01, (byte) 0x7E,
              (byte) 0x8C, (byte) 0x01, ACCESS_MODE_ALWAYS,
              (byte) 0x8D, (byte) 0x01, ACCESS_MODE_ALWAYS,
              (byte) 0x91, (byte) 0x01, (byte) 0x9B
            });
    assertSw(0x9000, transmit(0x84, 0xDB, 0x3F, 0x00, request), "Create Discovery Object");
  }

  private void importVciPrivateKeyOverScp(byte[] privateScalar) {
    ResponseAPDU response =
        changeVciReferenceDataOverScp(tlv((byte) 0x30, tlv((byte) 0x87, privateScalar)));
    assertSw(0x9000, response, "Import VCI private key");
  }

  private void importVciPublicKeyOverScp(byte[] publicPoint) {
    ResponseAPDU response =
        changeVciReferenceDataOverScp(tlv((byte) 0x30, tlv((byte) 0x86, publicPoint)));
    assertSw(0x9000, response, "Import VCI public key");
  }

  private void loadVciCvcOverScp(byte[] cvc) {
    ResponseAPDU response = changeVciReferenceDataOverScp(tlv((byte) 0x30, tlv((byte) 0x8A, cvc)));
    assertSw(0x9000, response, "Load VCI CVC");
  }

  private ResponseAPDU changeVciReferenceDataOverScp(final byte[] data) {
    final ResponseAPDU[] response = new ResponseAPDU[1];
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            response[0] = transmit(0x84, 0x24, ALG_CS2 & 0xFF, KEY_REF_SECURE_MESSAGING & 0xFF, data);
          }
        });
    return response[0];
  }

  private static boolean contains(byte[] haystack, byte[] needle) {
    outer:
    for (int i = 0; i <= haystack.length - needle.length; i++) {
      for (int j = 0; j < needle.length; j++) {
        if (haystack[i + j] != needle[j]) continue outer;
      }
      return true;
    }
    return false;
  }

  private ResponseAPDU selectAppletWithData() {
    return transmit(new javax.smartcardio.CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 256));
  }

  private static byte[] fixed(byte value, int length) {
    byte[] out = new byte[length];
    for (int i = 0; i < out.length; i++) out[i] = value;
    return out;
  }

  private static byte[] policyBytes(byte[] discovery) {
    for (int i = 0; i <= discovery.length - 5; i++) {
      if (discovery[i] == (byte) 0x5F && discovery[i + 1] == (byte) 0x2F && discovery[i + 2] == 2) {
        return new byte[] {discovery[i + 3], discovery[i + 4]};
      }
    }
    throw new IllegalArgumentException("Discovery Object missing 5F2F policy bytes");
  }

  private static byte[] p256ScalarOne() {
    byte[] scalar = new byte[32];
    scalar[31] = 1;
    return scalar;
  }

  private static byte[] p256BasePoint() {
    return hex(
        "04"
            + "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
            + "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
  }
}
