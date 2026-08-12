package dev.mistial.tests.openfips201;

import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Test;

class OpenFIPS201KeySlotInvariantTest extends OpenFIPS201TestSupport {

  private static final byte ALG_RSA_2048 = (byte) 0x07;
  private static final byte ALG_AES_128 = (byte) 0x08;
  private static final byte ALG_AES_256 = (byte) 0x0C;
  private static final byte ALG_ECC_P256 = (byte) 0x11;
  private static final byte SLOT_MANAGEMENT = (byte) 0x9B;
  private static final byte SLOT_RETIRED = (byte) 0x82;
  private static final byte ACCESS_NEVER = (byte) 0x00;
  private static final byte ACCESS_ALWAYS = (byte) 0x7F;
  private static final byte ROLE_SIGN = (byte) 0x04;
  private static final byte ROLE_ADMIN = (byte) 0x01;
  private static final byte ATTR_IMPORTABLE = (byte) 0x10;
  private static final byte ATTR_IMPORTABLE_PERMIT_MUTUAL = (byte) 0x11;

  @Test
  void keySlotRejectsSecondMechanismForSameReference() {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before duplicate-slot create");
          assertSw(
              0x9000,
              createKey(SLOT_MANAGEMENT, ALG_AES_128, ROLE_ADMIN, ATTR_IMPORTABLE_PERMIT_MUTUAL),
              "Initial 9B AES-128 definition should succeed");
          assertSw(
              0x6E27,
              createKey(SLOT_MANAGEMENT, ALG_AES_256, ROLE_ADMIN, ATTR_IMPORTABLE_PERMIT_MUTUAL),
              "Same key reference must not accept a second mechanism");
        });
  }

  @Test
  void retiredKeySlotRejectsSecondAsymmetricMechanism() {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before duplicate retired-slot create");
          assertSw(
              0x9000,
              createKey(SLOT_RETIRED, ALG_RSA_2048, ROLE_SIGN, ATTR_IMPORTABLE),
              "Initial retired RSA definition should succeed");
          assertSw(
              0x6E27,
              createKey(SLOT_RETIRED, ALG_ECC_P256, ROLE_SIGN, ATTR_IMPORTABLE),
              "Retired slot must not accept a second key mechanism");
        });
  }

  @Test
  void deleteKeyDistinguishesMissingReferenceFromWrongMechanism() {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before delete-key status tests");
          assertSw(
              0x6A88,
              deleteKey(SLOT_RETIRED, ALG_ECC_P256),
              "Deleting an empty key reference should report reference not found");
          assertSw(
              0x9000,
              createKey(SLOT_RETIRED, ALG_ECC_P256, ROLE_SIGN, ATTR_IMPORTABLE),
              "Create retired ECC key before wrong-mechanism delete");
          assertSw(
              0x6A86,
              deleteKey(SLOT_RETIRED, ALG_RSA_2048),
              "Deleting an existing slot with the wrong mechanism should fail as P1/P2 mismatch");
        });
  }

  @Test
  void deleteKeyAllowsSlotReuseWithDifferentMechanism() {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before key reuse test");
          assertSw(
              0x9000,
              createKey(SLOT_RETIRED, ALG_ECC_P256, ROLE_SIGN, ATTR_IMPORTABLE),
              "Create retired ECC key before delete");
          assertSw(0x9000, deleteKey(SLOT_RETIRED, ALG_ECC_P256), "Delete retired ECC key");
          assertSw(
              0x9000,
              createKey(SLOT_RETIRED, ALG_RSA_2048, ROLE_SIGN, ATTR_IMPORTABLE),
              "Deleted slot should be reusable with a new mechanism");
        });
  }

  @Test
  void retiredRestrictSingleKeyConfigTagFails() {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before retired config tag test");
          assertSw(
              0x6E26,
              transmit(0x84, 0xDB, 0x3F, 0x00, hex("6805A403830100")),
              "Former restrictSingleKey option must fail instead of being ignored");
        });
  }

  private ResponseAPDU createKey(byte slot, byte algorithm, byte role, byte attribute) {
    return transmit(
        0x84,
        0xDB,
        0x3F,
        0x00,
        new byte[] {
          (byte) 0x66,
          (byte) 0x12,
          (byte) 0x8B,
          (byte) 0x01,
          slot,
          (byte) 0x8C,
          (byte) 0x01,
          ACCESS_ALWAYS,
          (byte) 0x8D,
          (byte) 0x01,
          ACCESS_NEVER,
          (byte) 0x8E,
          (byte) 0x01,
          algorithm,
          (byte) 0x8F,
          (byte) 0x01,
          role,
          (byte) 0x90,
          (byte) 0x01,
          attribute
        });
  }

  private ResponseAPDU deleteKey(byte slot, byte algorithm) {
    return transmit(
        0x84,
        0xDB,
        0x3F,
        0x00,
        new byte[] {
          (byte) 0x67,
          (byte) 0x06,
          (byte) 0x8B,
          (byte) 0x01,
          slot,
          (byte) 0x8E,
          (byte) 0x01,
          algorithm
        });
  }

  @Override
  protected boolean provisionsStandardCard() {
    return false;
  }
}
