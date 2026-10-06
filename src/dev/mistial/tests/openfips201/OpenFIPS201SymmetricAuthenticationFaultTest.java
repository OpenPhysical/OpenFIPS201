package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import com.makina.security.openfips201.OpenFIPS201;
import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.security.CryptoException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * Symmetric GENERAL AUTHENTICATE across every PIV symmetric mechanism, and provider faults in the
 * mutual-authentication exchange (SP 800-73-5 Part 2 Section 3.2.4 and Appendix A.2).
 *
 * <p>SP 800-73-5 Part 2 Section 2.4.2: "An aborted or failed execution of an authentication
 * protocol SHALL set the security status indicator associated with the credential used in the
 * protocol to FALSE." A provider {@code CryptoException} is reported as '6A80' and abandons the
 * exchange, so a witness issued before the failure is never accepted afterwards. Faults are
 * injected by intercepting {@code PIVCrypto} in the class loader that loaded the installed applet.
 */
@Timeout(value = 30, unit = TimeUnit.SECONDS)
class OpenFIPS201SymmetricAuthenticationFaultTest extends OpenFIPS201TestSupport {
  private static final byte ALG_3DES = (byte) 0x03;
  private static final byte ALG_AES_128 = (byte) 0x08;
  private static final byte KEY_CARD_MANAGEMENT = StandardCardProfile.ADMIN_KEY_REF;
  // A dynamically defined key reference, available in the compatibility profile.
  private static final byte KEY_DYNAMIC = (byte) 0x10;
  private static final byte ATTR_PERMIT_INTERNAL_IMPORTABLE = (byte) 0x12;
  // ATTR_PERMIT_EXTERNAL | ATTR_PERMIT_MUTUAL | ATTR_IMPORTABLE.
  private static final byte ATTR_MUTUAL_IMPORTABLE = (byte) 0x1C;
  private static final byte[] PROBE_OBJECT_TAG_LIST = hex("5C035FFF10");
  private static final String PIV_CRYPTO = "com.makina.security.openfips201.PIVCrypto";

  /** Provisions a 9B key that permits mutual authentication instead of the standard card's. */
  @Override
  protected boolean provisionsStandardCard() {
    return false;
  }

  /**
   * GENERAL AUTHENTICATE Case 1D (internal authenticate): the card enciphers exactly one block of
   * host challenge with the referenced symmetric key, for every SP 800-78-5 Table 6 mechanism.
   */
  @ParameterizedTest(name = "{0}")
  @CsvSource({"3TDEA, 3", "AES-128, 8", "AES-192, 10", "AES-256, 12"})
  void internalAuthenticateEnciphersOneBlockForEverySymmetricMechanism(String name, byte algorithm)
      throws Exception {
    // FipsPolicy refuses ATTR_PERMIT_INTERNAL on 9B and reserves every other symmetric reference,
    // so the FIPS profile has no key that Case 1D can address; TDEA is also outside that profile.
    assumeFalse(
        Boolean.getBoolean("fips.mode"),
        "The FIPS profile defines no symmetric key permitting internal authentication");
    byte[] key = keyMaterial(algorithm, (byte) 0x21);
    provisionSymmetricKeyOverScp(KEY_DYNAMIC, algorithm, ATTR_PERMIT_INTERNAL_IMPORTABLE, key);
    assertSw(0x9000, selectApplet(), "SELECT before internal authentication");

    int block = algorithm == ALG_3DES ? 8 : 16;
    byte[] challenge = new byte[block];
    for (int i = 0; i < block; i++) challenge[i] = (byte) (0xC0 + i);
    ResponseAPDU response =
        transmit(
            0x00,
            0x87,
            algorithm & 0xFF,
            KEY_DYNAMIC & 0xFF,
            tlv((byte) 0x7C, concat(tlv((byte) 0x81, challenge), tlv((byte) 0x82, new byte[0]))));
    assertSw(0x9000, response, "Internal authenticate");
    byte[] cryptogram = tlvValue(response.getData(), (byte) 0x82);
    assertEquals(block, cryptogram.length, "One cipher block is returned");
    assertArrayEquals(
        challenge,
        crypt(Cipher.DECRYPT_MODE, algorithm, key, cryptogram),
        "The card enciphers the challenge with the referenced key");

    assertSw(
        ISO7816.SW_WRONG_DATA,
        transmit(
            0x00,
            0x87,
            algorithm & 0xFF,
            KEY_DYNAMIC & 0xFF,
            tlv(
                (byte) 0x7C,
                concat(tlv((byte) 0x81, new byte[block + 1]), tlv((byte) 0x82, new byte[0])))),
        "The challenge must be exactly one cipher block");
  }

  /**
   * Case 4 (witness request): the provider fault returns '6A80' and the witness issued by the
   * preceding Case 4 is abandoned with it.
   */
  @Test
  void providerFaultInWitnessRequestAbandonsTheExchange() throws Exception {
    provisionMutualManagementKey();
    assertSw(0x9000, selectApplet(), "SELECT before mutual authentication");
    byte[] witness = decryptWitness(requestWitness());

    AtomicInteger faults = new AtomicInteger();
    try (MockedStatic<?> crypto = failingEncrypt(faults)) {
      assertSw(
          ISO7816.SW_WRONG_DATA,
          transmit(0x00, 0x87, ALG_AES_128, KEY_CARD_MANAGEMENT & 0xFF, hex("7C028000")),
          "A provider fault while enciphering the witness is incorrect command data");
    }
    assertEquals(1, faults.get(), "The witness encryption must reach the provider once");

    assertSw(
        ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
        transmit(
            0x00,
            0x87,
            ALG_AES_128,
            KEY_CARD_MANAGEMENT & 0xFF,
            mutualResponse(witness, new byte[16])),
        "The earlier witness must not survive the failed request");
    assertSw(
        ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
        putProbe(),
        "9B is not authenticated after the abandoned exchange");
    assertMutualAuthenticationSucceeds();
  }

  /**
   * Case 5 (witness and challenge): the provider fault while enciphering the host challenge returns
   * '6A80', leaves 9B unauthenticated, and the verified witness cannot be replayed.
   */
  @Test
  void providerFaultInChallengeResponseLeavesTheKeyUnauthenticated() throws Exception {
    provisionMutualManagementKey();
    assertSw(0x9000, selectApplet(), "SELECT before mutual authentication");
    byte[] witness = decryptWitness(requestWitness());
    byte[] request = mutualResponse(witness, filled(16, (byte) 0x5A));

    AtomicInteger faults = new AtomicInteger();
    try (MockedStatic<?> crypto = failingEncrypt(faults)) {
      assertSw(
          ISO7816.SW_WRONG_DATA,
          transmit(0x00, 0x87, ALG_AES_128, KEY_CARD_MANAGEMENT & 0xFF, request),
          "A provider fault while enciphering the challenge is incorrect command data");
    }
    assertEquals(1, faults.get(), "The challenge encryption must reach the provider once");

    assertSw(
        ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
        putProbe(),
        "A failed Case 5 must not authenticate 9B");
    assertSw(
        ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
        transmit(0x00, 0x87, ALG_AES_128, KEY_CARD_MANAGEMENT & 0xFF, request),
        "The verified witness must not be accepted again");
    assertMutualAuthenticationSucceeds();
  }

  private void assertMutualAuthenticationSucceeds() throws Exception {
    byte[] witness = decryptWitness(requestWitness());
    byte[] challenge = filled(16, (byte) 0x3C);
    ResponseAPDU response =
        transmit(
            0x00,
            0x87,
            ALG_AES_128,
            KEY_CARD_MANAGEMENT & 0xFF,
            mutualResponse(witness, challenge));
    assertSw(0x9000, response, "Mutual authentication after the fault");
    assertArrayEquals(
        challenge,
        crypt(
            Cipher.DECRYPT_MODE,
            ALG_AES_128,
            StandardCardProfile.ADMIN_KEY,
            tlvValue(response.getData(), (byte) 0x82)),
        "The card enciphers the host challenge");
    assertSw(0x9000, putProbe(), "A completed mutual authentication authenticates 9B");
  }

  private ResponseAPDU requestWitness() {
    ResponseAPDU response =
        transmit(0x00, 0x87, ALG_AES_128, KEY_CARD_MANAGEMENT & 0xFF, hex("7C028000"));
    assertSw(0x9000, response, "Witness request");
    return response;
  }

  private static byte[] decryptWitness(ResponseAPDU response) throws Exception {
    return crypt(
        Cipher.DECRYPT_MODE,
        ALG_AES_128,
        StandardCardProfile.ADMIN_KEY,
        tlvValue(response.getData(), (byte) 0x80));
  }

  /** PUT DATA of an object whose administration requires 9B: '9000' only while 9B is verified. */
  private ResponseAPDU putProbe() {
    return transmit(0x00, 0xDB, 0x3F, 0xFF, concat(PROBE_OBJECT_TAG_LIST, hex("530100")));
  }

  private void provisionMutualManagementKey() {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before 9B provisioning");
          byte[] definition = StandardCardProfile.managementKeyDefinition(ALG_AES_128);
          definition[definition.length - 1] = ATTR_MUTUAL_IMPORTABLE;
          assertSw(0x9000, transmit(0x84, 0xDB, 0xFF, 0xFF, definition), "Define 9B");
          assertSw(
              0x9000,
              transmit(
                  0x84,
                  0x25,
                  0x01,
                  KEY_CARD_MANAGEMENT & 0xFF,
                  concat(
                      new byte[] {(byte) 0x80, 0x01, ALG_AES_128},
                      keyUpdateData(StandardCardProfile.ADMIN_KEY))),
              "Import 9B");
          assertSw(
              0x9000,
              transmit(0x84, 0xDB, 0xFF, 0xFF, hex("64128B035FFF108C017F8D017F91019B92020010")),
              "Create the 9B-administered probe object");
        });
  }

  private void provisionSymmetricKeyOverScp(
      final byte id, final byte algorithm, final byte attributes, final byte[] keyBytes) {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before symmetric key provisioning");
          assertSw(
              0x9000,
              transmit(
                  0x84,
                  0xDB,
                  0xFF,
                  0xFF,
                  new byte[] {
                    0x66,
                    0x12,
                    (byte) 0x8B,
                    0x01,
                    id,
                    (byte) 0x8C,
                    0x01,
                    0x7F,
                    (byte) 0x8D,
                    0x01,
                    0x00,
                    (byte) 0x8E,
                    0x01,
                    algorithm,
                    (byte) 0x8F,
                    0x01,
                    0x01,
                    (byte) 0x90,
                    0x01,
                    attributes
                  }),
              "Create symmetric key");
          assertSw(
              0x9000,
              transmit(
                  0x84,
                  0x25,
                  0x01,
                  id & 0xFF,
                  concat(new byte[] {(byte) 0x80, 0x01, algorithm}, keyUpdateData(keyBytes))),
              "Import symmetric key");
        });
  }

  /** {@code PIVCrypto.doEncrypt} raises {@code CryptoException.ILLEGAL_USE}; all else is real. */
  private MockedStatic<?> failingEncrypt(final AtomicInteger faults) throws Exception {
    Class<?> crypto = Class.forName(PIV_CRYPTO, true, appletClassLoader());
    return Mockito.mockStatic(
        crypto,
        invocation -> {
          if (!invocation.getMethod().getName().equals("doEncrypt")) {
            return invocation.callRealMethod();
          }
          faults.incrementAndGet();
          throw new CryptoException(CryptoException.ILLEGAL_USE);
        });
  }

  private ClassLoader appletClassLoader() throws Exception {
    Applet proxy = engine.getApplet(OPENFIPS201_AID);
    if (proxy.getClass().getName().equals(OpenFIPS201.class.getName())) {
      return proxy.getClass().getClassLoader();
    }
    for (Field proxyField : proxy.getClass().getDeclaredFields()) {
      if (!InvocationHandler.class.isAssignableFrom(proxyField.getType())) continue;
      proxyField.setAccessible(true);
      Object handler = proxyField.get(null);
      for (Field handlerField : handler.getClass().getDeclaredFields()) {
        handlerField.setAccessible(true);
        Object value = handlerField.get(handler);
        if (value instanceof Applet
            && value.getClass().getName().equals(OpenFIPS201.class.getName())) {
          return value.getClass().getClassLoader();
        }
      }
    }
    throw new IllegalStateException("Unable to unwrap simulator applet proxy");
  }

  private static byte[] mutualResponse(byte[] witness, byte[] challenge) {
    return tlv(
        (byte) 0x7C,
        concat(
            tlv((byte) 0x80, witness), tlv((byte) 0x81, challenge), tlv((byte) 0x82, new byte[0])));
  }

  private static byte[] keyMaterial(byte algorithm, byte seed) {
    int length;
    switch (algorithm) {
      case 0x03:
      case 0x0A:
        length = 24;
        break;
      case 0x0C:
        length = 32;
        break;
      default:
        length = 16;
    }
    byte[] key = new byte[length];
    for (int i = 0; i < length; i++) key[i] = (byte) (seed + 7 * i);
    return key;
  }

  private static byte[] crypt(int mode, byte algorithm, byte[] key, byte[] input) throws Exception {
    String primitive = algorithm == ALG_3DES ? "DESede" : "AES";
    Cipher cipher = Cipher.getInstance(primitive + "/ECB/NoPadding");
    cipher.init(mode, new SecretKeySpec(key, primitive));
    return cipher.doFinal(input);
  }

  private static byte[] filled(int length, byte value) {
    byte[] bytes = new byte[length];
    Arrays.fill(bytes, value);
    return bytes;
  }
}
