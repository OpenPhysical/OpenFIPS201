package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.makina.security.openfips201.OpenFIPS201;
import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.security.CryptoException;
import javax.crypto.Cipher;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * Provider faults and malformed key material at the card edge.
 *
 * <p>A {@code CryptoException} raised by the cryptographic provider is reported as "Incorrect
 * parameter in command data field" ('6A80', SP 800-73-5 Part 2 Sections 3.2.2 and 3.2.4) and never
 * leaves usable partial state: a key whose pair-wise consistency test faulted is cleared, and SP
 * 800-73-5 Part 2 Section 2.4.2 requires "An aborted or failed execution of an authentication
 * protocol" to abandon the exchange. The faults are injected by intercepting {@code PIVCrypto} in
 * the class loader that loaded the installed applet.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class OpenFIPS201CryptoFaultTest extends OpenFIPS201TestSupport {
  private static final byte ALG_RSA_2048 = (byte) 0x07;
  private static final byte ALG_ECC_P256 = (byte) 0x11;
  private static final byte ALG_AES_128 = StandardCardProfile.ADMIN_KEY_ALG;
  private static final byte KEY_MANAGEMENT = (byte) 0x9D;
  private static final byte KEY_CARD_MANAGEMENT = StandardCardProfile.ADMIN_KEY_REF;
  private static final byte ROLE_KEY_ESTABLISH = (byte) 0x02;
  private static final byte ATTR_NONE = (byte) 0x00;
  private static final byte ATTR_IMPORTABLE = (byte) 0x10;
  private static final int RSA_2048_BYTES = 256;
  private static final String PIV_CRYPTO = "com.makina.security.openfips201.PIVCrypto";

  /**
   * The RSA private-key sign of the import pair-wise consistency test faults inside the provider.
   * The import is refused with '6A80' and every imported component is cleared, so the exponent
   * alone cannot complete a pair afterwards.
   */
  @Test
  void providerFaultInRsaImportConsistencyTestClearsTheKey() throws Exception {
    KeyPair pair = rsaKeyPair();
    defineKey(ALG_RSA_2048, ATTR_IMPORTABLE);
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before RSA import");
          assertSw(0x9000, importRsaElement(0x81, modulus(pair)), "Import the modulus");
          assertSw(0x9000, importRsaElement(0x82, hex("010001")), "Import the public exponent");
        });

    AtomicInteger faults = new AtomicInteger();
    try (MockedStatic<?> crypto =
        failingCrypto("doSign", javacard.security.RSAPrivateKey.class, faults)) {
      withMockedScp(
          () ->
              assertSw(
                  ISO7816.SW_WRONG_DATA,
                  importRsaElement(0x83, privateExponent(pair)),
                  "A provider fault in the consistency-test signature is incorrect command data"));
    }
    assertEquals(1, faults.get(), "The consistency test must reach the provider exactly once");

    // The fault cleared the modulus and public exponent too, so this exponent completes nothing.
    withMockedScp(
        () ->
            assertSw(
                0x9000,
                importRsaElement(0x83, privateExponent(pair)),
                "Import the private exponent into the cleared key"));
    assertSw(0x9000, transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN), "VERIFY");
    assertSw(
        ISO7816.SW_INCORRECT_P1P2,
        keyTransport(new byte[RSA_2048_BYTES]),
        "A cleared key is not initialised for GENERAL AUTHENTICATE");

    withMockedScp(
        () -> {
          assertSw(0x9000, importRsaElement(0x81, modulus(pair)), "Re-import the modulus");
          assertSw(0x9000, importRsaElement(0x82, hex("010001")), "Re-import the exponent");
        });
    assertKeyTransportRecovers(pair);
  }

  /**
   * ECDH inside GENERAL AUTHENTICATE faults in the provider. The command returns '6A80', the
   * authentication context is abandoned, so a challenge requested before the failure is no longer
   * accepted, and the key and PIN remain usable.
   */
  @Test
  void providerFaultInKeyAgreementAbandonsTheAuthenticationContext() throws Exception {
    defineKey(ALG_ECC_P256, ATTR_NONE);
    withMockedScp(
        () ->
            collectResponse(
                transmit(0x84, 0x47, 0x00, KEY_MANAGEMENT & 0xFF, hex("AC03800111"), 256),
                "Generate the key-management key"));
    assertSw(0x9000, selectApplet(), "SELECT before key establishment");
    assertSw(0x9000, transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN), "VERIFY");

    ResponseAPDU challengeResponse =
        transmit(0x00, 0x87, ALG_AES_128 & 0xFF, KEY_CARD_MANAGEMENT & 0xFF, hex("7C028100"));
    assertSw(0x9000, challengeResponse, "9B challenge request");
    byte[] challenge = tlvValue(challengeResponse.getData(), (byte) 0x81);

    byte[] hostPoint = p256Point();
    AtomicInteger faults = new AtomicInteger();
    try (MockedStatic<?> crypto =
        failingCrypto("doKeyAgreement", javacard.security.ECPrivateKey.class, faults)) {
      assertSw(
          ISO7816.SW_WRONG_DATA,
          transmit(0x00, 0x87, ALG_ECC_P256, KEY_MANAGEMENT & 0xFF, keyAgreementRequest(hostPoint)),
          "A provider fault in ECDH is incorrect command data");
    }
    assertEquals(1, faults.get(), "Key agreement must reach the provider exactly once");

    byte[] cryptogram =
        encryptManagementChallenge(ALG_AES_128, StandardCardProfile.ADMIN_KEY, challenge);
    assertSw(
        ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
        transmit(
            0x00,
            0x87,
            ALG_AES_128 & 0xFF,
            KEY_CARD_MANAGEMENT & 0xFF,
            tlv((byte) 0x7C, tlv((byte) 0x82, cryptogram))),
        "The challenge issued before the failed command must not be accepted");

    assertSw(
        0x9000,
        transmit(0x00, 0x20, 0x00, 0x80),
        "The PIN security status survives the failed key establishment");
    ResponseAPDU agreement =
        transmit(0x00, 0x87, ALG_ECC_P256, KEY_MANAGEMENT & 0xFF, keyAgreementRequest(hostPoint));
    assertSw(0x9000, agreement, "Key establishment succeeds once the provider recovers");
    assertEquals(
        32,
        tlvValue(tlvValue(agreement.getData(), (byte) 0x7C), (byte) 0x82).length,
        "Shared secret");
  }

  /**
   * SP 800-78-5 Section 3.1 Table 1: an RSA-2048 key has a 2048-bit modulus. A 255-octet (2040-bit)
   * modulus sent as a chained administrative CHANGE REFERENCE DATA is refused as a wrong element
   * length ('6700'), the same status as an imported ECC point of the wrong length, and leaves no
   * key material behind.
   */
  @Test
  void chainedShortRsaModulusIsRejected() throws Exception {
    KeyPair pair = rsaKeyPair();
    byte[] modulus255 = new byte[RSA_2048_BYTES - 1];
    Arrays.fill(modulus255, (byte) 0xA5);
    modulus255[0] = (byte) 0xC3;
    defineKey(ALG_RSA_2048, ATTR_IMPORTABLE);
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before RSA import");
          assertSw(
              ISO7816.SW_WRONG_LENGTH,
              transmitChained(
                  0x84,
                  0x24,
                  ALG_RSA_2048,
                  KEY_MANAGEMENT & 0xFF,
                  tlv((byte) 0x30, tlv((byte) 0x81, modulus255))),
              "A 2040-bit modulus does not fill an RSA-2048 key");
          assertSw(0x9000, importRsaElement(0x82, hex("010001")), "Import the public exponent");
          assertSw(0x9000, importRsaElement(0x83, privateExponent(pair)), "Import the exponent");
        });
    assertSw(0x9000, transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN), "VERIFY");
    assertSw(
        ISO7816.SW_INCORRECT_P1P2,
        keyTransport(new byte[RSA_2048_BYTES]),
        "Without a modulus the key is not initialised");

    withMockedScp(
        () ->
            assertSw(
                0x9000,
                importRsaElement(0x81, modulus(pair)),
                "The full 2048-bit modulus completes the pair"));
    assertKeyTransportRecovers(pair);
  }

  private void defineKey(final byte mechanism, final byte attributes) {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before key definition");
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
                    KEY_MANAGEMENT,
                    (byte) 0x8C,
                    0x01,
                    0x01,
                    (byte) 0x8D,
                    0x01,
                    0x09,
                    (byte) 0x8E,
                    0x01,
                    mechanism,
                    (byte) 0x8F,
                    0x01,
                    ROLE_KEY_ESTABLISH,
                    (byte) 0x90,
                    0x01,
                    attributes
                  }),
              "Define the key-management key");
        });
  }

  private ResponseAPDU importRsaElement(int tag, byte[] value) {
    return transmitChained(
        0x84, 0x24, ALG_RSA_2048, KEY_MANAGEMENT & 0xFF, tlv((byte) 0x30, tlv((byte) tag, value)));
  }

  private ResponseAPDU keyTransport(byte[] block) {
    return transmitChained(
        0x00,
        0x87,
        ALG_RSA_2048,
        KEY_MANAGEMENT & 0xFF,
        tlv((byte) 0x7C, concat(tlv((byte) 0x82, new byte[0]), tlv((byte) 0x81, block))));
  }

  private void assertKeyTransportRecovers(KeyPair pair) throws Exception {
    assertSw(0x9000, transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN), "VERIFY");
    byte[] representative = new byte[RSA_2048_BYTES];
    Arrays.fill(representative, (byte) 0x39);
    representative[0] = 0;
    Cipher rsa = Cipher.getInstance("RSA/ECB/NoPadding");
    rsa.init(Cipher.ENCRYPT_MODE, pair.getPublic());
    byte[] response =
        collectResponse(keyTransport(rsa.doFinal(representative)), "RSA key transport");
    byte[] recovered = tlvValue(tlvValue(response, (byte) 0x7C), (byte) 0x82);
    assertArrayEquals(
        representative,
        fixed(new BigInteger(1, recovered), RSA_2048_BYTES),
        "The card holds exactly the imported pair");
  }

  /**
   * Intercepts {@code PIVCrypto} in the applet class loader: the named method whose first parameter
   * has the given type raises {@code CryptoException.ILLEGAL_VALUE}; every other method runs
   * unchanged.
   */
  private MockedStatic<?> failingCrypto(
      final String name, final Class<?> firstParameter, final AtomicInteger faults)
      throws Exception {
    Class<?> crypto = Class.forName(PIV_CRYPTO, true, appletClassLoader());
    return Mockito.mockStatic(
        crypto,
        invocation -> {
          Method method = invocation.getMethod();
          if (method.getName().equals(name)
              && method.getParameterTypes().length > 0
              && method.getParameterTypes()[0] == firstParameter) {
            faults.incrementAndGet();
            throw new CryptoException(CryptoException.ILLEGAL_VALUE);
          }
          return invocation.callRealMethod();
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

  private static byte[] keyAgreementRequest(byte[] point) {
    return tlv((byte) 0x7C, concat(tlv((byte) 0x82, new byte[0]), tlv((byte) 0x85, point)));
  }

  private static byte[] p256Point() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    ECPublicKey key = (ECPublicKey) generator.generateKeyPair().getPublic();
    return concat(
        new byte[] {0x04}, fixed(key.getW().getAffineX(), 32), fixed(key.getW().getAffineY(), 32));
  }

  private static KeyPair rsaKeyPair() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
    return generator.generateKeyPair();
  }

  private static byte[] modulus(KeyPair pair) {
    return fixed(((RSAPublicKey) pair.getPublic()).getModulus(), RSA_2048_BYTES);
  }

  private static byte[] privateExponent(KeyPair pair) {
    return fixed(((RSAPrivateKey) pair.getPrivate()).getPrivateExponent(), RSA_2048_BYTES);
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
