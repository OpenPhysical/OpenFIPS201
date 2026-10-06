package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import javacard.framework.Applet;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Test;

/**
 * Protected commands whose plaintext is larger than any short command APDU data field.
 *
 * <p>SP 800-73-5 Part 2 Section 4.2.4: the card "reconstructs and processes the entire command".
 * The protected command arrives as an ISO/IEC 7816-4 command chain ('1C' frames, then '0C'), is
 * unwrapped once into the secure-messaging command buffer, and every handler must read its data
 * from that reassembled plaintext rather than from the final transport frame. Each test sends a
 * plaintext of more than 255 octets for CHANGE REFERENCE DATA ('24'), the proprietary key update
 * ('25') and GENERATE ASYMMETRIC KEY PAIR ('47') and checks both the protected application status
 * (Section 4.2.6 '99' template, SW processing status '90 00') and the resulting card state.
 *
 * <p>The session is the synthetic one of the white-box dispatch tests (all-zero session keys, zero
 * MCV, encryption counter 1), established afresh before each protected command.
 */
class OpenFIPS201LargeSecureMessagingCommandTest extends OpenFIPS201TestSupport {
  private static final byte CLA_SM = (byte) 0x0C;
  private static final byte CLA_SM_CHAINED = (byte) 0x1C;
  private static final byte ALG_RSA_2048 = (byte) 0x07;
  private static final byte KEY_AUTHENTICATION = (byte) 0x9A;
  private static final byte KEY_MANAGEMENT = (byte) 0x9D;
  private static final byte ROLE_SIGN = (byte) 0x04;
  private static final byte ROLE_KEY_ESTABLISH = (byte) 0x02;
  private static final byte ATTR_NONE = (byte) 0x00;
  private static final byte ATTR_IMPORTABLE = (byte) 0x10;
  private static final int RSA_2048_BYTES = 256;
  private static final int SHORT_APDU_MAX_DATA = 255;
  private static final int FRAGMENT = 200;

  /**
   * An RSA-2048 key arrives as three proprietary key updates ('25', P1 '01'). The modulus and the
   * private exponent each carry a 267-octet plaintext. The imported pair must complete its
   * pair-wise consistency test and then recover a key-transport block.
   */
  @Test
  void protectedKeyUpdateImportsRsaComponentsFromTheReassembledPlaintext() throws Exception {
    KeyPair pair = rsaKeyPair();
    defineKey(KEY_MANAGEMENT, ROLE_KEY_ESTABLISH, ATTR_IMPORTABLE);

    byte[] modulus = keyUpdate(0x81, fixed(((RSAPublicKey) pair.getPublic()).getModulus()));
    byte[] exponent =
        keyUpdate(0x83, fixed(((RSAPrivateKey) pair.getPrivate()).getPrivateExponent()));
    assertTrue(modulus.length > SHORT_APDU_MAX_DATA, "modulus update exceeds a short APDU");
    assertTrue(exponent.length > SHORT_APDU_MAX_DATA, "exponent update exceeds a short APDU");

    authenticateCardManagementKey(StandardCardProfile.ADMIN_KEY_ALG, StandardCardProfile.ADMIN_KEY);
    assertProtectedStatus(0x9000, protectedCommand(0x25, 0x01, KEY_MANAGEMENT, modulus), "modulus");
    // The completed update clears the 9B authentication, so the handler ran to its last step.
    assertProtectedStatus(
        0x6982,
        protectedCommand(0x25, 0x01, KEY_MANAGEMENT, keyUpdate(0x82, hex("010001"))),
        "update after the 9B authentication was consumed");

    authenticateCardManagementKey(StandardCardProfile.ADMIN_KEY_ALG, StandardCardProfile.ADMIN_KEY);
    assertProtectedStatus(
        0x9000,
        protectedCommand(0x25, 0x01, KEY_MANAGEMENT, keyUpdate(0x82, hex("010001"))),
        "public exponent");
    authenticateCardManagementKey(StandardCardProfile.ADMIN_KEY_ALG, StandardCardProfile.ADMIN_KEY);
    assertProtectedStatus(
        0x9000, protectedCommand(0x25, 0x01, KEY_MANAGEMENT, exponent), "private exponent");

    assertSw(0x9000, transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN), "VERIFY");
    byte[] representative = new byte[RSA_2048_BYTES];
    Arrays.fill(representative, (byte) 0x39);
    representative[0] = 0;
    Cipher rsa = Cipher.getInstance("RSA/ECB/NoPadding");
    rsa.init(Cipher.ENCRYPT_MODE, pair.getPublic());
    byte[] response =
        collectResponse(
            transmitChained(
                0x00,
                0x87,
                ALG_RSA_2048,
                KEY_MANAGEMENT & 0xFF,
                tlv(
                    (byte) 0x7C,
                    concat(
                        tlv((byte) 0x82, new byte[0]),
                        tlv((byte) 0x81, rsa.doFinal(representative))))),
            "RSA key transport with the imported pair");
    assertArrayEquals(
        representative,
        fixed(new BigInteger(1, tlvValue(tlvValue(response, (byte) 0x7C), (byte) 0x82))),
        "the card holds exactly the pair imported through secure messaging");
  }

  /**
   * SP 800-73-5 Part 2 Section 3.2.2: the CHANGE REFERENCE DATA data field is the current and the
   * new reference data, sixteen octets for key reference '80'. A 260-octet protected plaintext is
   * an "Incorrect parameter in command data field" ('6A 80'), returned in the '99' template, and
   * "the security status and retry counter associated with the key reference shall remain
   * unchanged".
   */
  @Test
  void protectedChangeReferenceDataRejectsAnOversizedPlaintextWithoutSideEffects()
      throws Exception {
    assertSw(0x9000, selectApplet(), "SELECT");
    int retries = assert63cxAndGetRetries(transmit(0x00, 0x20, 0x00, 0x80), "PIN status");
    byte[] oversized = new byte[260];
    for (int i = 0; i < 8; i++) oversized[i] = StandardCardProfile.PIN[i];
    Arrays.fill(oversized, 8, oversized.length, (byte) 0x31);

    assertProtectedStatus(
        0x6A80, protectedCommand(0x24, 0x00, (byte) 0x80, oversized), "oversized CRD");

    assertEquals(
        retries,
        assert63cxAndGetRetries(transmit(0x00, 0x20, 0x00, 0x80), "PIN status"),
        "the retry counter is unchanged");
    assertSw(
        0x9000, transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN), "the PIN is unchanged");
  }

  /**
   * SP 800-73-5 Part 1 Section 5.3 Table 6 defines the GENERATE parameter '81' as the RSA public
   * exponent, and SP 800-78-5 Section 3.1 requires 65537. A template whose 256-octet exponent makes
   * the protected plaintext 267 octets is parsed from the reassembled buffer and refused with '6A
   * 80' (Section 3.3.2, "Incorrect parameter in command data field"); no key pair is generated.
   */
  @Test
  void protectedGenerateParsesTheReassembledTemplate() throws Exception {
    defineKey(KEY_AUTHENTICATION, ROLE_SIGN, ATTR_NONE);
    authenticateCardManagementKey(StandardCardProfile.ADMIN_KEY_ALG, StandardCardProfile.ADMIN_KEY);
    byte[] exponent = new byte[RSA_2048_BYTES];
    exponent[RSA_2048_BYTES - 3] = 0x01;
    exponent[RSA_2048_BYTES - 1] = 0x01;
    byte[] template = tlv((byte) 0xAC, concat(hex("800107"), tlv((byte) 0x81, exponent)));
    assertTrue(template.length > SHORT_APDU_MAX_DATA, "template exceeds a short APDU");

    assertProtectedStatus(
        0x6A80,
        protectedCommand(0x47, 0x00, KEY_AUTHENTICATION, template),
        "padded public exponent");

    assertSw(0x9000, transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN), "VERIFY");
    ResponseAPDU sign =
        transmitChained(
            0x00,
            0x87,
            ALG_RSA_2048,
            KEY_AUTHENTICATION & 0xFF,
            tlv(
                (byte) 0x7C,
                concat(tlv((byte) 0x82, new byte[0]), tlv((byte) 0x81, new byte[RSA_2048_BYTES]))));
    assertSw(0x6A86, sign, "no key pair was generated for 9A");
  }

  /**
   * Establishes a fresh synthetic session, then sends {@code plaintext} as one protected command
   * split into chained frames, and returns the response to the final frame.
   */
  private ResponseAPDU protectedCommand(int ins, int p1, byte p2, byte[] plaintext)
      throws Exception {
    establishSyntheticSession();
    byte[] header = {(byte) ins, (byte) p1, p2};
    byte[] body = protectedBody(header, plaintext);
    ResponseAPDU response = null;
    for (int offset = 0; offset < body.length; offset += FRAGMENT) {
      int length = Math.min(FRAGMENT, body.length - offset);
      boolean last = offset + length == body.length;
      response =
          transmit(
              new CommandAPDU(
                  last ? CLA_SM : CLA_SM_CHAINED,
                  ins,
                  p1,
                  p2 & 0xFF,
                  Arrays.copyOfRange(body, offset, offset + length),
                  last ? 256 : 0));
      if (!last) assertSw(0x9000, response, "intermediate protected frame");
    }
    return response;
  }

  /** SP 800-73-5 Part 2 Section 4.2.6 response: '99' status, then '8E' over the zero MCV. */
  private static void assertProtectedStatus(int status, ResponseAPDU response, String context) {
    assertSw(0x9000, response, context + ": SW processing status");
    byte[] statusObject = {(byte) 0x99, 0x02, (byte) (status >> 8), (byte) status};
    byte[] macInput = concat(new byte[16], statusObject);
    byte[] mac = Arrays.copyOf(cmac(macInput), 8);
    assertArrayEquals(
        concat(statusObject, new byte[] {(byte) 0x8E, 0x08}, mac),
        response.getData(),
        context + ": protected status " + Integer.toHexString(status));
  }

  /** '87' (indicator '01', AES-CBC ciphertext under IV = E(K_ENC, counter 1)) then '8E'. */
  private static byte[] protectedBody(byte[] header, byte[] plaintext) throws Exception {
    byte[] padded = Arrays.copyOf(plaintext, plaintext.length + 16 - plaintext.length % 16);
    padded[plaintext.length] = (byte) 0x80;
    byte[] counter = new byte[16];
    counter[15] = 1;
    Cipher ecb = Cipher.getInstance("AES/ECB/NoPadding");
    ecb.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionKey(), "AES"));
    Cipher cbc = Cipher.getInstance("AES/CBC/NoPadding");
    cbc.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(sessionKey(), "AES"),
        new IvParameterSpec(ecb.doFinal(counter)));
    byte[] encrypted = tlv((byte) 0x87, concat(new byte[] {0x01}, cbc.doFinal(padded)));
    byte[] macHeader = new byte[16];
    macHeader[0] = CLA_SM;
    System.arraycopy(header, 0, macHeader, 1, 3);
    macHeader[4] = (byte) 0x80;
    byte[] mac = Arrays.copyOf(cmac(concat(new byte[16], macHeader, encrypted)), 8);
    return concat(encrypted, new byte[] {(byte) 0x8E, 0x08}, mac);
  }

  private static byte[] cmac(byte[] input) {
    CMac cmac = new CMac(AESEngine.newInstance());
    cmac.init(new KeyParameter(sessionKey()));
    cmac.update(input, 0, input.length);
    byte[] mac = new byte[16];
    cmac.doFinal(mac, 0);
    return mac;
  }

  private static byte[] sessionKey() {
    boolean cs7 = "CS7".equalsIgnoreCase(System.getProperty("vci.suite", "CS2"));
    return new byte[cs7 ? 32 : 16];
  }

  /** Loads all-zero SK_CFRM, SK_MAC, SK_ENC and SK_RMAC and resets MCV and counter. */
  private void establishSyntheticSession() throws Exception {
    Method asCurrent = engine.getClass().getMethod("asCurrent");
    asCurrent.setAccessible(true);
    try (AutoCloseable ignored = (AutoCloseable) asCurrent.invoke(engine)) {
      Applet applet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(applet, "piv").get(applet);
      Object sm = field(piv, "secureMessaging").get(piv);
      Class<?> opacity =
          Class.forName(
              "com.makina.security.openfips201.PIVOpacity", true, sm.getClass().getClassLoader());
      short keyLength = field(opacity, "SESSION_KEY_LENGTH").getShort(null);
      method(sm.getClass(), "setSessionKeys", byte[].class, short.class, short.class)
          .invoke(sm, new byte[sessionKey().length * 4], (short) 0, keyLength);
      method(sm.getClass(), "markEstablished", boolean.class).invoke(sm, false);
    }
  }

  private void defineKey(byte reference, byte role, byte attributes) {
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
                    reference,
                    (byte) 0x8C,
                    0x01,
                    0x01,
                    (byte) 0x8D,
                    0x01,
                    0x09,
                    (byte) 0x8E,
                    0x01,
                    ALG_RSA_2048,
                    (byte) 0x8F,
                    0x01,
                    role,
                    (byte) 0x90,
                    0x01,
                    attributes
                  }),
              "Define the RSA-2048 key");
        });
  }

  /** Proprietary key update data: '80 01' algorithm, then a one-element key-update sequence. */
  private static byte[] keyUpdate(int tag, byte[] value) {
    return concat(
        new byte[] {(byte) 0x80, 0x01, ALG_RSA_2048}, tlv((byte) 0x30, tlv((byte) tag, value)));
  }

  private static KeyPair rsaKeyPair() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
    return generator.generateKeyPair();
  }

  private static byte[] fixed(BigInteger value) {
    byte[] encoded = value.toByteArray();
    byte[] result = new byte[RSA_2048_BYTES];
    int sourceOffset = Math.max(0, encoded.length - RSA_2048_BYTES);
    int copyLength = Math.min(encoded.length, RSA_2048_BYTES);
    System.arraycopy(encoded, sourceOffset, result, RSA_2048_BYTES - copyLength, copyLength);
    return result;
  }

  private static Applet unwrapApplet(Applet proxy) throws Exception {
    for (Field proxyField : proxy.getClass().getDeclaredFields()) {
      if (!InvocationHandler.class.isAssignableFrom(proxyField.getType())) continue;
      proxyField.setAccessible(true);
      Object handler = proxyField.get(null);
      for (Field handlerField : handler.getClass().getDeclaredFields()) {
        handlerField.setAccessible(true);
        Object value = handlerField.get(handler);
        if (value instanceof Applet
            && value.getClass().getName().equals("com.makina.security.openfips201.OpenFIPS201")) {
          return (Applet) value;
        }
      }
    }
    throw new IllegalStateException("Unable to unwrap simulator applet proxy");
  }

  private static Field field(Object target, String name) throws Exception {
    return field(target.getClass(), name);
  }

  private static Field field(Class<?> type, String name) throws Exception {
    Field field = type.getDeclaredField(name);
    field.setAccessible(true);
    return field;
  }

  private static Method method(Class<?> type, String name, Class<?>... parameterTypes)
      throws Exception {
    Method method = type.getDeclaredMethod(name, parameterTypes);
    method.setAccessible(true);
    return method;
  }
}
