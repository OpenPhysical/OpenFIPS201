package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import apdu4j.core.BIBO;
import com.makina.security.openfips201.OpenFIPS201;
import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.io.ByteArrayOutputStream;
import java.util.function.Supplier;
import javacard.framework.AID;
import javacard.framework.APDU;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import pro.javacard.engine.JavaCardEngine;

/**
 * Shared test harness for OpenFIPS201 APDU command testing.
 *
 * <p>This harness intentionally talks to the card using raw APDUs through JCardEngine rather than
 * helper convenience layers. That keeps the tests close to what host middleware actually sends,
 * which is critical when testing APDU parsing edge cases (Lc, TLV shape, and command routing).
 */
abstract class OpenFIPS201TestSupport {
  // Production applet AID used by the project.
  protected static final byte[] OPENFIPS201_AID_BYTES = hex("A000000308000010000100");
  protected static final AID OPENFIPS201_AID =
      new AID(OPENFIPS201_AID_BYTES, (short) 0, (byte) OPENFIPS201_AID_BYTES.length);
  // CAP package AID, matching the ant-javacard <cap aid="..."> in build/build.xml.
  protected static final byte[] OPENFIPS201_PACKAGE_AID_BYTES = hex("A00000030800001000");
  protected static final AID OPENFIPS201_PACKAGE_AID =
      new AID(
          OPENFIPS201_PACKAGE_AID_BYTES, (short) 0, (byte) OPENFIPS201_PACKAGE_AID_BYTES.length);

  protected JavaCardEngine engine;
  protected BIBO session;

  @BeforeEach
  void setUpCard() {
    engine = createEngine();
    installApplet();
    session = engine.connect();
    if (provisionsStandardCard()) {
      provisionStandardTestCard();
    }
  }

  /**
   * Whether {@link #setUpCard()} provisions the deterministic standard test card (known PIN, PUK
   * and 9B admin key from {@link StandardCardProfile}). Tests that need a different or raw card
   * state — e.g. those exercising the random boot PUK, real SCP transport, or their own management
   * key — override this to return {@code false}.
   */
  protected boolean provisionsStandardCard() {
    return true;
  }

  protected static boolean isAttestationEnabledBuild() {
    return !"false".equalsIgnoreCase(System.getProperty("attestation.enabled", "true"));
  }

  /**
   * Provisions the deterministic standard test card: sets the local PIN and PUK and creates and
   * loads the 9B card management key, all from {@link StandardCardProfile} over a mocked secure
   * channel. This replaces the applet's random boot PIN/PUK so PIN-gated and admin operations are
   * reproducible.
   */
  protected void provisionStandardTestCard() {
    setLocalPinOverScp(StandardCardProfile.PIN);
    setPukOverScp(StandardCardProfile.PUK);
    provisionManagementKeyOverScp(StandardCardProfile.ADMIN_KEY_ALG, StandardCardProfile.ADMIN_KEY);
  }

  /** Sets the local PIN (reference 0x80) over a mocked administrative secure channel. */
  protected void setLocalPinOverScp(final byte[] pin) {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before admin PIN update");
          assertSw(
              0x9000,
              transmit(0x84, 0x24, 0x01, StandardCardProfile.LOCAL_PIN_REF & 0xFF, pin),
              "Administrative local PIN update");
        });
  }

  /** Sets the PUK (reference 0x81) over a mocked administrative secure channel. */
  protected void setPukOverScp(final byte[] puk) {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before admin PUK update");
          assertSw(
              0x9000,
              transmit(0x84, 0x24, 0x01, StandardCardProfile.PUK_REF & 0xFF, puk),
              "Administrative PUK update");
        });
  }

  /**
   * Creates and loads the 9B card management key with the given PIV mechanism over a mocked
   * administrative secure channel.
   */
  protected void provisionManagementKeyOverScp(final byte algorithm, final byte[] keyBytes) {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before SCP provisioning flow");
          assertSw(
              0x9000,
              transmit(
                  0x84, 0xDB, 0xFF, 0xFF, StandardCardProfile.managementKeyDefinition(algorithm)),
              "SCP create-key operation for 9B should succeed");
          assertSw(
              0x9000,
              transmit(
                  0x84,
                  0x25,
                  0x01,
                  StandardCardProfile.ADMIN_KEY_REF & 0xFF,
                  concat(
                      new byte[] {(byte) 0x80, (byte) 0x01, algorithm}, keyUpdateData(keyBytes))),
              "SCP initial key import for 9B should succeed");
        });
  }

  /** Wraps a key value in the administrative CHANGE REFERENCE DATA key-import structure. */
  protected static byte[] keyUpdateData(byte[] keyBytes) {
    return StandardCardProfile.keyUpdateData(keyBytes);
  }

  /** Deterministic AES-128 key material derived from a seed: {@code key[i] = seed + i}. */
  protected static byte[] keyMaterialAes128(byte seed) {
    byte[] key = new byte[0x10];
    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) (seed + i);
    }
    return key;
  }

  /**
   * Performs PIV external authentication with the 9B card-management key over plain APDUs.
   *
   * <p>This helper exercises the non-SCP authorization path. Administrative commands may instead be
   * authorized by an active GlobalPlatform secure channel; both paths are supported and tested.
   */
  protected void authenticateCardManagementKey(byte algorithm, byte[] keyBytes) {
    assertSw(
        0x9000,
        authenticateCardManagementKeyResponse(algorithm, keyBytes),
        "GENERAL AUTHENTICATE should accept the current 9B key");
  }

  /** Same plaintext 9B flow, returning the verification response for negative tests. */
  protected ResponseAPDU authenticateCardManagementKeyResponse(byte algorithm, byte[] keyBytes) {
    assertSw(0x9000, selectApplet(), "SELECT before plaintext 9B authentication");
    ResponseAPDU challengeResponse =
        transmit(
            0x00,
            0x87,
            algorithm & 0xFF,
            StandardCardProfile.ADMIN_KEY_REF & 0xFF,
            hex("7C028100"));
    assertSw(0x9000, challengeResponse, "9B challenge request");

    int blockLength = algorithm == (byte) 0x03 ? 8 : 16;
    byte[] challenge = tlvValue(challengeResponse.getData(), (byte) 0x81);
    assertEquals(blockLength, challenge.length, "Unexpected 9B challenge length");
    byte[] cryptogram = encryptManagementChallenge(algorithm, keyBytes, challenge);
    return transmit(
        0x00,
        0x87,
        algorithm & 0xFF,
        StandardCardProfile.ADMIN_KEY_REF & 0xFF,
        tlv((byte) 0x7C, tlv((byte) 0x82, cryptogram)));
  }

  protected static byte[] encryptManagementChallenge(
      byte algorithm, byte[] keyBytes, byte[] challenge) {
    try {
      boolean tripleDes = algorithm == (byte) 0x03;
      if (!tripleDes
          && algorithm != (byte) 0x08
          && algorithm != (byte) 0x0A
          && algorithm != (byte) 0x0C) {
        throw new IllegalArgumentException(
            "Unsupported PIV management-key algorithm: " + String.format("0x%02X", algorithm));
      }
      String primitive = tripleDes ? "DESede" : "AES";
      Cipher cipher = Cipher.getInstance(primitive + "/ECB/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, primitive));
      return cipher.doFinal(challenge);
    } catch (IllegalArgumentException e) {
      throw e;
    } catch (Exception e) {
      throw new IllegalStateException("Unable to compute 9B challenge response", e);
    }
  }

  protected JavaCardEngine createEngine() {
    return JavaCardEngine.create();
  }

  /**
   * Installs the applet into the simulator. The default is a direct engine install, which is fast
   * and sufficient for command parsing tests. Tests that need full GlobalPlatform fidelity (card
   * content managed through the ISD, e.g. real SCP03 transport tests) override this to install
   * through the GP load/INSTALL lifecycle instead.
   */
  protected void installApplet() {
    engine.installApplet(OPENFIPS201_AID, OpenFIPS201.class, new byte[0]);
  }

  @AfterEach
  void tearDownCard() {
    if (session != null) {
      session.close();
    }
  }

  /**
   * Issues a standard ISO 7816 SELECT by AID command.
   *
   * <p>Most tests call this first so command semantics are exercised in the same state as real card
   * usage.
   */
  protected ResponseAPDU selectApplet() {
    return transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0));
  }

  protected ResponseAPDU transmit(CommandAPDU command) {
    return new ResponseAPDU(session.transceive(command.getBytes()));
  }

  protected ResponseAPDU transmit(int cla, int ins, int p1, int p2) {
    return transmit(new CommandAPDU(cla, ins, p1, p2));
  }

  protected ResponseAPDU transmit(int cla, int ins, int p1, int p2, byte[] data) {
    return transmit(new CommandAPDU(cla, ins, p1, p2, data));
  }

  protected ResponseAPDU transmit(int cla, int ins, int p1, int p2, byte[] data, int le) {
    return transmit(new CommandAPDU(cla, ins, p1, p2, data, le));
  }

  /** Collects an ISO 7816 response chain using plaintext GET RESPONSE commands. */
  protected byte[] collectResponse(ResponseAPDU response, String context) {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    ResponseAPDU current = response;
    while ((current.getSW() & 0xFF00) == 0x6100) {
      output.write(current.getData(), 0, current.getData().length);
      int le = current.getSW2() == 0 ? 256 : current.getSW2();
      current = transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00, le));
    }
    assertSw(0x9000, current, context);
    output.write(current.getData(), 0, current.getData().length);
    return output.toByteArray();
  }

  protected static void assertSw(int expectedSw, ResponseAPDU response, String context) {
    assertEquals(
        expectedSw,
        response.getSW(),
        context
            + " expected SW="
            + Integer.toHexString(expectedSw)
            + " but was "
            + swHex(response));
  }

  /** Asserts a "63Cx retries remaining" status and returns retries as an integer. */
  protected static int assert63cxAndGetRetries(ResponseAPDU response, String context) {
    int sw = response.getSW();
    assertEquals(
        0x63C0,
        sw & 0xFFF0,
        context + " expected SW pattern 63Cx but was " + Integer.toHexString(sw));
    int retries = sw & 0x000F;
    assertTrue(retries >= 0 && retries <= 0x0F, context + " returned invalid retries nibble");
    return retries;
  }

  protected static String swHex(ResponseAPDU response) {
    return String.format("0x%04X", response.getSW());
  }

  protected static byte[] hex(String value) {
    String normalized = value.replace(" ", "").replace("\n", "").replace("\t", "");
    if ((normalized.length() & 1) != 0) {
      throw new IllegalArgumentException("Hex value must contain an even number of characters");
    }

    byte[] bytes = new byte[normalized.length() / 2];
    for (int i = 0; i < normalized.length(); i += 2) {
      int high = Character.digit(normalized.charAt(i), 16);
      int low = Character.digit(normalized.charAt(i + 1), 16);
      if (high < 0 || low < 0) {
        throw new IllegalArgumentException("Invalid hex character in: " + value);
      }
      bytes[i / 2] = (byte) ((high << 4) | low);
    }
    return bytes;
  }

  protected void withMockedScp(Runnable action) {
    withMockedScp(
        () -> {
          action.run();
          return null;
        });
  }

  /**
   * Runs an administrative operation with an authenticated SCP supplied by the test harness.
   *
   * <p>This models the SCP authorization alternative to plaintext 9B authentication. The applet
   * deliberately supports both paths.
   */
  protected <T> T withMockedScp(Supplier<T> action) {
    try (MockedStatic<GPSystem> mockedGp = Mockito.mockStatic(GPSystem.class)) {
      Mockito.when(GPSystem.getCardContentState()).thenReturn(GPSystem.APPLICATION_SELECTABLE);
      SecureChannel secureChannel = Mockito.mock(SecureChannel.class);
      Mockito.when(secureChannel.getSecurityLevel())
          .thenReturn(
              (byte)
                  (SecureChannel.AUTHENTICATED | SecureChannel.C_DECRYPTION | SecureChannel.C_MAC));
      Mockito.when(
              secureChannel.unwrap(
                  Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyShort()))
          .thenAnswer(invocation -> (short) invocation.getArgument(2));
      Mockito.when(GPSystem.getSecureChannel()).thenReturn(secureChannel);
      return action.get();
    }
  }

  /** Runs an APDU flow with Java Card's transport reported as ISO 14443 contactless Type A. */
  protected void withContactless(Runnable action) {
    try (MockedStatic<APDU> mockedApdu = Mockito.mockStatic(APDU.class)) {
      mockedApdu
          .when(APDU::getProtocol)
          .thenReturn((byte) (APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A | APDU.PROTOCOL_T1));
      action.run();
    }
  }

  protected static byte[] tlv(byte tag, byte[] value) {
    byte[] length = derLength(value.length);
    byte[] result = new byte[1 + length.length + value.length];
    result[0] = tag;
    System.arraycopy(length, 0, result, 1, length.length);
    System.arraycopy(value, 0, result, 1 + length.length, value.length);
    return result;
  }

  protected static byte[] derLength(int length) {
    if (length < 0x80) {
      return new byte[] {(byte) length};
    }
    if (length < 0x100) {
      return new byte[] {(byte) 0x81, (byte) length};
    }
    return new byte[] {(byte) 0x82, (byte) (length >> 8), (byte) length};
  }

  protected static byte[] concat(byte[]... arrays) {
    int length = 0;
    for (byte[] array : arrays) {
      length += array.length;
    }

    byte[] output = new byte[length];
    int offset = 0;
    for (byte[] array : arrays) {
      System.arraycopy(array, 0, output, offset, array.length);
      offset += array.length;
    }
    return output;
  }

  protected static byte[] tlvValue(byte[] data, byte tag) {
    int offset = 0;
    // Test responses commonly wrap the requested primitive in a dynamic-authentication (7C) or
    // two-byte application (7Fxx) template. Enter that outer value before scanning its children.
    if (data.length > 0 && data[0] != tag && (data[0] == (byte) 0x7C || data[0] == (byte) 0x7F)) {
      offset = contentOffset(data, 0);
    }
    while (offset < data.length) {
      int currentTag = data[offset++] & 0xFF;
      if ((currentTag & 0x1F) == 0x1F) {
        currentTag = ((currentTag << 8) | (data[offset++] & 0xFF)) & 0xFFFF;
      }
      int lengthOffset = offset;
      int valueOffset = contentOffset(data, offset - 1);
      int length = derLength(data, lengthOffset);
      if (((byte) currentTag) == tag) {
        byte[] value = new byte[length];
        System.arraycopy(data, valueOffset, value, 0, length);
        return value;
      }
      offset = valueOffset + length;
    }
    throw new IllegalArgumentException("Tag not found: " + String.format("0x%02X", tag));
  }

  protected static int contentOffset(byte[] data, int tagOffset) {
    int lengthOffset = tagOffset + 1;
    if ((data[tagOffset] & 0x1F) == 0x1F) {
      lengthOffset++;
    }
    int firstLength = data[lengthOffset] & 0xFF;
    if ((firstLength & 0x80) == 0) return lengthOffset + 1;
    return lengthOffset + 1 + (firstLength & 0x7F);
  }

  protected static int derLength(byte[] data, int lengthOffset) {
    int firstLength = data[lengthOffset] & 0xFF;
    if ((firstLength & 0x80) == 0) return firstLength;
    int length = 0;
    int count = firstLength & 0x7F;
    for (int i = 0; i < count; i++) {
      length = (length << 8) | (data[lengthOffset + 1 + i] & 0xFF);
    }
    return length;
  }
}
