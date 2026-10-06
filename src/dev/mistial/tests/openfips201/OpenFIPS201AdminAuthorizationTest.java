package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import com.makina.security.openfips201.OpenFIPS201;
import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javacard.framework.Applet;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * Interface and authorization rules for administrative commands and for PIN-protected private keys.
 *
 * <p>The PIN-protected key rules run for ECC P-256 and RSA-2048 keys, over the contact interface
 * and over the VCI. Tests over the VCI enable contactless PIN use and hold the applet's VCI
 * condition true (see {@link #satisfyVciCondition()}); establishing the VCI itself is covered by
 * the VCI end-to-end tests.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class OpenFIPS201AdminAuthorizationTest extends OpenFIPS201TestSupport {

  private static final boolean FIPS_MODE = Boolean.getBoolean("fips.mode");
  private static final byte ROLE_KEY_ESTABLISH = (byte) 0x02;
  private static final byte ROLE_SIGN = (byte) 0x04;
  // SP 800-73-5 Part 1 Table 5 access rules: PIN (01) or PIN Always (02) over contact, the same
  // with VCI (08) over contactless.
  private static final int MODE_PIN = 0x01;
  private static final int MODE_PIN_ALWAYS = 0x02;
  private static final int MODE_VCI_PIN = 0x09;
  private static final int MODE_VCI_PIN_ALWAYS = 0x0A;
  private static final byte[] REPLACEMENT = hex("3939393939393939");
  // P-256 base point G (SEC 2 Section 2.4.2), a valid ECDH peer public key.
  private static final byte[] P256_G =
      hex(
          "04"
              + "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
              + "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");

  /** The asymmetric mechanism of a PIN-protected key (SP 800-78-5 Table 6-2). */
  enum KeyAlgorithm {
    ECC_P256((byte) 0x11),
    RSA_2048((byte) 0x07);

    final byte id;

    KeyAlgorithm(byte id) {
      this.id = id;
    }
  }

  /** The interface a key-use test runs over. */
  enum Channel {
    CONTACT,
    /** Contactless over the VCI, with contactless PIN use enabled. */
    VCI
  }

  static List<Arguments> algorithmsAndChannels() {
    List<Arguments> arguments = new ArrayList<>();
    for (KeyAlgorithm algorithm : KeyAlgorithm.values()) {
      for (Channel channel : Channel.values()) {
        arguments.add(Arguments.of(algorithm, channel));
      }
    }
    return arguments;
  }

  /**
   * With contactless administration restricted (the default), a 9B session established over
   * contactless must not replace the PIN or PUK through any proprietary form, INS 24 P1=01
   * included.
   */
  @Test
  void contactlessManagementKeySessionCannotReplacePinOrPuk() {
    assumeFalse(FIPS_MODE, "The FIPS profile fixes the 9B contactless access rule to NEVER");
    byte[] definition =
        StandardCardProfile.managementKeyDefinition(StandardCardProfile.ADMIN_KEY_ALG);
    definition[10] = (byte) 0x7F; // 8D: 9B usable over contactless
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before 9B redefinition");
          assertSw(
              0x9000,
              transmit(0x84, 0xDB, 0xFF, 0xFF, hex("6706 8B019B 8E0108")),
              "Delete the contact-only 9B");
          assertSw(0x9000, transmit(0x84, 0xDB, 0xFF, 0xFF, definition), "Create contactless 9B");
          assertSw(
              0x9000,
              transmit(
                  0x84,
                  0x25,
                  0x01,
                  0x9B,
                  concat(
                      new byte[] {(byte) 0x80, (byte) 0x01, StandardCardProfile.ADMIN_KEY_ALG},
                      keyUpdateData(StandardCardProfile.ADMIN_KEY))),
              "Import 9B");
        });

    withContactless(
        () -> {
          authenticateCardManagementKey(
              StandardCardProfile.ADMIN_KEY_ALG, StandardCardProfile.ADMIN_KEY);
          assertSw(
              0x6982,
              transmit(0x80, 0x24, 0x01, 0x80, REPLACEMENT),
              "INS 24 P1=01 must not replace the PIN over contactless");
          assertSw(
              0x6982,
              transmit(0x80, 0x24, 0x01, 0x81, REPLACEMENT),
              "INS 24 P1=01 must not replace the PUK over contactless");
          assertSw(
              0x6982,
              transmit(0x80, 0x25, 0x01, 0x80, REPLACEMENT),
              "INS 25 P1=01 must not replace the PIN over contactless");
        });

    assertSw(0x9000, selectApplet(), "SELECT over contact");
    assertSw(0x9000, verifyPin(), "The original PIN is unchanged");
    assertSw(
        0x9000,
        transmit(0x00, 0x2C, 0x00, 0x80, concat(StandardCardProfile.PUK, REPLACEMENT)),
        "The original PUK is unchanged");
  }

  /**
   * SP 800-73-5 Part 2 Section 3.2.2: "If key reference '81' is specified and the command is not
   * submitted over the contact interface, then the card command SHALL fail." Table 2 marks RESET
   * RETRY COUNTER "No" for contactless. The contactless PIN and PUK flags relax neither.
   */
  @Test
  void contactlessPinAndPukFlagsDoNotEnablePukChangeOrRetryReset() {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before contactless flag configuration");
          assertSw(
              0x9000,
              transmit(0x84, 0xDB, 0xFF, 0xFF, hex("680AA0038301FFA1038101FF")),
              "Enable the contactless PIN and PUK flags");
        });

    withContactless(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT over contactless");
          ResponseAPDU change =
              transmit(0x00, 0x24, 0x00, 0x81, concat(StandardCardProfile.PUK, REPLACEMENT));
          assertSw(
              FIPS_MODE ? 0x6A81 : 0x6982, change, "CHANGE REFERENCE DATA 81 over contactless");
          assertSw(
              0x6A81,
              transmit(0x00, 0x2C, 0x00, 0x80, concat(StandardCardProfile.PUK, REPLACEMENT)),
              "RESET RETRY COUNTER over contactless");
        });

    assertSw(0x9000, selectApplet(), "SELECT over contact");
    assertSw(0x9000, verifyPin(), "The PIN was not reset over contactless");
    assertSw(
        0x9000,
        transmit(0x00, 0x2C, 0x00, 0x80, concat(StandardCardProfile.PUK, REPLACEMENT)),
        "The PUK was not changed over contactless");
  }

  /**
   * SP 800-73-5 Part 2 Section 3, following Table 2: a command marked "No" for the contactless
   * interface takes '6A 81', and a command that "can be performed over the contactless interface in
   * support of card management" may take another status word such as '69 82'. With contactless card
   * management restricted (the default), each administrative entry point keeps its status word. The
   * GlobalPlatform secure channel and the proprietary INS 24 / INS 25 commands return '69 82'; PUT
   * DATA (both forms) and GENERATE ASYMMETRIC KEY PAIR return '6A 81'.
   */
  @Test
  void administrativeEntryPointsKeepTheirStatusWordsOverContactless() {
    withContactless(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT over contactless");
          try (MockedStatic<GPSystem> mockedGp = Mockito.mockStatic(GPSystem.class)) {
            SecureChannel secureChannel = Mockito.mock(SecureChannel.class);
            Mockito.when(GPSystem.getSecureChannel()).thenReturn(secureChannel);
            assertSw(
                0x6982,
                transmit(new CommandAPDU(0x80, 0x50, 0x00, 0x00, hex("0102030405060708"))),
                "INITIALIZE UPDATE over contactless");
            Mockito.verify(secureChannel, Mockito.never()).processSecurity(Mockito.any());
          }
          assertSw(
              0x6A81,
              transmit(0x00, 0xDB, 0x3F, 0xFF, hex("5C035FC102 530100")),
              "Interindustry PUT DATA over contactless");
          assertSw(
              0x6A81,
              transmit(0x80, 0xDB, 0xFF, 0xFF, hex("6805A403810100")),
              "Proprietary PUT DATA over contactless");
          assertSw(
              0x6A81,
              transmit(0x00, 0x47, 0x00, 0x9A, hex("AC03800111"), 256),
              "GENERATE ASYMMETRIC KEY PAIR over contactless");
          assertSw(
              0x6982,
              transmit(0x80, 0x24, 0x01, 0x80, REPLACEMENT),
              "Proprietary INS 24 P1=01 over contactless");
          assertSw(
              0x6982,
              transmit(
                  0x80,
                  0x25,
                  0x01,
                  0x9B,
                  concat(
                      new byte[] {(byte) 0x80, (byte) 0x01, StandardCardProfile.ADMIN_KEY_ALG},
                      keyUpdateData(StandardCardProfile.ADMIN_KEY))),
              "Proprietary INS 25 over contactless");
        });

    assertSw(0x9000, selectApplet(), "SELECT over contact");
    assertSw(0x9000, verifyPin(), "The PIN is unchanged");
  }

  /**
   * With the issuer opt-in to contactless card management, the interface rule no longer refuses the
   * administrative entry points: the secure channel reaches GlobalPlatform, PUT DATA reaches its
   * object lookup and GENERATE reaches its PIV Card Application Administrator security condition.
   */
  @Test
  void contactlessCardManagementOptInPassesTheInterfaceRule() {
    assumeFalse(FIPS_MODE, "The FIPS profile refuses contactless card management");
    provisionGeneratedKey(0x9A, MODE_PIN, MODE_VCI_PIN, ROLE_SIGN, KeyAlgorithm.ECC_P256);
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before configuration");
          assertSw(
              0x9000,
              transmit(0x84, 0xDB, 0xFF, 0xFF, hex("6805A403810100")),
              "Permit contactless card management");
        });

    withContactless(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT over contactless");
          try (MockedStatic<GPSystem> mockedGp = Mockito.mockStatic(GPSystem.class)) {
            SecureChannel secureChannel = Mockito.mock(SecureChannel.class);
            Mockito.when(GPSystem.getSecureChannel()).thenReturn(secureChannel);
            Mockito.when(secureChannel.processSecurity(Mockito.any())).thenReturn((short) 0);
            assertSw(
                0x9000,
                transmit(new CommandAPDU(0x80, 0x50, 0x00, 0x00, hex("0102030405060708"))),
                "INITIALIZE UPDATE over contactless");
            Mockito.verify(secureChannel).processSecurity(Mockito.any());
          }
          // The standard test card defines no CHUID, so PUT DATA reaches the object lookup.
          assertSw(
              0x6A82,
              transmit(0x00, 0xDB, 0x3F, 0xFF, hex("5C035FC102 530100")),
              "PUT DATA past the interface rule");
          assertSw(
              0x6982,
              transmit(0x00, 0x47, 0x00, 0x9A, hex("AC03800111"), 256),
              "GENERATE without administrator authentication");
        });
  }

  /** SP 800-73-5 Part 1 Table 5: the digital signature key 9C requires PIN Always. */
  @ParameterizedTest(name = "{0} over {1}")
  @MethodSource("algorithmsAndChannels")
  void pinAlwaysKeyRequiresVerifyBeforeEachUse(KeyAlgorithm algorithm, Channel channel)
      throws Exception {
    provisionGeneratedKey(0x9C, MODE_PIN_ALWAYS, MODE_VCI_PIN_ALWAYS, ROLE_SIGN, algorithm);
    over(
        channel,
        () -> {
          assertSw(0x6982, sign(0x9C, algorithm), "PIN Always key without VERIFY");
          assertSw(0x9000, verifyPin(), "VERIFY");
          assertSuccess(sign(0x9C, algorithm), "PIN Always key immediately after VERIFY");
          assertSw(0x6982, sign(0x9C, algorithm), "PIN Always is consumed by one use");
          assertSw(0x9000, verifyPin(), "VERIFY again");
          assertSuccess(sign(0x9C, algorithm), "A new VERIFY authorizes one more use");
        });
  }

  /** SP 800-73-5 Part 1 Table 5: the PIV authentication key 9A requires the PIN. */
  @ParameterizedTest(name = "{0} over {1}")
  @MethodSource("algorithmsAndChannels")
  void pinKeyRejectsUseWithoutVerify(KeyAlgorithm algorithm, Channel channel) throws Exception {
    provisionGeneratedKey(0x9A, MODE_PIN, MODE_VCI_PIN, ROLE_SIGN, algorithm);
    over(
        channel,
        () -> {
          assertSw(0x6982, sign(0x9A, algorithm), "PIN key without VERIFY");
          assertSw(0x9000, verifyPin(), "VERIFY");
          assertSuccess(sign(0x9A, algorithm), "PIN key after VERIFY");
          assertSuccess(sign(0x9A, algorithm), "PIN status persists for a PIN key");
        });
  }

  /**
   * SP 800-73-5 Part 1 Table 5: the key management key 9D requires the PIN, for ECDH key agreement
   * and for RSA key transport alike.
   */
  @ParameterizedTest(name = "{0} over {1}")
  @MethodSource("algorithmsAndChannels")
  void keyManagementKeyRejectsAgreementWithoutVerify(KeyAlgorithm algorithm, Channel channel)
      throws Exception {
    provisionGeneratedKey(0x9D, MODE_PIN, MODE_VCI_PIN, ROLE_KEY_ESTABLISH, algorithm);
    over(
        channel,
        () -> {
          assertSw(0x6982, establishKey(algorithm), "Key establishment without VERIFY");
          assertSw(0x9000, verifyPin(), "VERIFY");
          assertSuccess(establishKey(algorithm), "Key establishment after VERIFY");
        });
  }

  /**
   * SP 800-73-5 Part 1 Table 5 requires the VCI in addition to the PIN for the 9A, 9C and 9D keys
   * over contactless, and Part 2 Section 3.2.1 makes VERIFY fail when it "is not submitted over
   * either the contact interface or the VCI". Over plain contactless none of these keys is usable,
   * before or after an attempted VERIFY.
   */
  @ParameterizedTest(name = "{0}")
  @EnumSource(KeyAlgorithm.class)
  void pinProtectedKeysRefuseUseOverContactlessWithoutVci(KeyAlgorithm algorithm) {
    provisionGeneratedKey(0x9A, MODE_PIN, MODE_VCI_PIN, ROLE_SIGN, algorithm);
    provisionGeneratedKey(0x9C, MODE_PIN_ALWAYS, MODE_VCI_PIN_ALWAYS, ROLE_SIGN, algorithm);
    provisionGeneratedKey(0x9D, MODE_PIN, MODE_VCI_PIN, ROLE_KEY_ESTABLISH, algorithm);
    enableContactlessPinUse();
    withContactless(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT over contactless");
          assertSw(0x6982, sign(0x9A, algorithm), "9A over contactless without VCI");
          assertSw(0x6982, sign(0x9C, algorithm), "9C over contactless without VCI");
          assertSw(0x6982, establishKey(algorithm), "9D over contactless without VCI");
          assertSw(0x6982, verifyPin(), "VERIFY over contactless without VCI");
          assertSw(0x6982, sign(0x9A, algorithm), "9A after the refused VERIFY");
          assertSw(0x6982, sign(0x9C, algorithm), "9C after the refused VERIFY");
          assertSw(0x6982, establishKey(algorithm), "9D after the refused VERIFY");
        });
  }

  private void provisionGeneratedKey(
      final int slot,
      final int contact,
      final int contactless,
      final byte role,
      final KeyAlgorithm algorithm) {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before key provisioning");
          assertSw(
              0x9000,
              transmit(
                  0x84,
                  0xDB,
                  0xFF,
                  0xFF,
                  new byte[] {
                    (byte) 0x66,
                    (byte) 0x12,
                    (byte) 0x8B,
                    (byte) 0x01,
                    (byte) slot,
                    (byte) 0x8C,
                    (byte) 0x01,
                    (byte) contact,
                    (byte) 0x8D,
                    (byte) 0x01,
                    (byte) contactless,
                    (byte) 0x8E,
                    (byte) 0x01,
                    algorithm.id,
                    (byte) 0x8F,
                    (byte) 0x01,
                    role,
                    (byte) 0x90,
                    (byte) 0x01,
                    (byte) 0x00
                  }),
              "Create key " + Integer.toHexString(slot));
          collectResponse(
              transmit(
                  0x84,
                  0x47,
                  0x00,
                  slot,
                  new byte[] {(byte) 0xAC, (byte) 0x03, (byte) 0x80, (byte) 0x01, algorithm.id},
                  256),
              "Generate key " + Integer.toHexString(slot));
        });
  }

  /**
   * Runs {@code action} after SELECT over the given channel. Over the VCI it first enables
   * contactless PIN use and holds the VCI condition true.
   */
  private void over(Channel channel, Runnable action) throws Exception {
    if (channel == Channel.CONTACT) {
      assertSw(0x9000, selectApplet(), "SELECT over contact");
      action.run();
      return;
    }
    enableContactlessPinUse();
    satisfyVciCondition();
    withContactless(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT over contactless");
          action.run();
        });
  }

  private void enableContactlessPinUse() {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before configuration");
          assertSw(
              0x9000,
              transmit(0x84, 0xDB, 0xFF, 0xFF, hex("6805A0038301FF")),
              "Enable contactless PIN use");
        });
  }

  /**
   * Digital signature with the key at {@code slot}: an ECDSA signature over a P-256 digest, or the
   * RSA-2048 private-key operation over a 256-byte representative sent as an ISO/IEC 7816-4 command
   * chain.
   */
  private ResponseAPDU sign(int slot, KeyAlgorithm algorithm) {
    if (algorithm == KeyAlgorithm.RSA_2048) {
      byte[] representative = new byte[256];
      Arrays.fill(representative, (byte) 0x5C);
      representative[0] = 0;
      return transmitChained(0x00, 0x87, algorithm.id, slot, challengeTemplate(representative));
    }
    byte[] digest = new byte[32];
    for (int i = 0; i < digest.length; i++) digest[i] = (byte) (0x40 + i);
    return transmit(0x00, 0x87, algorithm.id, slot, challengeTemplate(digest), 256);
  }

  /**
   * Key establishment with the 9D key: ECDH with the P-256 base point, or RSA key transport of a
   * 256-byte block sent as an ISO/IEC 7816-4 command chain.
   */
  private ResponseAPDU establishKey(KeyAlgorithm algorithm) {
    if (algorithm == KeyAlgorithm.RSA_2048) {
      byte[] block = new byte[256];
      Arrays.fill(block, (byte) 0x39);
      block[0] = 0;
      return transmitChained(0x00, 0x87, algorithm.id, 0x9D, challengeTemplate(block));
    }
    byte[] request =
        tlv((byte) 0x7C, concat(tlv((byte) 0x82, new byte[0]), tlv((byte) 0x85, P256_G)));
    return transmit(0x00, 0x87, algorithm.id, 0x9D, request, 256);
  }

  private static byte[] challengeTemplate(byte[] challenge) {
    return tlv((byte) 0x7C, concat(tlv((byte) 0x82, new byte[0]), tlv((byte) 0x81, challenge)));
  }

  private ResponseAPDU verifyPin() {
    return transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN);
  }

  private static void assertSuccess(ResponseAPDU response, String context) {
    int sw = response.getSW();
    assertTrue(
        sw == 0x9000 || (sw & 0xFF00) == 0x6100,
        context + " expected success but was " + swHex(response));
  }

  /**
   * Holds the applet's VCI condition (SP 800-73-5 Part 1 Section 5.5) true for the PIN and
   * authentication command handlers, as after VCI establishment and pairing, by giving them a spy
   * of the PIV instance whose {@code isVciSatisfied()} returns true. Everything else, including the
   * contactless interface, the key access rules and the PIN security status, is the installed
   * applet's.
   */
  private void satisfyVciCondition() throws Exception {
    Object piv = field(unwrapApplet(engine.getApplet(OPENFIPS201_AID)), "piv");
    Object spy = Mockito.spy(piv);
    Method isVciSatisfied = piv.getClass().getDeclaredMethod("isVciSatisfied");
    isVciSatisfied.setAccessible(true);
    isVciSatisfied.invoke(Mockito.doReturn(true).when(spy));
    for (String handler : new String[] {"pinCommands", "authenticationCommands"}) {
      Object commands = field(piv, handler);
      Field owner = commands.getClass().getDeclaredField("owner");
      owner.setAccessible(true);
      owner.set(commands, spy);
    }
  }

  private static Object field(Object target, String name) throws Exception {
    Field field = target.getClass().getDeclaredField(name);
    field.setAccessible(true);
    return field.get(target);
  }

  private static Applet unwrapApplet(Applet appletProxy) throws Exception {
    if (appletProxy.getClass().getName().equals(OpenFIPS201.class.getName())) return appletProxy;
    for (Field proxyField : appletProxy.getClass().getDeclaredFields()) {
      if (!InvocationHandler.class.isAssignableFrom(proxyField.getType())) continue;
      proxyField.setAccessible(true);
      Object handler = proxyField.get(null);
      for (Field handlerField : handler.getClass().getDeclaredFields()) {
        handlerField.setAccessible(true);
        Object value = handlerField.get(handler);
        if (value instanceof Applet
            && value.getClass().getName().equals(OpenFIPS201.class.getName())) {
          return (Applet) value;
        }
      }
    }
    throw new IllegalStateException("Unable to unwrap simulator applet proxy");
  }
}
