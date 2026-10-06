package dev.mistial.tools.openfips201.vci;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import apdu4j.core.BIBO;
import com.makina.security.openfips201.OpenFIPS201;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import javacard.framework.AID;
import javacard.framework.APDU;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import pro.javacard.engine.JavaCardEngine;

/**
 * A plaintext command sent while an OPACITY secure-messaging session is established.
 *
 * <p>SP 800-73-5 Part 2 Section 4.2: once session keys are established, "subsequent communication
 * with the card can be performed using secure messaging", so plaintext commands remain valid.
 * Section 4.3 lists the only circumstances in which the session keys are zeroized: a card reset, an
 * error in secure messaging, or a new key-establishment request. A plaintext GET DATA is none of
 * these, so the session survives it and the MAC chaining value continues from the last protected
 * exchange. The plaintext command itself is evaluated under the plaintext access rules: it does not
 * satisfy the VCI, which only a protected command does (SP 800-73-5 Part 1 Section 5.5).
 *
 * <p>The applet runs in an in-process jCardEngine so the contactless interface can be modelled;
 * real OPACITY establishment and SM wrapping use the host implementation in {@link VciSupport}.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class OpenFIPS201VciPlaintextDuringSessionTest {
  private static final byte[] PIV_AID = Hex.decode("A000000308000010000100");
  private static final byte[] CVC = Hex.decode("7F210401020304");
  private static final byte ACCESS_ALWAYS = (byte) 0x7F;
  private static final byte ACCESS_VCI = (byte) 0x08;
  private static final byte[] CONTENT = Hex.decode("5308C10401020304FE00");

  private final byte suite =
      "CS7".equalsIgnoreCase(System.getProperty("vci.suite", "CS2"))
          ? VciSupport.ALG_CS7
          : VciSupport.ALG_CS2;
  private JavaCardEngine engine;
  private BIBO session;
  private byte[] cardPoint;

  @BeforeEach
  void installApplet() {
    engine = JavaCardEngine.create();
    engine.installApplet(
        new AID(PIV_AID, (short) 0, (byte) PIV_AID.length), OpenFIPS201.class, new byte[0]);
    session = engine.connect();
  }

  @AfterEach
  void closeSession() {
    if (session != null) session.close();
  }

  @Test
  void plaintextGetDataOverContactKeepsTheSession() throws Exception {
    byte[] objectId = Hex.decode("5FFF20");
    provisionSecureMessaging(false);
    provisionObject(objectId, ACCESS_ALWAYS);

    VciSupport.SmSession sm = establish();
    assertProtectedRead(sm, objectId, "Protected GET DATA before the plaintext command");

    ResponseAPDU plaintext = getData(objectId);
    assertEquals(0x9000, plaintext.getSW(), "Plaintext GET DATA during the session");
    assertArrayEquals(CONTENT, plaintext.getData(), "Plaintext GET DATA returns the object");

    assertProtectedRead(sm, objectId, "Protected GET DATA after the plaintext command");
  }

  @Test
  void plaintextGetDataOverContactlessKeepsTheSessionAndPlaintextRules() throws Exception {
    byte[] objectId = Hex.decode("5FFF21");
    provisionSecureMessaging(true);
    provisionObject(objectId, ACCESS_VCI);

    withContactless(
        () -> {
          VciSupport.SmSession sm = establish();
          assertProtectedRead(sm, objectId, "Protected GET DATA satisfies the VCI");

          assertEquals(
              0x6982,
              getData(objectId).getSW(),
              "A plaintext command does not satisfy the VCI access rule");

          assertProtectedRead(sm, objectId, "Protected GET DATA after the plaintext command");
        });
  }

  private void assertProtectedRead(VciSupport.SmSession sm, byte[] objectId, String context) {
    byte[] command =
        VciSupport.wrapCommand(
            sm, (byte) 0xCB, (byte) 0x3F, (byte) 0xFF, VciSupport.tlv(0x5C, objectId), true);
    VciSupport.SmResponse response = VciSupport.unwrapResponse(sm, transceiveChained(command));
    assertEquals(0x9000, response.statusWord, context);
    assertArrayEquals(CONTENT, response.data, context);
  }

  private ResponseAPDU getData(byte[] objectId) {
    return new ResponseAPDU(
        transceiveChained(
            new CommandAPDU(0x00, 0xCB, 0x3F, 0xFF, VciSupport.tlv(0x5C, objectId), 256)
                .getBytes()));
  }

  /**
   * SP 800-73-5 Part 2 Section 4.1 OPACITY ZKM with an ephemeral host key; returns the host side of
   * the session after checking the card's authentication cryptogram.
   */
  private VciSupport.SmSession establish() throws Exception {
    ResponseAPDU select = transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, PIV_AID, 256));
    assertEquals(0x9000, select.getSW(), "SELECT PIV");

    int field = VciSupport.coordLength(suite);
    int nonceLength = field / 2;
    X9ECParameters curve = VciSupport.curveForSuite(suite);
    ECDomainParameters domain =
        new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH());
    SecureRandom random = new SecureRandom();
    BigInteger d;
    do {
      d = new BigInteger(curve.getN().bitLength(), random);
    } while (d.signum() <= 0 || d.compareTo(curve.getN()) >= 0);
    byte[] hostPoint = VciSupport.encodePoint(curve.getG().multiply(d).normalize());
    byte[] idH = new byte[8];

    byte[] witness = concat(new byte[] {0x00}, VciSupport.buildWitness(hostPoint));
    byte[] template =
        VciSupport.tlv(
            0x7C, concat(VciSupport.tlv(0x81, witness), VciSupport.tlv(0x82, new byte[0])));
    ResponseAPDU response =
        new ResponseAPDU(
            transceiveChained(
                new CommandAPDU(
                        0x00, 0x87, suite, VciSupport.KEY_REF_SECURE_MESSAGING, template, 256)
                    .getBytes()));
    assertEquals(0x9000, response.getSW(), "OPACITY key establishment");

    byte[] data = response.getData();
    int[] outer = VciSupport.locateTlv(data, 0, 0x7C);
    int[] value = VciSupport.locateTlv(data, outer[1], 0x82);
    int offset = value[1];
    assertEquals(0x00, data[offset], "CB_ICC");
    byte[] nonce = Arrays.copyOfRange(data, offset + 1, offset + 1 + nonceLength);
    byte[] cryptogram =
        Arrays.copyOfRange(data, offset + 1 + nonceLength, offset + 17 + nonceLength);
    assertArrayEquals(
        CVC, Arrays.copyOfRange(data, offset + 17 + nonceLength, offset + value[2]), "C_ICC");

    ECPoint card = curve.getCurve().decodePoint(cardPoint);
    ECDHBasicAgreement agreement = new ECDHBasicAgreement();
    agreement.init(new ECPrivateKeyParameters(d, domain));
    byte[] z = fixed(agreement.calculateAgreement(new ECPublicKeyParameters(card, domain)), field);
    byte[] idSicc = VciSupport.computeIdSicc(CVC);
    VciSupport.SessionKeys keys =
        VciSupport.deriveSessionKeys(suite, z, idH, hostPoint, idSicc, nonce);
    assertArrayEquals(
        Arrays.copyOf(VciSupport.computeAuthCryptogram(keys.skCfrm, idSicc, idH, hostPoint), 16),
        cryptogram,
        "AuthCryptogram_ICC");
    return new VciSupport.SmSession(keys);
  }

  /**
   * Generates the secure-messaging key and loads its CVC over a mocked GlobalPlatform secure
   * channel. For the contactless case VCI is configured without pairing and the Discovery Object
   * advertises it (PIN Usage Policy '4C 00').
   */
  private void provisionSecureMessaging(final boolean vciWithoutPairing) {
    withMockedScp(
        () -> {
          expect(transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, PIV_AID, 256)), "SELECT");
          if (vciWithoutPairing) {
            expect(adminPut(Hex.decode("68 05 A2 03 80 01 01".replace(" ", ""))), "VCI mode");
          }
          expect(
              adminPut(
                  concat(
                      Hex.decode("66128B01048C017F8D017F8E01"),
                      new byte[] {suite},
                      Hex.decode("8F0102900100"))),
              "Define the secure-messaging key");
          ResponseAPDU generated =
              new ResponseAPDU(
                  transceiveChained(
                      new CommandAPDU(
                              0x84,
                              0x47,
                              0x00,
                              VciSupport.KEY_REF_SECURE_MESSAGING,
                              VciSupport.tlv(0xAC, VciSupport.tlv(0x80, new byte[] {suite})),
                              256)
                          .getBytes()));
          expect(generated, "Generate the secure-messaging key");
          int[] outer = VciSupport.locateTlv(generated.getData(), 0, 0x7F49);
          int[] point = VciSupport.locateTlv(generated.getData(), outer[1], 0x86);
          cardPoint = Arrays.copyOfRange(generated.getData(), point[1], point[1] + point[2]);
          expect(
              transmit(
                  new CommandAPDU(
                      0x84,
                      0x24,
                      suite,
                      VciSupport.KEY_REF_SECURE_MESSAGING,
                      VciSupport.tlv(0x30, VciSupport.tlv(0x8A, CVC)))),
              "Load the CVC");
          if (vciWithoutPairing) {
            expect(adminPut(Hex.decode("64108B017E8C017F8D017F91019B92020020")), "Discovery");
            expect(
                transmit(
                    new CommandAPDU(
                        0x84,
                        0xDB,
                        0x3F,
                        0xFF,
                        VciSupport.tlv(
                            0x7E,
                            concat(VciSupport.tlv(0x4F, PIV_AID), Hex.decode("5F2F024C00"))))),
                "Store the Discovery Object");
          }
        });
  }

  private void provisionObject(final byte[] objectId, final byte contactless) {
    withMockedScp(
        () -> {
          expect(
              adminPut(
                  VciSupport.tlv(
                      0x64,
                      concat(
                          VciSupport.tlv(0x8B, objectId),
                          new byte[] {
                            (byte) 0x8C, 0x01, ACCESS_ALWAYS, (byte) 0x8D, 0x01, contactless
                          },
                          Hex.decode("91019B92020040")))),
              "Create the object");
          expect(
              transmit(
                  new CommandAPDU(
                      0x84, 0xDB, 0x3F, 0xFF, concat(VciSupport.tlv(0x5C, objectId), CONTENT))),
              "Load the object");
        });
  }

  private ResponseAPDU adminPut(byte[] data) {
    return transmit(new CommandAPDU(0x84, 0xDB, 0xFF, 0xFF, data));
  }

  private ResponseAPDU transmit(CommandAPDU command) {
    return new ResponseAPDU(session.transceive(command.getBytes()));
  }

  /** Transceives a command, collecting any '61 XX' continuation with GET RESPONSE. */
  private byte[] transceiveChained(byte[] command) {
    ByteArrayOutputStream logical = new ByteArrayOutputStream();
    byte[] response = session.transceive(command);
    while ((response[response.length - 2] & 0xFF) == 0x61) {
      logical.write(response, 0, response.length - 2);
      response =
          session.transceive(
              new byte[] {0x00, (byte) 0xC0, 0x00, 0x00, response[response.length - 1]});
    }
    logical.write(response, 0, response.length);
    return logical.toByteArray();
  }

  private static void expect(ResponseAPDU response, String context) {
    assertEquals(0x9000, response.getSW(), context);
  }

  /** Runs provisioning with an authenticated GlobalPlatform secure channel supplied by the test. */
  private static void withMockedScp(Runnable action) {
    try (MockedStatic<GPSystem> gp = Mockito.mockStatic(GPSystem.class)) {
      gp.when(GPSystem::getCardContentState).thenReturn(GPSystem.APPLICATION_SELECTABLE);
      SecureChannel channel = Mockito.mock(SecureChannel.class);
      Mockito.when(channel.getSecurityLevel())
          .thenReturn(
              (byte)
                  (SecureChannel.AUTHENTICATED | SecureChannel.C_DECRYPTION | SecureChannel.C_MAC));
      Mockito.when(
              channel.unwrap(Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyShort()))
          .thenAnswer(invocation -> (short) invocation.getArgument(2));
      gp.when(GPSystem::getSecureChannel).thenReturn(channel);
      action.run();
    }
  }

  /** Runs an APDU flow with Java Card's transport reported as ISO 14443 contactless Type A. */
  private static void withContactless(ThrowingRunnable action) throws Exception {
    try (MockedStatic<APDU> mockedApdu = Mockito.mockStatic(APDU.class)) {
      mockedApdu
          .when(APDU::getProtocol)
          .thenReturn((byte) (APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A | APDU.PROTOCOL_T1));
      action.run();
    }
  }

  private interface ThrowingRunnable {
    void run() throws Exception;
  }

  private static byte[] concat(byte[]... arrays) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (byte[] array : arrays) out.write(array, 0, array.length);
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
