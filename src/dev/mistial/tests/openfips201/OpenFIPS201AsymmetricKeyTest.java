package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import javacard.framework.ISO7816;
import javax.crypto.KeyAgreement;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class OpenFIPS201AsymmetricKeyTest extends OpenFIPS201TestSupport {
  private static final int KEY_REFERENCE = 0x9A;

  @Test
  void generatesRsa1024KeyPairAndReturnsModulusAndExponent() {
    assumeFalse(Boolean.getBoolean("fips.mode"), "RSA-1024 is excluded from the FIPS profile");
    withMockedScp(
        () -> {
          createKey(0x82, 0x06, 0x02);
          ResponseAPDU response = transmit(0x84, 0x47, 0x00, 0x82, hex("AC03800106"), 0);
          assertSw(0x9000, response, "RSA key generation");
          byte[] data = response.getData();
          assertEquals((byte) 0x7F, data[0]);
          assertEquals((byte) 0x49, data[1]);
        });
  }

  @Test
  void generatesP256KeyPairAndReturnsUncompressedPoint() {
    withMockedScp(
        () -> {
          createKey(0x11, 0x04);
          ResponseAPDU response = transmit(0x84, 0x47, 0x00, KEY_REFERENCE, hex("AC03800111"), 0);
          assertSw(0x9000, response, "P-256 key generation");
          byte[] data = response.getData();
          assertEquals((byte) 0x7F, data[0]);
          assertEquals((byte) 0x49, data[1]);
          assertEquals((byte) 0x86, data[3]);
          assertEquals((byte) 0x04, data[5]);
        });
  }

  @Test
  void generatesP256KeyPairFromChainedControlReferenceTemplate() {
    withMockedScp(
        () -> {
          createKey(0x11, 0x04);

          // SP 800-73-5 Part 2 Table 2 and Section 3.3.2 require INS 47 chaining.
          assertSw(
              0x9000,
              transmit(0x14, 0x47, 0x00, KEY_REFERENCE, hex("AC03")),
              "First protected GENERATE fragment");
          ResponseAPDU response =
              transmit(0x04, 0x47, 0x00, KEY_REFERENCE, hex("800111"), 0);
          assertSw(0x9000, response, "Final protected GENERATE fragment");
          assertEquals((byte) 0x7F, response.getData()[0]);
          assertEquals((byte) 0x49, response.getData()[1]);
        });
  }

  @Test
  void generatesRsa2048WithRequiredPublicExponent() {
    withMockedScp(
        () -> {
          createKey(0x07, 0x04);
          ResponseAPDU response = transmit(0x84, 0x47, 0x00, KEY_REFERENCE, hex("AC03800107"), 0);
          byte[] data = collectResponse(response, "RSA-2048 key generation");
          boolean found = false;
          for (int i = 0; i <= data.length - 5; i++) {
            if (data[i] == (byte) 0x82
                && data[i + 1] == (byte) 0x03
                && data[i + 2] == (byte) 0x01
                && data[i + 3] == (byte) 0x00
                && data[i + 4] == (byte) 0x01) {
              found = true;
              break;
            }
          }
          assertTrue(found, "Generated RSA public exponent must be 65537");
        });
  }

  private byte[] collectResponse(ResponseAPDU response, String context) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ResponseAPDU current = response;
    while ((current.getSW() & 0xFF00) == 0x6100) {
      out.write(current.getData(), 0, current.getData().length);
      int le = current.getSW2() == 0 ? 256 : current.getSW2();
      current = transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00, le));
    }
    assertSw(0x9000, current, context);
    out.write(current.getData(), 0, current.getData().length);
    return out.toByteArray();
  }

  @Test
  void rejectsConflictingAsymmetricRolesDuringProvisioning() {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before conflicting-role test");
          assertSw(
              ISO7816.SW_WRONG_DATA,
              transmit(0x84, 0xDB, 0x3F, 0x00, createKeyRequest(0x11, 0x06)),
              "SIGN and KEY_ESTABLISH roles must be mutually exclusive");
        });
  }

  @Test
  void rejectsOffCurvePointThroughGeneralAuthenticate() {
    withMockedScp(
        () -> {
          int keyManagementReference = 0x9D;
          createKey(keyManagementReference, 0x11, 0x02);
          assertSw(
              0x9000,
              transmit(0x84, 0x47, 0x00, keyManagementReference, hex("AC03800111"), 0),
              "P-256 key generation");
          verifyLocalPin();

          byte[] point = new byte[65];
          point[0] = 0x04;
          byte[] request = new byte[69];
          request[0] = 0x7C;
          request[1] = 0x43;
          request[2] = (byte) 0x85;
          request[3] = 0x41;
          System.arraycopy(point, 0, request, 4, point.length);

          assertSw(
              ISO7816.SW_WRONG_DATA,
              transmit(0x00, 0x87, 0x11, keyManagementReference, request, 0),
              "GENERAL AUTHENTICATE must reject an off-curve ECDH point");
        });
  }

  @Test
  void derivesP256SharedSecretThroughGeneralAuthenticate() throws Exception {
    assertEcdhSharedSecret(0x11, "secp256r1", 32);
  }

  @Test
  void derivesP384SharedSecretThroughGeneralAuthenticate() throws Exception {
    assumeFalse(
        Boolean.getBoolean("fips.mode")
            && "CS2".equalsIgnoreCase(System.getProperty("vci.suite", "CS2")),
        "SP 800-78-5 requires CS7 when a VCI-capable FIPS profile uses P-384 slot 9D");
    assertEcdhSharedSecret(0x14, "secp384r1", 48);
  }

  private void assertEcdhSharedSecret(int algorithm, String curve, int fieldBytes)
      throws Exception {
    final int keyManagementReference = 0x9D;
    final byte[][] cardPoint = new byte[1][];
    withMockedScp(
        () -> {
          createKey(keyManagementReference, algorithm, 0x02);
          byte[] generated =
              collectResponse(
                  transmit(
                      0x84,
                      0x47,
                      0x00,
                      keyManagementReference,
                      new byte[] {(byte) 0xAC, 0x03, (byte) 0x80, 0x01, (byte) algorithm},
                      0),
                  "EC key-management generation");
          cardPoint[0] = tlvValue(generated, (byte) 0x86);
        });
    verifyLocalPin();

    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec(curve));
    KeyPair host = generator.generateKeyPair();
    byte[] hostPoint = encodePoint((ECPublicKey) host.getPublic(), fieldBytes);
    byte[] response =
        collectResponse(
            transmit(
                0x00,
                0x87,
                algorithm,
                keyManagementReference,
                tlv((byte) 0x7C, tlv((byte) 0x85, hostPoint)),
                0),
            "EC GENERAL AUTHENTICATE key establishment");
    byte[] cardSecret = tlvValue(tlvValue(response, (byte) 0x7C), (byte) 0x82);

    KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
    agreement.init(host.getPrivate());
    agreement.doPhase(decodePoint(cardPoint[0], curve, fieldBytes), true);
    assertTrue(
        java.util.Arrays.equals(agreement.generateSecret(), cardSecret),
        "Card and host must derive the same ECDH shared secret");
  }

  @Test
  void signsP256DigestThroughGeneralAuthenticate() {
    withMockedScp(
        () -> {
          createKey(0x11, 0x04);
          assertSw(
              0x9000,
              transmit(0x84, 0x47, 0x00, KEY_REFERENCE, hex("AC03800111"), 0),
              "P-256 key generation");
          verifyLocalPin();

          byte[] request = new byte[38];
          request[0] = 0x7C;
          request[1] = 0x24;
          request[2] = (byte) 0x81;
          request[3] = 0x20;
          for (int i = 0; i < 32; i++) request[4 + i] = (byte) (i + 1);
          request[36] = (byte) 0x82;
          request[37] = 0x00;

          ResponseAPDU response = transmit(0x00, 0x87, 0x11, KEY_REFERENCE, request, 0);
          assertSw(0x9000, response, "P-256 GENERAL AUTHENTICATE signature");
          assertEquals(0x7C, response.getData()[0] & 0xFF);
        });
  }

  private void createKey(int mechanism, int role) {
    createKey(KEY_REFERENCE, mechanism, role);
  }

  private void verifyLocalPin() {
    assertSw(
        0x9000,
        transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN),
        "VERIFY before PIN-gated asymmetric use");
  }

  private void createKey(int keyReference, int mechanism, int role) {
    assertSw(0x9000, selectApplet(), "SELECT before asymmetric provisioning");
    assertSw(
        0x9000,
        transmit(0x84, 0xDB, 0x3F, 0x00, createKeyRequest(keyReference, mechanism, role)),
        "Create asymmetric key object");
  }

  private static byte[] createKeyRequest(int mechanism, int role) {
    return createKeyRequest(KEY_REFERENCE, mechanism, role);
  }

  private static byte[] createKeyRequest(int keyReference, int mechanism, int role) {
    byte modeContact = (byte) 0x01;
    byte modeContactless = (byte) 0x09;
    return new byte[] {
      0x66,
      0x12,
      (byte) 0x8B,
      0x01,
      (byte) keyReference,
      (byte) 0x8C,
      0x01,
      modeContact,
      (byte) 0x8D,
      0x01,
      modeContactless,
      (byte) 0x8E,
      0x01,
      (byte) mechanism,
      (byte) 0x8F,
      0x01,
      (byte) role,
      (byte) 0x90,
      0x01,
      0x00
    };
  }

  private static byte[] encodePoint(ECPublicKey key, int fieldBytes) {
    return concat(
        new byte[] {0x04},
        fixed(key.getW().getAffineX(), fieldBytes),
        fixed(key.getW().getAffineY(), fieldBytes));
  }

  private static PublicKey decodePoint(byte[] point, String curve, int fieldBytes)
      throws Exception {
    byte[] x = new byte[fieldBytes];
    byte[] y = new byte[fieldBytes];
    System.arraycopy(point, 1, x, 0, fieldBytes);
    System.arraycopy(point, 1 + fieldBytes, y, 0, fieldBytes);
    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
    parameters.init(new ECGenParameterSpec(curve));
    ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);
    return KeyFactory.getInstance("EC")
        .generatePublic(
            new ECPublicKeySpec(
                new ECPoint(new BigInteger(1, x), new BigInteger(1, y)), spec));
  }

  private static byte[] fixed(BigInteger value, int length) {
    byte[] encoded = value.toByteArray();
    byte[] result = new byte[length];
    int sourceOffset = Math.max(0, encoded.length - length);
    int copyLength = Math.min(encoded.length, length);
    System.arraycopy(encoded, sourceOffset, result, length - copyLength, copyLength);
    return result;
  }

  protected void withMockedScp(Runnable action) {
    try (MockedStatic<GPSystem> mocked = Mockito.mockStatic(GPSystem.class)) {
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
      action.run();
    }
  }
}
