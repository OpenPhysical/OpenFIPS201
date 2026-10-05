package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

import apdu4j.core.BIBO;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.AESKey;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import pro.javacard.engine.JavaCardEngine;

/**
 * Conformance tests for secure messaging APDU dispatching.
 *
 * <p>NIST SP 800-73-5 Part 2 Sections 4.2.4-4.2.7 define protected command and response APDUs;
 * Section 4.3 defines session key destruction.
 */
@Tag("slow")
class OpenFIPS201SecureMessagingDispatchTest {
  // Deliberately leave only one octet free after a full T=1 input block.
  private static final short INPUT_BLOCK_BYTES =
      (short) (OpenFIPS201.MAX_SHORT_APDU_DATA_LENGTH - 1);
  private static final int SHORT_APDU_BUFFER_BYTES =
      ISO7816.OFFSET_CDATA + OpenFIPS201.MAX_SHORT_APDU_DATA_LENGTH;
  private static final byte SYNTHETIC_PLAINTEXT_BYTE = (byte) 0x42;
  private static final short MAX_SAFE_SECURE_RESPONSE_PLAINTEXT = (short) 191;
  private static final byte[] OPENFIPS201_AID_BYTES = hex("A000000308000010000100");
  private static final AID OPENFIPS201_AID =
      new AID(OPENFIPS201_AID_BYTES, (short) 0, (byte) OPENFIPS201_AID_BYTES.length);

  private JavaCardEngine engine;
  private BIBO session;

  @BeforeEach
  void setUpCard() throws Exception {
    engine = JavaCardEngine.create();
    try (AutoCloseable ignored = enterEngineContext()) {
      PIVCrypto.terminate();
      PIVCrypto.init();
    }
    engine.installApplet(OPENFIPS201_AID, OpenFIPS201.class, new byte[0]);
    session = engine.connect();
  }

  private static boolean isCs2Build() {
    return !"CS7".equalsIgnoreCase(System.getProperty("vci.suite", "CS2"));
  }

  @AfterEach
  void tearDownCard() {
    if (session != null) {
      session.close();
    }
  }

  @Test
  void wrappedOpacityCannotReplaceEstablishedSessionKeys() throws Exception {
    assertEquals(
        0x9000,
        new ResponseAPDU(
                session.transceive(
                    new CommandAPDU(0, 0xA4, 4, 0, OPENFIPS201_AID_BYTES).getBytes()))
            .getSW());
    Object piv;
    Object sm;
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet applet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      piv = field(applet, "piv").get(applet);
      sm = field(piv, "secureMessaging").get(piv);
      establishSyntheticSession(sm);
    }
    byte[] command = authenticatedEncryptedDataCommand(hex("7C00"));
    command[ISO7816.OFFSET_INS] = OpenFIPS201.INS_PIV_GENERAL_AUTHENTICATE;
    command[ISO7816.OFFSET_P1] = PIV.ID_ALG_ECC_SM;
    command[ISO7816.OFFSET_P2] = PIV.ID_KEY_SECURE_MESSAGING;
    byte[] mac = commandMac(command, (short) 5, (short) (command.length - 10));
    System.arraycopy(mac, 0, command, command.length - 8, 8);
    ResponseAPDU response = new ResponseAPDU(session.transceive(command));
    assertEquals(0x9000, response.getSW());
    assertArrayEquals(hex("99026E00"), java.util.Arrays.copyOf(response.getData(), 4));
    try (AutoCloseable ignored = enterEngineContext()) {
      assertEquals(true, method(sm.getClass(), "isEstablished").invoke(sm));
      for (String keyName : new String[] {"skMac", "skEnc", "skRmac"}) {
        byte[] actual = new byte[activeSessionKeyBytes()];
        ((AESKey) field(sm, keyName).get(sm)).getKey(actual, (short) 0);
        assertArrayEquals(zeroSessionKey(), actual, keyName);
      }
    }
  }

  @Test
  void responseProviderFailureDestroysSession() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet applet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(applet, "piv").get(applet);
      Object sm = field(piv, "secureMessaging").get(piv);
      establishSyntheticSession(sm);
      seedWorkBuffers(piv);
      Class<?> cryptoClass = piv.getClass().getClassLoader().loadClass(PIVCrypto.class.getName());
      Method initMac =
          method(cryptoClass, "doAesResponseCmacInit", javacard.security.SecretKey.class);
      APDU apdu = Mockito.mock(APDU.class);
      when(apdu.getBuffer()).thenReturn(new byte[SHORT_APDU_BUFFER_BYTES]);
      when(apdu.setOutgoing()).thenReturn(OpenFIPS201.MAX_SHORT_APDU_RESPONSE_LENGTH);
      try (org.mockito.MockedStatic<?> crypto =
          Mockito.mockStatic(cryptoClass, Mockito.CALLS_REAL_METHODS)) {
        crypto
            .when(() -> initMac.invoke(null, Mockito.any(javacard.security.SecretKey.class)))
            .thenThrow(
                new javacard.security.CryptoException(
                    javacard.security.CryptoException.ILLEGAL_USE));
        InvocationTargetException failure =
            assertThrows(
                InvocationTargetException.class,
                () ->
                    method(piv.getClass(), "processOutgoingSecure", APDU.class, short.class)
                        .invoke(piv, apdu, ISO7816.SW_NO_ERROR));
        assertEquals(
            PIVSecureMessaging.SW_SM_OBJECTS_INCORRECT,
            ((ISOException) failure.getCause()).getReason());
      }
      assertSessionDestroyed(piv, sm);
    }
  }

  @Test
  void segmentedReceiveKeepsFullInputBlockCapacityAtTheTail() throws Exception {
    // Java Card 3.0.5 APDU.receiveBytes requires room for getInBlockSize(), even
    // when the final fragment is shorter. A permissive emulator alone misses this condition.
    try (AutoCloseable ignored = enterEngineContext();
        org.mockito.MockedStatic<APDU> api = Mockito.mockStatic(APDU.class)) {
      api.when(APDU::getInBlockSize).thenReturn(INPUT_BLOCK_BYTES);
      Applet applet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Method receive = method(applet.getClass(), "receiveAllIncomingData", APDU.class);
      byte[] expected = new byte[OpenFIPS201.MAX_SHORT_APDU_DATA_LENGTH];
      for (int i = 0; i < expected.length; i++) expected[i] = (byte) i;
      for (int[] receiveCase :
          new int[][] {
            {1, INPUT_BLOCK_BYTES},
            {TLV.LENGTH_1BYTE_MAX, TLV.LENGTH_1BYTE_MAX + 1},
            {INPUT_BLOCK_BYTES, 1},
            {TLV.LENGTH_1BYTE_MAX, 0},
            {TLV.LENGTH_1BYTE_MAX, -1},
            {TLV.LENGTH_1BYTE_MAX, OpenFIPS201.MAX_SHORT_APDU_RESPONSE_LENGTH}
          }) {
        int initialLength = receiveCase[0];
        int returnedLength = receiveCase[1];
        boolean valid = returnedLength == expected.length - initialLength;
        byte[] buffer = new byte[SHORT_APDU_BUFFER_BYTES];
        System.arraycopy(expected, 0, buffer, ISO7816.OFFSET_CDATA, initialLength);
        APDU apdu = Mockito.mock(APDU.class);
        when(apdu.getBuffer()).thenReturn(buffer);
        when(apdu.getOffsetCdata()).thenReturn((short) ISO7816.OFFSET_CDATA);
        when(apdu.getIncomingLength()).thenReturn(OpenFIPS201.MAX_SHORT_APDU_DATA_LENGTH);
        when(apdu.setIncomingAndReceive()).thenReturn((short) initialLength);
        doAnswer(
                call -> {
                  short offset = call.getArgument(0);
                  assertTrue(
                      buffer.length - offset >= INPUT_BLOCK_BYTES, "platform input-block capacity");
                  int remaining = expected.length - initialLength;
                  if (valid) System.arraycopy(expected, initialLength, buffer, offset, remaining);
                  return (short) returnedLength;
                })
            .when(apdu)
            .receiveBytes(Mockito.anyShort());
        if (valid) {
          assertEquals(OpenFIPS201.MAX_SHORT_APDU_DATA_LENGTH, receive.invoke(applet, apdu));
          assertArrayEquals(
              expected, java.util.Arrays.copyOfRange(buffer, ISO7816.OFFSET_CDATA, buffer.length));
        } else {
          InvocationTargetException failure =
              assertThrows(InvocationTargetException.class, () -> receive.invoke(applet, apdu));
          assertEquals(ISO7816.SW_WRONG_LENGTH, ((ISOException) failure.getCause()).getReason());
        }
        byte[] prefix = (byte[]) field(applet, "receivePrefix").get(applet);
        assertArrayEquals(new byte[prefix.length], prefix);
      }
    }
  }

  @Test
  void malformedProtectedLengthsDestroySessionAndReturnSmStatus() throws Exception {
    // SP 800-73-5 Part 2 Section 4.2.7 distinguishes malformed SM (6988) from
    // missing objects (6987). Bytes outside Nc must never complete a truncated length.
    byte[][] bodies = {hex("8780"), hex("8783000001"), hex("8782FFFF"), hex("8781")};
    try (AutoCloseable ignored = enterEngineContext()) {
      Object piv =
          field(unwrapApplet(engine.getApplet(OPENFIPS201_AID)), "piv")
              .get(unwrapApplet(engine.getApplet(OPENFIPS201_AID)));
      Object sm = field(piv, "secureMessaging").get(piv);
      for (byte[] body : bodies) {
        establishSyntheticSession(sm);
        byte[] command = new byte[64];
        command[ISO7816.OFFSET_CLA] = PIVSecureMessaging.CLA_SECURE_MESSAGING;
        command[ISO7816.OFFSET_INS] = OpenFIPS201.INS_PIV_GET_DATA;
        System.arraycopy(body, 0, command, ISO7816.OFFSET_CDATA, body.length);
        ISOException failure =
            assertThrows(
                ISOException.class, () -> unwrapProtected(piv, command, (short) body.length));
        assertEquals(PIVSecureMessaging.SW_SM_OBJECTS_INCORRECT, failure.getReason());
        assertSessionDestroyed(piv, sm);
      }
    }
  }

  @Test
  void protectedPaddingIsLimitedToOneCipherBlock() throws Exception {
    // SP 800-73-5 Part 2 Section 4.2.2 requires one through sixteen padding octets.
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet applet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(applet, "piv").get(applet);
      Object sm = field(piv, "secureMessaging").get(piv);
      for (int paddingLength :
          new int[] {
            1,
            PIVCrypto.LENGTH_BLOCK_AES,
            PIVCrypto.LENGTH_BLOCK_AES + 1,
            2 * PIVCrypto.LENGTH_BLOCK_AES
          }) {
        establishSyntheticSession(sm);
        byte[] padded = new byte[3 * PIVCrypto.LENGTH_BLOCK_AES];
        int plaintextLength = padded.length - paddingLength;
        java.util.Arrays.fill(padded, 0, plaintextLength, SYNTHETIC_PLAINTEXT_BYTE);
        padded[plaintextLength] = PIVSecureMessaging.PADDING_DELIMITER;
        byte[] command = authenticatedPaddedDataCommand(padded);
        if (paddingLength <= PIVCrypto.LENGTH_BLOCK_AES) {
          assertEquals(
              plaintextLength,
              unwrapProtected(piv, command, (short) (command.length - ISO7816.OFFSET_CDATA)));
        } else {
          ISOException failure =
              assertThrows(
                  ISOException.class,
                  () ->
                      unwrapProtected(
                          piv, command, (short) (command.length - ISO7816.OFFSET_CDATA)));
          assertEquals(PIVSecureMessaging.SW_SM_OBJECTS_INCORRECT, failure.getReason());
          assertSessionDestroyed(piv, sm);
        }
      }
    }
  }

  @Test
  void commandProviderFailureDestroysKeysAndWorkBuffers() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet applet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(applet, "piv").get(applet);
      Object sm = field(piv, "secureMessaging").get(piv);
      Class<?> cryptoClass = piv.getClass().getClassLoader().loadClass(PIVCrypto.class.getName());
      for (boolean decrypt : new boolean[] {false, true}) {
        establishSyntheticSession(sm);
        seedWorkBuffers(piv);
        byte[] command = authenticatedEncryptedDataCommand(hex("5300"));
        try (org.mockito.MockedStatic<?> crypto =
            Mockito.mockStatic(cryptoClass, Mockito.CALLS_REAL_METHODS)) {
          org.mockito.MockedStatic.Verification operation;
          if (decrypt) {
            Method decryptMethod =
                method(
                    cryptoClass,
                    "doAesCbcDecrypt",
                    javacard.security.SecretKey.class,
                    byte[].class,
                    short.class,
                    short.class,
                    byte[].class,
                    short.class,
                    short.class,
                    byte[].class,
                    short.class);
            operation =
                () ->
                    decryptMethod.invoke(
                        null,
                        Mockito.any(javacard.security.SecretKey.class),
                        Mockito.any(byte[].class),
                        Mockito.anyShort(),
                        Mockito.anyShort(),
                        Mockito.any(byte[].class),
                        Mockito.anyShort(),
                        Mockito.anyShort(),
                        Mockito.any(byte[].class),
                        Mockito.anyShort());
          } else {
            Method initMac =
                method(cryptoClass, "doAesCmacInit", javacard.security.SecretKey.class);
            operation = () -> initMac.invoke(null, Mockito.any(javacard.security.SecretKey.class));
          }
          crypto
              .when(operation)
              .thenThrow(
                  new javacard.security.CryptoException(
                      javacard.security.CryptoException.ILLEGAL_USE));
          ISOException failure =
              assertThrows(
                  ISOException.class,
                  () ->
                      unwrapProtected(
                          piv, command, (short) (command.length - ISO7816.OFFSET_CDATA)));
          assertEquals(PIVSecureMessaging.SW_SM_OBJECTS_INCORRECT, failure.getReason());
        }
        assertSessionDestroyed(piv, sm);
      }
    }
  }

  private static void seedWorkBuffers(Object piv) throws Exception {
    // Nonzero synthetic sentinels ensure cleanup checks cannot pass on untouched zero-filled RAM.
    for (String name : new String[] {"scratch", "smCommand", "smResponse"}) {
      java.util.Arrays.fill((byte[]) field(piv, name).get(piv), (byte) 0xA5);
    }
  }

  private static void establishSyntheticSession(Object sm) throws Exception {
    loadSessionKeys(sm, zeroSessionKeys());
    method(sm.getClass(), "markEstablished", boolean.class).invoke(sm, false);
  }

  private static short unwrapProtected(Object piv, byte[] command, short length) throws Exception {
    try {
      return (short)
          method(
                  piv.getClass(),
                  "unwrapSecureMessagingCommand",
                  byte[].class,
                  short.class,
                  short.class)
              .invoke(piv, command, (short) 5, length);
    } catch (InvocationTargetException failure) {
      if (failure.getCause() instanceof ISOException) throw (ISOException) failure.getCause();
      throw failure;
    }
  }

  private static void assertSessionDestroyed(Object piv, Object sm) throws Exception {
    assertEquals(false, method(sm.getClass(), "isEstablished").invoke(sm));
    assertEquals(false, method(sm.getClass(), "isVciEstablished").invoke(sm));
    for (String keyName : new String[] {"skCfrm", "skMac", "skEnc", "skRmac"}) {
      assertTrue(!((AESKey) field(sm, keyName).get(sm)).isInitialized(), keyName);
    }
    for (String bufferName : new String[] {"scratch", "smCommand", "smResponse"}) {
      byte[] buffer = (byte[]) field(piv, bufferName).get(piv);
      assertTrue(allZero(buffer), bufferName + " cleared");
    }
    for (String name :
        new String[] {
          "commandMcv",
          "responseMcv",
          "encCounter",
          "responseIv",
          "responseBlock",
          "responseCandidateMcv",
          "responseTail",
          "commandStreamHeader",
          "commandStreamBlock",
          "commandStreamMac"
        }) {
      assertTrue(allZero((byte[]) field(sm, name).get(sm)), name + " cleared");
    }
    for (String name : new String[] {"responseState", "commandStreamState"}) {
      for (short value : (short[]) field(sm, name).get(sm)) assertEquals((short) 0, value, name);
    }
    assertEquals(false, method(sm.getClass(), "isResponseStreamActive").invoke(sm));
  }

  private static boolean allZero(byte[] buffer) {
    int combined = 0;
    for (byte value : buffer) combined |= value;
    return combined == 0;
  }

  @Test
  void sessionKeyBundleMapsEachPurposeToItsOwnSlot() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(realApplet, "piv").get(realApplet);
      Object secureMessaging = field(piv, "secureMessaging").get(piv);
      byte[] sessionKeys = distinctSessionKeys();
      loadSessionKeys(secureMessaging, sessionKeys);

      String[] fields = {"skCfrm", "skMac", "skEnc", "skRmac"};
      short keyLength = activeSessionKeyBytes();
      for (short slot = 0; slot < (short) fields.length; slot++) {
        byte[] actual = new byte[keyLength];
        AESKey key = (AESKey) field(secureMessaging, fields[slot]).get(secureMessaging);
        assertEquals(keyLength, key.getKey(actual, (short) 0), fields[slot] + " length");
        byte[] expected = new byte[keyLength];
        System.arraycopy(sessionKeys, slot * keyLength, expected, 0, keyLength);
        assertArrayEquals(expected, actual, fields[slot] + " session-key slot");
      }
    }
  }

  @Test
  void secureOutgoingStreamsProtectedResponseAcrossPhysicalGetResponse() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(realApplet, "piv").get(realApplet);
      Object chainBuffer = field(piv, "chainBuffer").get(piv);
      Object secureMessaging = field(piv, "secureMessaging").get(piv);
      Class<?> secureMessagingClass = secureMessaging.getClass();
      loadSessionKeys(secureMessaging, zeroSessionKeys());
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);

      byte[] outgoing = new byte[256];
      method(
              chainBuffer.getClass(),
              "setOutgoing",
              byte[].class,
              short.class,
              short.class,
              boolean.class)
          .invoke(chainBuffer, outgoing, (short) 0, (short) outgoing.length, false);

      byte[] apduBuffer = new byte[5];
      apduBuffer[ISO7816.OFFSET_INS] = (byte) 0xCB;
      APDU apdu = Mockito.mock(APDU.class);
      when(apdu.getBuffer()).thenReturn(apduBuffer);
      when(apdu.setOutgoing()).thenReturn(OpenFIPS201.MAX_SHORT_APDU_RESPONSE_LENGTH);

      final short[] sentLength = new short[] {(short) 0};
      final byte[][] sent = new byte[][] {new byte[256]};
      doAnswer(
              invocation -> {
                byte[] source = invocation.getArgument(0);
                short offset = invocation.getArgument(1);
                short length = invocation.getArgument(2);
                sentLength[0] = length;
                System.arraycopy(source, offset, sent[0], 0, length);
                return null;
              })
          .when(apdu)
          .sendBytesLong(Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyShort());

      Method processOutgoingSecure =
          method(
              chainBuffer.getClass(),
              "processOutgoingSecure",
              APDU.class,
              secureMessagingClass,
              byte[].class,
              short.class);
      InvocationTargetException first =
          assertThrows(
              InvocationTargetException.class,
              () ->
                  processOutgoingSecure.invoke(
                      chainBuffer, apdu, secureMessaging, new byte[448], ISO7816.SW_NO_ERROR));

      assertTrue(first.getCause() instanceof ISOException);
      assertEquals((short) 0x6123, ((ISOException) first.getCause()).getReason());
      assertEquals((short) 256, sentLength[0]);
      assertEquals((byte) 0x87, sent[0][0]);
      assertEquals((byte) 0x82, sent[0][1]);
      assertEquals((byte) 0x01, sent[0][2]);
      assertEquals((byte) 0x11, sent[0][3]);
      assertEquals((byte) 0x01, sent[0][4]);

      apduBuffer[ISO7816.OFFSET_INS] = OpenFIPS201.INS_GP_GET_RESPONSE;
      InvocationTargetException second =
          assertThrows(
              InvocationTargetException.class,
              () ->
                  processOutgoingSecure.invoke(
                      chainBuffer, apdu, secureMessaging, new byte[448], ISO7816.SW_NO_ERROR));
      assertTrue(second.getCause() instanceof ISOException);
      assertEquals(ISO7816.SW_NO_ERROR, ((ISOException) second.getCause()).getReason());
      assertEquals((short) 35, sentLength[0]);
    }
  }

  @Test
  void unrelatedCommandAbortsPlainOutgoingResponse() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT before interrupted plaintext response");

    try (AutoCloseable ignored = enterEngineContext()) {
      Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(realApplet, "piv").get(realApplet);
      Object chainBuffer = field(piv, "chainBuffer").get(piv);
      method(
              chainBuffer.getClass(),
              "setOutgoing",
              byte[].class,
              short.class,
              short.class,
              boolean.class)
          .invoke(chainBuffer, new byte[300], (short) 0, (short) 300, false);
    }

    ResponseAPDU verifyStatus = transmit(new CommandAPDU(0x00, 0x20, 0x00, 0x80));
    assertEquals(0x63C6, verifyStatus.getSW(), "The intervening command must execute normally");
    // An idle GET RESPONSE has no data field to be incorrect; it reports 6985 as the protected
    // GET RESPONSE path does.
    assertSw(
        ISO7816.SW_CONDITIONS_NOT_SATISFIED,
        transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00, 0)),
        "GET RESPONSE must not resume the abandoned response");
  }

  @Test
  void objectChainRejectsProtectionContextChangeAndRollsBack() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      ChainBuffer chain = new ChainBuffer();
      byte[] original = new byte[] {0x11, 0x22, 0x33, 0x44};
      PIVDataObject destination = publishedObject(original);
      chain.setIncomingObject(destination, (short) 4);

      byte[] first = hex("10DB3FFF02AABB");
      ISOException accepted =
          assertThrows(
              ISOException.class,
              () ->
                  chain.processIncomingObject(
                      first, (short) 5, (short) 2, ChainBuffer.PROTECTION_SCP));
      assertEquals(ISO7816.SW_NO_ERROR, accepted.getReason());

      byte[] downgraded = hex("00DB3FFF02CCDD");
      ISOException rejected =
          assertThrows(
              ISOException.class,
              () ->
                  chain.processIncomingObject(
                      downgraded, (short) 5, (short) 2, ChainBuffer.PROTECTION_PLAIN));
      assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, rejected.getReason());
      assertArrayEquals(
          original, destination.content, "A protection mismatch must roll back staged data");

      destination.beginUpdate((short) 8);
      destination.commitUpdate();
      assertEquals(8, destination.getLength(), "A rolled-back object remains safely reallocatable");
    }
  }

  @Test
  void unrelatedCommandSoftAbortsProtectedObjectChain() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      ChainBuffer chain = new ChainBuffer();
      byte[] original = new byte[] {0x11, 0x22, 0x33, 0x44};
      PIVDataObject destination = publishedObject(original);
      chain.setIncomingObject(destination, (short) 4);

      byte[] first = hex("10DB3FFF02AABB");
      ISOException accepted =
          assertThrows(
              ISOException.class,
              () ->
                  chain.processIncomingObject(
                      first, (short) 5, (short) 2, ChainBuffer.PROTECTION_SCP));
      assertEquals(ISO7816.SW_NO_ERROR, accepted.getReason());

      byte[] verify = hex("0020008000");
      chain.processIncomingObject(verify, (short) 5, (short) 0, ChainBuffer.PROTECTION_PLAIN);
      assertArrayEquals(original, destination.content, "The interrupted write must roll back");
    }
  }

  @Test
  void secureMessagingCommandSoftAbortsDifferentIncompleteApduChain() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(realApplet, "piv").get(realApplet);
      Object chainBuffer = field(piv, "chainBuffer").get(piv);
      Object secureMessaging = field(piv, "secureMessaging").get(piv);

      loadSessionKeys(secureMessaging, zeroSessionKeys());
      method(secureMessaging.getClass(), "markEstablished", boolean.class)
          .invoke(secureMessaging, false);

      byte[] chainedGa = hex("1087039B027C02");
      assertEquals(
          (short) 0,
          method(
                  chainBuffer.getClass(),
                  "processIncomingAPDU",
                  byte[].class,
                  short.class,
                  short.class,
                  byte[].class,
                  short.class)
              .invoke(chainBuffer, chainedGa, (short) 5, (short) 2, new byte[32], (short) 0));

      byte[] protectedVerify =
          macOnlySecureCommand(
              PIVSecureMessaging.CLA_SECURE_MESSAGING, (byte) 0x20, (byte) 0x00, (byte) 0x80);
      short length =
          (Short)
              method(
                      piv.getClass(),
                      "unwrapSecureMessagingCommand",
                      byte[].class,
                      short.class,
                      short.class)
                  .invoke(piv, protectedVerify, (short) 5, (short) 10);

      assertEquals((short) 0, length, "The interrupting SM command must be processed afresh");
      assertEquals((byte) 0x20, protectedVerify[ISO7816.OFFSET_INS]);
    }
  }

  @Test
  void interruptedProtectedResponseKeepsDeliveredRmacAndAdvancesCounterOnce() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT before interrupted protected response");

    try (AutoCloseable ignored = enterEngineContext()) {
      Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(realApplet, "piv").get(realApplet);
      Class<?> pivClass = piv.getClass();
      Object chainBuffer = field(piv, "chainBuffer").get(piv);
      Object secureMessaging = field(piv, "secureMessaging").get(piv);
      Class<?> secureMessagingClass = secureMessaging.getClass();
      byte[] sessionKeys = zeroSessionKeys();
      loadSessionKeys(secureMessaging, sessionKeys);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);

      byte[] command =
          macOnlySecureCommand(
              PIVSecureMessaging.CLA_SECURE_MESSAGING, (byte) 0xCB, (byte) 0x3F, (byte) 0xFF);
      method(
              secureMessagingClass,
              "unwrapCommand",
              byte[].class,
              short.class,
              short.class,
              byte[].class,
              short.class)
          .invoke(secureMessaging, command, (short) 5, (short) 10, new byte[512], (short) 0);

      method(
              chainBuffer.getClass(),
              "setOutgoing",
              byte[].class,
              short.class,
              short.class,
              boolean.class)
          .invoke(chainBuffer, new byte[256], (short) 0, (short) 256, true);
      ((byte[]) field(piv, "secureMessagingCommand").get(piv))[0] = (byte) 1;

      byte[] deliveredRmac =
          ((byte[]) field(secureMessaging, "responseMcv").get(secureMessaging)).clone();
      byte[] counterBefore = counter(secureMessaging);
      APDU apdu = streamingApdu((byte) 0xCB, (short) 32);
      InvocationTargetException first =
          assertThrows(
              InvocationTargetException.class,
              () -> method(pivClass, "processOutgoing", APDU.class).invoke(piv, apdu));
      assertTrue(first.getCause() instanceof ISOException);
      assertEquals((short) 0x6100, ((ISOException) first.getCause()).getReason());

      assertArrayEquals(
          deliveredRmac,
          (byte[]) field(secureMessaging, "responseMcv").get(secureMessaging),
          "An R-MCV is published only after its complete response is delivered");

      method(pivClass, "abortOutgoingResponse").invoke(piv);
      byte[] expectedCounter = counterBefore.clone();
      expectedCounter[15]++;
      assertArrayEquals(expectedCounter, counter(secureMessaging));
      assertArrayEquals(
          deliveredRmac, (byte[]) field(secureMessaging, "responseMcv").get(secureMessaging));
      assertEquals(
          false, method(secureMessagingClass, "isResponseStreamActive").invoke(secureMessaging));
      assertEquals(false, method(chainBuffer.getClass(), "isOutgoingActive").invoke(chainBuffer));

      method(pivClass, "abortOutgoingResponse").invoke(piv);
      assertArrayEquals(
          expectedCounter,
          counter(secureMessaging),
          "Repeated aborts must not advance the logical command counter again");
    }
  }

  /**
   * Verifies that command unwrapping preserves the command chaining bit in CLA.
   *
   * <p>Aligned with NIST SP 800-73-5 Part 2, Section 4.2.4 (Chained command under secure
   * messaging).
   */
  @Test
  void unwrapPreservesCommandChainingBit() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(realApplet, "piv").get(realApplet);
      Object secureMessaging = field(piv, "secureMessaging").get(piv);
      Class<?> secureMessagingClass = secureMessaging.getClass();
      Object chainBuffer = field(piv, "chainBuffer").get(piv);
      byte[] sessionKeys = zeroSessionKeys();
      loadSessionKeys(secureMessaging, sessionKeys);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);

      byte[] command = new byte[15];
      command[ISO7816.OFFSET_CLA] = PIVSecureMessaging.CLA_CHAINED_SECURE_MESSAGING;
      command[ISO7816.OFFSET_INS] = (byte) 0xDB;
      command[ISO7816.OFFSET_P1] = (byte) 0x3F;
      command[ISO7816.OFFSET_P2] = (byte) 0x00;
      command[ISO7816.OFFSET_LC] = (byte) 0x0A;
      command[5] = (byte) 0x8E;
      command[6] = (byte) 0x08;
      byte[] work = new byte[128];
      byte[] macInput = new byte[64];
      short macLength = buildMacOnlyCommandInput(command, macInput);
      AESKey macKey = PIVCrypto.buildTransientAesKey(activeSessionKeyBits());
      macKey.setKey(sessionKeys, activeSessionKeyBytes());
      PIVCrypto.doAesCmac(macKey, macInput, (short) 0, macLength, work, (short) 0);
      System.arraycopy(work, 0, command, 7, 8);

      short plaintextLength =
          (Short)
              method(
                      secureMessagingClass,
                      "unwrapCommand",
                      byte[].class,
                      short.class,
                      short.class,
                      byte[].class,
                      short.class)
                  .invoke(secureMessaging, command, (short) 5, (short) 10, work, (short) 0);

      assertEquals((short) 0, plaintextLength, "MAC-only SM command has no plaintext body");
      assertEquals(
          (byte) 0x10, command[ISO7816.OFFSET_CLA], "SM unwrap must preserve command chaining");
    }
  }

  /**
   * Verifies that command C-MAC verification does not stage the whole MAC input in the small
   * response buffer.
   *
   * <p>The encrypted data object is authenticated but intentionally not valid ciphertext for the
   * all-zero session key. A correct implementation reaches padding validation and returns the
   * secure-messaging object error instead of overflowing while preparing the C-MAC input.
   */
  @Test
  void unwrapLargeAuthenticatedCommandBodyDoesNotOverflowMacWorkspace() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(realApplet, "piv").get(realApplet);
      Object secureMessaging = field(piv, "secureMessaging").get(piv);
      Class<?> secureMessagingClass = secureMessaging.getClass();
      byte[] sessionKeys = zeroSessionKeys();
      loadSessionKeys(secureMessaging, sessionKeys);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);

      byte[] command = largeAuthenticatedEncryptedDataCommand();
      byte[] work = new byte[320];
      InvocationTargetException thrown =
          assertThrows(
              InvocationTargetException.class,
              () ->
                  method(
                          secureMessagingClass,
                          "unwrapCommand",
                          byte[].class,
                          short.class,
                          short.class,
                          byte[].class,
                          short.class)
                      .invoke(
                          secureMessaging,
                          command,
                          (short) 5,
                          (short) (command.length - ISO7816.OFFSET_CDATA),
                          work,
                          (short) 0));

      assertTrue(thrown.getCause() instanceof ISOException);
      assertEquals(
          PIVSecureMessaging.SW_SM_OBJECTS_INCORRECT,
          ((ISOException) thrown.getCause()).getReason());
    }
  }

  @Test
  void unwrapMultiBlockEncryptedCommandUsesNonOverlappingCbcOutput() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(realApplet, "piv").get(realApplet);
      Object secureMessaging = field(piv, "secureMessaging").get(piv);
      Class<?> secureMessagingClass = secureMessaging.getClass();
      byte[] sessionKeys = zeroSessionKeys();
      loadSessionKeys(secureMessaging, sessionKeys);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);

      byte[] expectedPlaintext = hex("00112233445566778899AABBCCDDEEFF10");
      byte[] command = authenticatedEncryptedDataCommand(expectedPlaintext);
      byte[] work = new byte[320];
      short plaintextLength =
          (Short)
              method(
                      secureMessagingClass,
                      "unwrapCommand",
                      byte[].class,
                      short.class,
                      short.class,
                      byte[].class,
                      short.class)
                  .invoke(
                      secureMessaging,
                      command,
                      (short) 5,
                      (short) (command.length - ISO7816.OFFSET_CDATA),
                      work,
                      (short) 0);

      assertEquals((short) expectedPlaintext.length, plaintextLength);
      for (short i = 0; i < plaintextLength; i++) {
        assertEquals(expectedPlaintext[i], command[(short) (5 + i)], "plaintext byte " + i);
      }
    }
  }

  @Test
  void incomingChainDuringOutgoingStateFailsClosed() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(realApplet, "piv").get(realApplet);
      Object chainBuffer = field(piv, "chainBuffer").get(piv);
      method(
              chainBuffer.getClass(),
              "setOutgoing",
              byte[].class,
              short.class,
              short.class,
              boolean.class)
          .invoke(chainBuffer, new byte[32], (short) 0, (short) 32, false);

      byte[] commandData = new byte[] {0x01, 0x02};
      byte[] destination = new byte[16];
      InvocationTargetException thrown =
          assertThrows(
              InvocationTargetException.class,
              () ->
                  method(
                          chainBuffer.getClass(),
                          "processIncomingAPDU",
                          byte[].class,
                          short.class,
                          short.class,
                          byte[].class,
                          short.class)
                      .invoke(
                          chainBuffer,
                          commandData,
                          (short) 0,
                          (short) commandData.length,
                          destination,
                          (short) 0));

      assertTrue(thrown.getCause() instanceof ISOException);
      assertEquals(
          ISO7816.SW_CONDITIONS_NOT_SATISFIED, ((ISOException) thrown.getCause()).getReason());
    }
  }

  /**
   * Verifies that command chaining fragments are reassembled before performing C-MAC verification.
   *
   * <p>Aligned with NIST SP 800-73-5 Part 2, Section 4.2.4. Only the final command APDU in the
   * chain (having CLA '0C') triggers the full unwrap and MAC validation process.
   */
  @Test
  void secureMessagingCommandChainingReassemblesBeforeMacVerification() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(realApplet, "piv").get(realApplet);
      Object secureMessaging = field(piv, "secureMessaging").get(piv);
      Class<?> secureMessagingClass = secureMessaging.getClass();
      byte[] sessionKeys = zeroSessionKeys();
      loadSessionKeys(secureMessaging, sessionKeys);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);

      byte[] complete =
          macOnlySecureCommand(
              PIVSecureMessaging.CLA_SECURE_MESSAGING, (byte) 0xDB, (byte) 0x3F, (byte) 0x00);
      byte[] first = new byte[10];
      first[ISO7816.OFFSET_CLA] = PIVSecureMessaging.CLA_CHAINED_SECURE_MESSAGING;
      first[ISO7816.OFFSET_INS] = complete[ISO7816.OFFSET_INS];
      first[ISO7816.OFFSET_P1] = complete[ISO7816.OFFSET_P1];
      first[ISO7816.OFFSET_P2] = complete[ISO7816.OFFSET_P2];
      first[ISO7816.OFFSET_LC] = (byte) 0x05;
      System.arraycopy(complete, 5, first, 5, 5);

      byte[] last = new byte[10];
      last[ISO7816.OFFSET_CLA] = PIVSecureMessaging.CLA_SECURE_MESSAGING;
      last[ISO7816.OFFSET_INS] = complete[ISO7816.OFFSET_INS];
      last[ISO7816.OFFSET_P1] = complete[ISO7816.OFFSET_P1];
      last[ISO7816.OFFSET_P2] = complete[ISO7816.OFFSET_P2];
      last[ISO7816.OFFSET_LC] = (byte) 0x05;
      System.arraycopy(complete, 10, last, 5, 5);

      Method unwrapSecureMessagingCommand =
          method(
              piv.getClass(),
              "unwrapSecureMessagingCommand",
              byte[].class,
              short.class,
              short.class);
      InvocationTargetException firstResult =
          assertThrows(
              InvocationTargetException.class,
              () -> unwrapSecureMessagingCommand.invoke(piv, first, (short) 5, (short) 5));
      assertTrue(
          firstResult.getCause() instanceof ISOException,
          "Intermediate chained secure fragment should complete with SW_NO_ERROR");
      assertEquals(
          ISO7816.SW_NO_ERROR,
          ((ISOException) firstResult.getCause()).getReason(),
          "Intermediate chained secure fragment should wait for the final MAC");

      short plaintextLength =
          (Short) unwrapSecureMessagingCommand.invoke(piv, last, (short) 5, (short) 5);

      assertEquals((short) 0, plaintextLength, "Reassembled MAC-only command has no plaintext");
      assertEquals((byte) 0x00, last[ISO7816.OFFSET_CLA], "Final unwrapped CLA should be plain");
    }
  }

  /**
   * Verifies bounded processing of a protected PUT DATA command that is larger than the secure
   * messaging work buffer.
   *
   * <p>SP 800-73-5 Part 2, Section 4.2.4 says the card "reconstructs and processes the entire
   * command." Table 2 requires {@code 6A81} for contactless PUT DATA. The applet must authenticate
   * every frame before it returns that protected application status.
   */
  @Test
  void largeContactlessPutDataChainReturnsProtectedFunctionNotSupported() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT before the protected PUT DATA chain");

    Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
    Object piv = field(realApplet, "piv").get(realApplet);
    Object secureMessaging = field(piv, "secureMessaging").get(piv);
    Class<?> secureMessagingClass = secureMessaging.getClass();

    try (AutoCloseable ignored = enterEngineContext()) {
      loadSessionKeys(secureMessaging, zeroSessionKeys());
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);
      method(piv.getClass(), "setIsContactless", boolean.class).invoke(piv, true);
    }

    byte[] plaintext = new byte[600];
    for (short i = 0; i < (short) plaintext.length; i++) {
      plaintext[i] = (byte) i;
    }
    byte[] command = authenticatedEncryptedDataCommand(plaintext);
    int bodyOffset = 5;
    int firstLength = 220;
    int secondLength = 220;
    byte[] first = commandFragment(command, bodyOffset, firstLength, false);
    byte[] second = commandFragment(command, bodyOffset + firstLength, secondLength, false);
    byte[] last =
        commandFragment(
            command,
            bodyOffset + firstLength + secondLength,
            command.length - bodyOffset - firstLength - secondLength,
            true);

    assertSw(0x9000, transmit(new CommandAPDU(first)), "first protected PUT DATA frame");
    assertSw(0x9000, transmit(new CommandAPDU(second)), "second protected PUT DATA frame");
    ResponseAPDU response = transmit(new CommandAPDU(last));

    assertSw(0x9000, response, "protected PUT DATA policy response");
    assertEncapsulatedStatus(
        (short) 0x6A81,
        response,
        "Table 2 contactless PUT DATA status after complete command authentication");
    assertEquals(
        true,
        method(secureMessagingClass, "isEstablished").invoke(secureMessaging),
        "A protected application status must retain the secure messaging session");
  }

  @Test
  void largeProtectedPutDataUsesTheReassembledPlaintextBuffer() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT before protected PUT DATA");

    Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
    Object piv = field(realApplet, "piv").get(realApplet);
    Object dataStore = field(piv, "dataStore").get(piv);
    Object securityProvider = field(piv, "cspPIV").get(piv);
    Object secureMessaging = field(piv, "secureMessaging").get(piv);
    Class<?> secureMessagingClass = secureMessaging.getClass();
    byte[] objectId = hex("5FC108");

    try (AutoCloseable ignored = enterEngineContext()) {
      // Admin key 00 matches the fresh transient authorization state. This isolates dispatch and
      // storage from management-key authentication, which has separate conformance coverage.
      method(
              dataStore.getClass(),
              "create",
              byte[].class,
              short.class,
              short.class,
              byte.class,
              byte.class,
              byte.class,
              short.class)
          .invoke(
              dataStore,
              objectId,
              (short) 0,
              (short) objectId.length,
              PIVObject.ACCESS_MODE_ALWAYS,
              PIVObject.ACCESS_MODE_ALWAYS,
              (byte) 0x00,
              (short) 300);
      method(securityProvider.getClass(), "setAuthenticatedKey", byte.class)
          .invoke(securityProvider, (byte) 0x9B);
      loadSessionKeys(secureMessaging, zeroSessionKeys());
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);
    }

    // A 260-byte plaintext crosses the simulator's APDU-buffer boundary after decryption while
    // remaining within the CS2 secure-command buffer.
    byte[] value = new byte[252];
    for (int i = 0; i < value.length; i++) value[i] = (byte) i;
    byte[] plaintext = new byte[8 + value.length];
    System.arraycopy(hex("5C035FC1085381FC"), 0, plaintext, 0, 8);
    System.arraycopy(value, 0, plaintext, 8, value.length);
    byte[] command = authenticatedEncryptedDataCommand(plaintext);

    int firstLength = 150;
    assertSw(
        0x9000,
        transmit(new CommandAPDU(commandFragment(command, 5, firstLength, false))),
        "first protected PUT DATA frame");
    ResponseAPDU response =
        transmit(
            new CommandAPDU(
                commandFragment(
                    command,
                    5 + firstLength,
                    command.length - ISO7816.OFFSET_CDATA - firstLength,
                    true)));

    assertSw(0x9000, response, "protected PUT DATA response");
    // Protected PUT is an extension, but must still authenticate its success status using
    // the ordinary SP 800-73-5 Part 2 Section 4.2.6 response envelope.
    byte[] expectedStatus = hex("990290008E08");
    byte[] responseMacInput = new byte[20];
    System.arraycopy(expectedStatus, 0, responseMacInput, 16, 4);
    byte[] expectedMac = aesCmac(zeroSessionKey(), responseMacInput);
    byte[] expectedResponse = new byte[14];
    System.arraycopy(expectedStatus, 0, expectedResponse, 0, expectedStatus.length);
    System.arraycopy(expectedMac, 0, expectedResponse, 6, 8);
    assertArrayEquals(expectedResponse, response.getData(), "authenticated success status");
    Object stored =
        method(dataStore.getClass(), "find", byte[].class, short.class, short.class)
            .invoke(dataStore, objectId, (short) 0, (short) objectId.length);
    assertEquals((short) 255, method(stored.getClass(), "getLength").invoke(stored));
    byte[] storedContent = (byte[]) field(stored, "content").get(stored);
    assertEquals((byte) 0x53, storedContent[0]);
    assertEquals(value[251], storedContent[254]);
  }

  @Test
  void largeContactlessPutDataChainRejectsBadFinalCmacAndClearsSession() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT before the invalid protected PUT DATA chain");

    Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
    Object piv = field(realApplet, "piv").get(realApplet);
    Object secureMessaging = field(piv, "secureMessaging").get(piv);
    Class<?> secureMessagingClass = secureMessaging.getClass();
    try (AutoCloseable ignored = enterEngineContext()) {
      loadSessionKeys(secureMessaging, zeroSessionKeys());
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);
      method(piv.getClass(), "setIsContactless", boolean.class).invoke(piv, true);
    }

    byte[] command = authenticatedEncryptedDataCommand(new byte[600]);
    command[command.length - 1] ^= (byte) 0x01;
    byte[] first = commandFragment(command, 5, 220, false);
    byte[] second = commandFragment(command, 225, 220, false);
    byte[] last = commandFragment(command, 445, command.length - 445, true);

    assertSw(0x9000, transmit(new CommandAPDU(first)), "first invalid-C-MAC frame");
    assertSw(0x9000, transmit(new CommandAPDU(second)), "second invalid-C-MAC frame");
    assertSw(
        0x6988,
        transmit(new CommandAPDU(last)),
        "Section 4.2.7 status for an incorrect secure messaging data object");
    assertEquals(
        false,
        method(secureMessagingClass, "isEstablished").invoke(secureMessaging),
        "Section 4.3 requires key destruction after a secure messaging error");
  }

  @Test
  void differentProtectedCommandAbortsIncompleteRejectedPutDataChain() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT before interrupted protected PUT DATA");

    Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
    Object piv = field(realApplet, "piv").get(realApplet);
    Object secureMessaging = field(piv, "secureMessaging").get(piv);
    Class<?> secureMessagingClass = secureMessaging.getClass();
    try (AutoCloseable ignored = enterEngineContext()) {
      loadSessionKeys(secureMessaging, zeroSessionKeys());
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);
      method(piv.getClass(), "setIsContactless", boolean.class).invoke(piv, true);
    }

    byte[] command = authenticatedEncryptedDataCommand(new byte[600]);
    assertSw(
        0x9000,
        transmit(new CommandAPDU(commandFragment(command, 5, 220, false))),
        "incomplete protected PUT DATA frame");

    ResponseAPDU response =
        transmit(
            new CommandAPDU(
                macOnlySecureCommand(
                    PIVSecureMessaging.CLA_SECURE_MESSAGING, (byte) 0xFE, (byte) 0, (byte) 0)));
    assertSw(0x9000, response, "replacement protected command");
    assertEncapsulatedStatus(
        ISO7816.SW_INS_NOT_SUPPORTED,
        response,
        "ISO/IEC 7816-4 replacement command after an interrupted chain");
    assertEquals(
        true,
        method(secureMessagingClass, "isEstablished").invoke(secureMessaging),
        "Interrupting a command chain must not create a secure messaging error");
  }

  /**
   * Verifies that a secure messaging processing error immediately zeroizes the session keys.
   *
   * <p>Aligned with NIST SP 800-73-5 Part 2, Sections 4.2.7 and 4.3. A C-MAC ('8E') that fails
   * verification is an incorrect secure messaging data object, so the SW processing status is '69
   * 88' (Section 4.2.7), returned without performing further secure messaging. Because that SW
   * processing status is other than '61 XX' or '90 00', an error has occurred in secure messaging
   * and the session keys must be zeroized (Section 4.3).
   */
  @Test
  void secureMessagingErrorClearsSessionKeys() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(realApplet, "piv").get(realApplet);
      Object secureMessaging = field(piv, "secureMessaging").get(piv);
      Class<?> secureMessagingClass = secureMessaging.getClass();
      byte[] sessionKeys = zeroSessionKeys();
      loadSessionKeys(secureMessaging, sessionKeys);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);

      byte[] command =
          macOnlySecureCommand(
              PIVSecureMessaging.CLA_SECURE_MESSAGING, (byte) 0xDB, (byte) 0x3F, (byte) 0x00);
      command[14] ^= (byte) 0x01;
      Method unwrapSecureMessagingCommand =
          method(
              piv.getClass(),
              "unwrapSecureMessagingCommand",
              byte[].class,
              short.class,
              short.class);

      InvocationTargetException thrown =
          assertThrows(
              InvocationTargetException.class,
              () -> unwrapSecureMessagingCommand.invoke(piv, command, (short) 5, (short) 10));

      assertTrue(thrown.getCause() instanceof ISOException, "Bad C-MAC should be rejected");
      assertEquals(
          PIVSecureMessaging.SW_SM_OBJECTS_INCORRECT,
          ((ISOException) thrown.getCause()).getReason(),
          "Bad C-MAC is an incorrect secure messaging data object: '69 88' (Part 2 Section 4.2.7)");
      assertEquals(
          false,
          method(secureMessagingClass, "isEstablished").invoke(secureMessaging),
          "Session keys must be zeroized after a secure messaging error (Part 2 Section 4.3)");
    }
  }

  /**
   * Verifies that a plaintext APDU sent after key establishment is processed under the plaintext
   * access rules and leaves the session intact.
   *
   * <p>SP 800-73-5 Part 2 Section 4.2: after key establishment "subsequent communication with the
   * card CAN be performed using secure messaging", and SM-AUTH (Appendix A.6.1) continues in
   * plaintext. Section 4.3 lists the only session-key destruction triggers; a plaintext command is
   * none of them. VCI is satisfied only by a protected command.
   */
  @Test
  void plaintextApduDuringSecureMessagingUsesPlaintextRulesAndKeepsSession() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT before plaintext APDU");

    Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
    Object piv = field(realApplet, "piv").get(realApplet);
    Object secureMessaging = field(piv, "secureMessaging").get(piv);
    Class<?> secureMessagingClass = secureMessaging.getClass();

    try (AutoCloseable ignored = enterEngineContext()) {
      byte[] sessionKeys = zeroSessionKeys();
      loadSessionKeys(secureMessaging, sessionKeys);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);
    }

    ResponseAPDU response = transmit(new CommandAPDU(0x00, 0xCB, 0x3F, 0xFF, hex("5C017E"), 0));

    assertSw(
        ISO7816.SW_FILE_NOT_FOUND,
        response,
        "Plain GET DATA is processed under plaintext rules (no Discovery Object loaded)");
    assertEquals(
        true,
        method(secureMessagingClass, "isEstablished").invoke(secureMessaging),
        "A plaintext APDU must not destroy the secure messaging session");

    byte[] mcv = new byte[16];
    ResponseAPDU protectedResponse =
        transmit(
            new CommandAPDU(
                chainedMacOnlySecureCommand(
                    mcv,
                    PIVSecureMessaging.CLA_SECURE_MESSAGING,
                    (byte) 0xFE,
                    (byte) 0x00,
                    (byte) 0x00,
                    mcv)));
    assertSw(0x9000, protectedResponse, "The session continues after the plaintext APDU");
    assertEncapsulatedStatus(
        ISO7816.SW_INS_NOT_SUPPORTED, protectedResponse, "Protected command after plaintext APDU");
  }

  /**
   * SP 800-73-5 Part 2 Section 3.1.1: for a SELECT naming "an invalid AID not supported by the ICC,
   * then the PIV Card Application SHALL remain the currently selected application, and all PIV Card
   * Application security status indicators SHALL remain unchanged."
   */
  @Test
  void selectOfUnknownAidDuringSecureMessagingReturns6A82AndKeepsStatus() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT PIV");
    Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
    Object piv = field(realApplet, "piv").get(realApplet);
    Object sm = field(piv, "secureMessaging").get(piv);
    try (AutoCloseable ignored = enterEngineContext()) {
      establishSyntheticSession(sm);
      method(sm.getClass(), "markPairingVerified").invoke(sm);
    }

    assertSw(
        ISO7816.SW_FILE_NOT_FOUND,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, hex("A0000000999901"), 0)),
        "SELECT of an AID not on the ICC");
    assertEquals(true, method(sm.getClass(), "isEstablished").invoke(sm), "SM status unchanged");
    assertEquals(
        true, method(sm.getClass(), "isVciEstablished").invoke(sm), "Pairing status unchanged");
  }

  @Test
  void failedPlaintextOpacityReestablishmentDestroysPreviousSession() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT before plaintext OPACITY re-establishment");

    Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
    Object piv = field(realApplet, "piv").get(realApplet);
    Object secureMessaging = field(piv, "secureMessaging").get(piv);
    Class<?> secureMessagingClass = secureMessaging.getClass();

    try (AutoCloseable ignored = enterEngineContext()) {
      byte[] sessionKeys = zeroSessionKeys();
      loadSessionKeys(secureMessaging, sessionKeys);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);
    }

    ResponseAPDU response =
        transmit(
            new CommandAPDU(0x00, 0x87, PIV.ID_ALG_ECC_SM & 0xFF, 0x04, hex("7C058101008200"), 0));

    assertSw(
        0x6A86,
        response,
        "Plaintext OPACITY re-establishment reaches GENERAL AUTHENTICATE instead of SM teardown");
    assertEquals(
        false,
        method(secureMessagingClass, "isEstablished").invoke(secureMessaging),
        "SP 800-73-5 Part 2 Section 4.3 destroys old keys on a new establishment request");
    assertSessionDestroyed(piv, secureMessaging);
  }

  /**
   * SP 800-73-5 Part 2 Section 4.1 permits only OPACITY Case 1A to re-establish a session. A
   * generic ECDH tag 85 command on key 04 is rejected under the plaintext rules and, not being a
   * new establishment request (Section 4.3), leaves the current session in place.
   */
  @Test
  void plaintextEcdhOnSecureMessagingKeyDoesNotReplaceActiveSession() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT before plaintext ECDH rejection");

    Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
    Object piv = field(realApplet, "piv").get(realApplet);
    Object secureMessaging = field(piv, "secureMessaging").get(piv);
    Class<?> secureMessagingClass = secureMessaging.getClass();

    try (AutoCloseable ignored = enterEngineContext()) {
      loadSessionKeys(secureMessaging, zeroSessionKeys());
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);
    }

    byte[] publicPoint = new byte[isCs2Build() ? 65 : 97];
    publicPoint[0] = 0x04;
    ResponseAPDU response =
        transmit(
            new CommandAPDU(
                0x00,
                0x87,
                PIV.ID_ALG_ECC_SM & 0xFF,
                PIV.ID_KEY_SECURE_MESSAGING & 0xFF,
                tlv((byte) 0x7C, tlv((byte) 0x85, publicPoint)),
                0));

    assertTrue(
        response.getSW() != 0x9000 && (response.getSW() & 0xFF00) != 0x6100,
        "Generic ECDH on key 04 must be rejected, was " + Integer.toHexString(response.getSW()));
    assertEquals(
        true,
        method(secureMessagingClass, "isEstablished").invoke(secureMessaging),
        "Rejected plaintext ECDH is not an establishment request and keeps the session");
  }

  /**
   * Verifies that an application error inside a verified secure messaging exchange is returned
   * encapsulated and does not destroy the session.
   *
   * <p>Aligned with NIST SP 800-73-5 Part 2, Sections 4.2.6, 4.2.7 and 4.3. The application status
   * is returned in the '99' status template of a wrapped response (Section 4.2.6); the SW
   * processing status of that exchange (Section 4.2.7) is '90 00' because the secure messaging
   * itself was performed successfully; and session key destruction (Section 4.3) applies only when
   * the SW processing status is other than '61 XX' or '90 00' - that is, to the secure messaging
   * error statuses of Section 4.2.7, never to an encapsulated application status. NIST SD-33
   * reference cards behave exactly this way: their contactless vectors carry '99'-encapsulated
   * error statuses followed by further successful exchanges in the same session.
   */
  @Test
  void wrappedApplicationErrorIsEncapsulatedAndRetainsSession() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT before wrapped application error");

    try (AutoCloseable ignored = enterEngineContext()) {
      Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(realApplet, "piv").get(realApplet);
      Object secureMessaging = field(piv, "secureMessaging").get(piv);
      Class<?> secureMessagingClass = secureMessaging.getClass();
      byte[] sessionKeys = zeroSessionKeys();
      loadSessionKeys(secureMessaging, sessionKeys);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);

      // First protected command: INS 'FE' is unsupported, so command processing raises an
      // application error (SW_INS_NOT_SUPPORTED) after the secure messaging unwrap succeeded.
      byte[] mcv = new byte[16];
      byte[] first =
          chainedMacOnlySecureCommand(
              mcv,
              PIVSecureMessaging.CLA_SECURE_MESSAGING,
              (byte) 0xFE,
              (byte) 0x00,
              (byte) 0x00,
              mcv);
      ResponseAPDU firstResponse = transmit(new CommandAPDU(first));
      assertSw(
          0x9000,
          firstResponse,
          "A wrapped application error has SW processing status '90 00' (Part 2 Section 4.2.7)");
      assertEncapsulatedStatus(
          ISO7816.SW_INS_NOT_SUPPORTED,
          firstResponse,
          "Application status encapsulated in the '99' template (Part 2 Section 4.2.6)");

      // The session must survive: the next protected command, MAC-chained from the updated MCV,
      // must be accepted and answered with another wrapped response - not rejected bare.
      byte[] second =
          chainedMacOnlySecureCommand(
              mcv,
              PIVSecureMessaging.CLA_SECURE_MESSAGING,
              (byte) 0xFE,
              (byte) 0x00,
              (byte) 0x00,
              mcv);
      ResponseAPDU secondResponse = transmit(new CommandAPDU(second));
      assertSw(
          0x9000,
          secondResponse,
          "The session continues after a wrapped application error (Part 2 Section 4.3)");
      assertEncapsulatedStatus(
          ISO7816.SW_INS_NOT_SUPPORTED, secondResponse, "Second wrapped application error");

      assertEquals(
          true,
          method(secureMessagingClass, "isEstablished").invoke(secureMessaging),
          "An application error must not zeroize the session keys (Part 2 Section 4.3)");
    }
  }

  /**
   * Verifies that a secure response stream increments the encryption counter once when the logical
   * response completes.
   *
   * <p>Aligned with NIST SP 800-73-5 Part 2, Section 4.2.2 (Encryption counter increment
   * exceptions).
   */
  @Test
  void secureResponseStreamIncrementsEncryptionCounterOnceOnCompletion() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT before plain GET RESPONSE counter check");
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(realApplet, "piv").get(realApplet);
      Object secureMessaging = field(piv, "secureMessaging").get(piv);
      Class<?> secureMessagingClass = secureMessaging.getClass();
      Object chainBuffer = field(piv, "chainBuffer").get(piv);
      byte[] sessionKeys = zeroSessionKeys();
      loadSessionKeys(secureMessaging, sessionKeys);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);

      byte[] command =
          macOnlySecureCommand(
              PIVSecureMessaging.CLA_SECURE_MESSAGING, (byte) 0xCB, (byte) 0x3F, (byte) 0xFF);
      byte[] work = new byte[512];
      method(
              secureMessagingClass,
              "unwrapCommand",
              byte[].class,
              short.class,
              short.class,
              byte[].class,
              short.class)
          .invoke(secureMessaging, command, (short) 5, (short) 10, work, (short) 0);
      byte[] counterBeforeGetResponse = counter(secureMessaging);
      byte[] outgoing = new byte[] {(byte) 0xA5};
      method(
              chainBuffer.getClass(),
              "setOutgoing",
              byte[].class,
              short.class,
              short.class,
              boolean.class)
          .invoke(chainBuffer, outgoing, (short) 0, (short) outgoing.length, true);
      ((byte[]) field(piv, "secureMessagingCommand").get(piv))[0] = (byte) 1;
      method(secureMessagingClass, "beginResponseStream", short.class, short.class)
          .invoke(secureMessaging, (short) outgoing.length, ISO7816.SW_NO_ERROR);

      ResponseAPDU response = transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00, 0));

      assertSw(0x9000, response, "Plain GET RESPONSE secure continuation");

      byte[] expectedCounter = counterBeforeGetResponse.clone();
      expectedCounter[15]++;
      assertArrayEquals(
          expectedCounter,
          counter(secureMessaging),
          "Completing a secure response stream must increment the logical command counter once");
    }
  }

  @Test
  void spuriousPlainGetResponseAfterSecureStreamCompletionDoesNotAdvanceSession() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT before spurious GET RESPONSE check");
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(realApplet, "piv").get(realApplet);
      Object secureMessaging = field(piv, "secureMessaging").get(piv);
      Object chainBuffer = field(piv, "chainBuffer").get(piv);
      Class<?> pivClass = piv.getClass();
      Class<?> secureMessagingClass = secureMessaging.getClass();
      byte[] sessionKeys = zeroSessionKeys();
      loadSessionKeys(secureMessaging, sessionKeys);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);

      byte[] command =
          macOnlySecureCommand(
              PIVSecureMessaging.CLA_SECURE_MESSAGING, (byte) 0xCB, (byte) 0x3F, (byte) 0xFF);
      byte[] work = new byte[512];
      method(
              secureMessagingClass,
              "unwrapCommand",
              byte[].class,
              short.class,
              short.class,
              byte[].class,
              short.class)
          .invoke(secureMessaging, command, (short) 5, (short) 10, work, (short) 0);
      ((byte[]) field(piv, "secureMessagingCommand").get(piv))[0] = (byte) 1;

      byte[] outgoing = new byte[256];
      method(
              chainBuffer.getClass(),
              "setOutgoing",
              byte[].class,
              short.class,
              short.class,
              boolean.class)
          .invoke(chainBuffer, outgoing, (short) 0, (short) outgoing.length, false);

      APDU apdu = streamingApdu((byte) 0xCB);
      Method processOutgoing = method(pivClass, "processOutgoing", APDU.class);
      InvocationTargetException first =
          assertThrows(InvocationTargetException.class, () -> processOutgoing.invoke(piv, apdu));
      assertTrue(first.getCause() instanceof ISOException);
      assertEquals((short) 0x6123, ((ISOException) first.getCause()).getReason());

      apdu.getBuffer()[ISO7816.OFFSET_INS] = OpenFIPS201.INS_GP_GET_RESPONSE;
      Method continuation = method(pivClass, "processOutgoingSecureContinuation", APDU.class);
      InvocationTargetException second =
          assertThrows(InvocationTargetException.class, () -> continuation.invoke(piv, apdu));
      assertTrue(second.getCause() instanceof ISOException);
      assertEquals(ISO7816.SW_NO_ERROR, ((ISOException) second.getCause()).getReason());

      byte[] counterAfterCompletion = counter(secureMessaging);
      InvocationTargetException third =
          assertThrows(InvocationTargetException.class, () -> continuation.invoke(piv, apdu));
      assertTrue(third.getCause() instanceof ISOException);
      assertEquals(
          ISO7816.SW_CONDITIONS_NOT_SATISFIED, ((ISOException) third.getCause()).getReason());
      assertArrayEquals(
          counterAfterCompletion,
          counter(secureMessaging),
          "Spurious GET RESPONSE must not advance the SM encryption counter");
    }
  }

  @Test
  void plaintextGetResponseContinuesStatusOnlySecureResponseStream() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT before status-only secure response check");
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(realApplet, "piv").get(realApplet);
      Object secureMessaging = field(piv, "secureMessaging").get(piv);
      Class<?> pivClass = piv.getClass();
      Class<?> secureMessagingClass = secureMessaging.getClass();
      byte[] sessionKeys = zeroSessionKeys();
      loadSessionKeys(secureMessaging, sessionKeys);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);
      ((byte[]) field(piv, "secureMessagingCommand").get(piv))[0] = (byte) 1;

      APDU apdu = streamingApdu((byte) 0xCB, (short) 8);
      Method processOutgoing = method(pivClass, "processOutgoing", APDU.class);
      InvocationTargetException first =
          assertThrows(InvocationTargetException.class, () -> processOutgoing.invoke(piv, apdu));
      assertTrue(first.getCause() instanceof ISOException);
      assertEquals((short) 0x6106, ((ISOException) first.getCause()).getReason());

      apdu.getBuffer()[ISO7816.OFFSET_INS] = OpenFIPS201.INS_GP_GET_RESPONSE;
      Method continuation = method(pivClass, "processOutgoingSecureContinuation", APDU.class);
      InvocationTargetException second =
          assertThrows(InvocationTargetException.class, () -> continuation.invoke(piv, apdu));
      assertTrue(second.getCause() instanceof ISOException);
      assertEquals(ISO7816.SW_NO_ERROR, ((ISOException) second.getCause()).getReason());

      byte[] counterAfterCompletion = counter(secureMessaging);
      InvocationTargetException third =
          assertThrows(InvocationTargetException.class, () -> continuation.invoke(piv, apdu));
      assertTrue(third.getCause() instanceof ISOException);
      assertEquals(
          ISO7816.SW_CONDITIONS_NOT_SATISFIED, ((ISOException) third.getCause()).getReason());
      assertArrayEquals(
          counterAfterCompletion,
          counter(secureMessaging),
          "Spurious GET RESPONSE after status-only response must not advance SM state");
    }
  }

  @Test
  void secureMessagingFailsClosedWhenCmacProviderIsUnavailable() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT before CMAC provider check");
    try (AutoCloseable ignored = enterEngineContext()) {
      Object original = staticField(PIVCrypto.class, "cspAESCMAC").get(null);
      try {
        staticField(PIVCrypto.class, "cspAESCMAC").set(null, null);
        PIVSecureMessaging secureMessaging = new PIVSecureMessaging();
        ISOException thrown =
            assertThrows(
                ISOException.class,
                () -> secureMessaging.beginResponseStream((short) 0, ISO7816.SW_NO_ERROR));
        assertEquals((short) 0x6882, thrown.getReason());
      } finally {
        staticField(PIVCrypto.class, "cspAESCMAC").set(null, original);
      }
    }
  }

  @Test
  void protectedGetResponseDoesNotSuppressLogicalCommandCounterIncrement() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(realApplet, "piv").get(realApplet);
      Object secureMessaging = field(piv, "secureMessaging").get(piv);
      Class<?> secureMessagingClass = secureMessaging.getClass();
      Object chainBuffer = field(piv, "chainBuffer").get(piv);
      byte[] sessionKeys = zeroSessionKeys();
      loadSessionKeys(secureMessaging, sessionKeys);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);

      byte[] firstMcv = new byte[16];
      byte[] command =
          chainedMacOnlySecureCommand(
              new byte[16],
              PIVSecureMessaging.CLA_SECURE_MESSAGING,
              (byte) 0xCB,
              (byte) 0x3F,
              (byte) 0xFF,
              firstMcv);
      byte[] work = new byte[512];
      method(
              secureMessagingClass,
              "unwrapCommand",
              byte[].class,
              short.class,
              short.class,
              byte[].class,
              short.class)
          .invoke(secureMessaging, command, (short) 5, (short) 10, work, (short) 0);

      byte[] outgoing = new byte[256];
      method(
              chainBuffer.getClass(),
              "setOutgoing",
              byte[].class,
              short.class,
              short.class,
              boolean.class)
          .invoke(chainBuffer, outgoing, (short) 0, (short) outgoing.length, false);

      ByteArrayOutputStream protectedResponse = new ByteArrayOutputStream();
      APDU apdu = capturingStreamingApdu((byte) 0xCB, protectedResponse);
      Method processOutgoingSecure =
          method(
              chainBuffer.getClass(),
              "processOutgoingSecure",
              APDU.class,
              secureMessagingClass,
              byte[].class,
              short.class);
      InvocationTargetException first =
          assertThrows(
              InvocationTargetException.class,
              () ->
                  processOutgoingSecure.invoke(
                      chainBuffer, apdu, secureMessaging, new byte[448], ISO7816.SW_NO_ERROR));
      assertTrue(first.getCause() instanceof ISOException);
      assertEquals((short) 0x6123, ((ISOException) first.getCause()).getReason());

      byte[] protectedGetResponse =
          chainedMacOnlySecureCommand(
              firstMcv,
              PIVSecureMessaging.CLA_SECURE_MESSAGING,
              OpenFIPS201.INS_GP_GET_RESPONSE,
              (byte) 0x00,
              (byte) 0x00,
              new byte[16]);
      method(
              secureMessagingClass,
              "unwrapCommand",
              byte[].class,
              short.class,
              short.class,
              byte[].class,
              short.class)
          .invoke(secureMessaging, protectedGetResponse, (short) 5, (short) 10, work, (short) 0);

      byte[] beforeCompletion = counter(secureMessaging);
      APDU getResponseApdu =
          capturingStreamingApdu(OpenFIPS201.INS_GP_GET_RESPONSE, protectedResponse);
      InvocationTargetException second =
          assertThrows(
              InvocationTargetException.class,
              () ->
                  processOutgoingSecure.invoke(
                      chainBuffer,
                      getResponseApdu,
                      secureMessaging,
                      new byte[448],
                      ISO7816.SW_NO_ERROR));
      assertTrue(second.getCause() instanceof ISOException);
      assertEquals(ISO7816.SW_NO_ERROR, ((ISOException) second.getCause()).getReason());

      byte[] response = protectedResponse.toByteArray();
      int rmacTag = response.length - 10;
      assertEquals((byte) 0x8E, response[rmacTag], "Final response object must be R-MAC");
      assertEquals((byte) 0x08, response[rmacTag + 1], "R-MAC is truncated to eight bytes");
      byte[] rmacInput = new byte[16 + rmacTag];
      System.arraycopy(response, 0, rmacInput, 16, rmacTag);
      byte[] expectedRmac = aesCmac(zeroSessionKey(), rmacInput);
      for (short i = 0; i < (short) 8; i++) {
        assertEquals(
            expectedRmac[i],
            response[rmacTag + 2 + i],
            "Protected GET RESPONSE must resume the original response CMAC state");
      }
      assertArrayEquals(
          expectedRmac,
          (byte[]) field(secureMessaging, "responseMcv").get(secureMessaging),
          "Command IV scratch must not overwrite the response MAC chaining value");

      byte[] expectedCounter = beforeCompletion.clone();
      expectedCounter[15]++;
      assertArrayEquals(
          expectedCounter,
          counter(secureMessaging),
          "Protected GET RESPONSE must not replace the original logical command for counter rules");
    }
  }

  /**
   * Verifies that a protected GET RESPONSE command drains the secure outgoing response chain.
   *
   * <p>Aligned with NIST SP 800-73-5 Part 2, Section 4.2.4 and 4.2.6.
   */
  @Test
  void protectedGetResponseDrainsSecureOutgoingChain() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT before protected GET RESPONSE");

    Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
    Field pivField = realApplet.getClass().getDeclaredField("piv");
    pivField.setAccessible(true);

    Class<?> pivClass = pivField.getType();
    Object piv = Mockito.mock(pivClass);
    Method isSecureMessagingCla = method(pivClass, "isSecureMessagingCLA", byte.class);
    Method isSecureMessagingEstablished = method(pivClass, "isSecureMessagingEstablished");
    Method unwrapSecureMessagingCommand =
        method(pivClass, "unwrapSecureMessagingCommand", byte[].class, short.class, short.class);
    Method processOutgoing = method(pivClass, "processOutgoing", APDU.class);
    final boolean[] outgoingCalled = new boolean[] {false};

    when((Boolean) isSecureMessagingCla.invoke(piv, Mockito.anyByte())).thenReturn(true);
    when((Boolean) isSecureMessagingEstablished.invoke(piv)).thenReturn(true);
    when((Short)
            unwrapSecureMessagingCommand.invoke(
                piv, Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyShort()))
        .thenReturn((short) 0);
    doAnswer(
            invocation -> {
              outgoingCalled[0] = true;
              throw new ISOException(ISO7816.SW_NO_ERROR);
            })
        .when(piv);
    processOutgoing.invoke(piv, Mockito.any(APDU.class));

    pivField.set(realApplet, piv);

    ResponseAPDU response = transmit(new CommandAPDU(0x0C, 0xC0, 0x00, 0x00, 0));

    assertSw(0x9000, response, "Protected GET RESPONSE should be dispatched as secure outgoing");
    assertTrue(
        outgoingCalled[0],
        "Protected GET RESPONSE should continue through PIV outgoing dispatch, not wrap 6D00");
  }

  /**
   * Verifies that a plain GET RESPONSE command sent after an SM command returns a secure wrapped
   * response.
   *
   * <p>Aligned with NIST SP 800-73-5 Part 2, Section 4.2.6 (Response with PIV Secure Messaging).
   */
  @Test
  void plainGetResponseAfterSecureResponseStaysSecureWrapped() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT before plain secure-continuation GET RESPONSE");

    Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
    Field pivField = realApplet.getClass().getDeclaredField("piv");
    pivField.setAccessible(true);

    Class<?> pivClass = pivField.getType();
    Object piv = Mockito.mock(pivClass);
    Method isSecureMessagingCla = method(pivClass, "isSecureMessagingCLA", byte.class);
    Method processOutgoing = method(pivClass, "processOutgoing", APDU.class);
    final boolean[] outgoingCalled = new boolean[] {false};

    when((Boolean) isSecureMessagingCla.invoke(piv, Mockito.anyByte())).thenReturn(false);
    doAnswer(
            invocation -> {
              outgoingCalled[0] = true;
              throw new ISOException(ISO7816.SW_NO_ERROR);
            })
        .when(piv);
    processOutgoing.invoke(piv, Mockito.any(APDU.class));

    pivField.set(realApplet, piv);

    ResponseAPDU response = transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00, 0));

    assertSw(0x9000, response, "Plain GET RESPONSE should still return a wrapped response");
    assertTrue(
        outgoingCalled[0],
        "Plain GET RESPONSE after an SM response should continue through PIV outgoing dispatch");
  }

  /**
   * An extended Ne larger than the response work buffer yields one full buffer and '61 00' instead
   * of overrunning it (SP 800-73-5 Part 2 Section 4.2.6 response chaining).
   */
  @Test
  void extendedLeLargerThanResponseBufferIsClampedToTheBuffer() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet applet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(applet, "piv").get(applet);
      Object sm = field(piv, "secureMessaging").get(piv);
      Object chainBuffer = field(piv, "chainBuffer").get(piv);
      establishSyntheticSession(sm);
      byte[] outgoing = new byte[700];
      method(
              chainBuffer.getClass(),
              "setOutgoing",
              byte[].class,
              short.class,
              short.class,
              boolean.class)
          .invoke(chainBuffer, outgoing, (short) 0, (short) outgoing.length, false);
      ((byte[]) field(piv, "secureMessagingCommand").get(piv))[0] = (byte) 1;
      ByteArrayOutputStream sent = new ByteArrayOutputStream();
      APDU apdu = capturingStreamingApdu(OpenFIPS201.INS_PIV_GET_DATA, (short) 32767, sent);

      InvocationTargetException chunk =
          assertThrows(
              InvocationTargetException.class,
              () ->
                  method(piv.getClass(), "processOutgoingSecure", APDU.class, short.class)
                      .invoke(piv, apdu, ISO7816.SW_NO_ERROR));
      assertTrue(
          chunk.getCause() instanceof ISOException, "unexpected " + chunk.getCause().toString());
      assertEquals(
          ISO7816.SW_BYTES_REMAINING_00, ((ISOException) chunk.getCause()).getReason(), "SW");
      assertEquals(PIV.LENGTH_SM_RESPONSE, sent.size(), "one full response buffer");
      assertEquals(true, method(sm.getClass(), "isEstablished").invoke(sm));
    }
  }

  /**
   * SP 800-73-5 Part 2 Section 4.3 zeroizes the session keys when "an error occurs in secure
   * messaging"; footnote 25 makes any status other than '61 XX' or '90 00' such an error, including
   * a runtime fault while building the protected response.
   */
  @Test
  void runtimeFaultWhileWrappingResponseDestroysSession() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet applet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(applet, "piv").get(applet);
      Object sm = field(piv, "secureMessaging").get(piv);
      establishSyntheticSession(sm);
      seedWorkBuffers(piv);
      ((byte[]) field(piv, "secureMessagingCommand").get(piv))[0] = (byte) 1;
      Class<?> cryptoClass = piv.getClass().getClassLoader().loadClass(PIVCrypto.class.getName());
      Method update =
          method(cryptoClass, "doAesResponseCmacUpdate", byte[].class, short.class, short.class);
      try (org.mockito.MockedStatic<?> crypto =
          Mockito.mockStatic(cryptoClass, Mockito.CALLS_REAL_METHODS)) {
        crypto
            .when(
                () ->
                    update.invoke(
                        null, Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyShort()))
            .thenThrow(new ArrayIndexOutOfBoundsException("injected"));
        InvocationTargetException failure =
            assertThrows(
                InvocationTargetException.class,
                () ->
                    method(piv.getClass(), "processOutgoingSecure", APDU.class, short.class)
                        .invoke(
                            piv, streamingApdu(OpenFIPS201.INS_PIV_GET_DATA), ISO7816.SW_NO_ERROR));
        assertTrue(failure.getCause() instanceof ArrayIndexOutOfBoundsException);
      }
      assertSessionDestroyed(piv, sm);
    }
  }

  /**
   * A protected GET RESPONSE retrieves the next part of a pending protected data response (SP
   * 800-73-5 Part 2 Section 4.2.6) instead of failing in command reassembly.
   */
  @Test
  void protectedGetResponseDrainsPendingSecureDataResponse() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT PIV");
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet applet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(applet, "piv").get(applet);
      Object sm = field(piv, "secureMessaging").get(piv);
      Object chainBuffer = field(piv, "chainBuffer").get(piv);
      establishSyntheticSession(sm);

      byte[] mcv = new byte[16];
      byte[] getData =
          chainedMacOnlySecureCommand(
              mcv,
              PIVSecureMessaging.CLA_SECURE_MESSAGING,
              OpenFIPS201.INS_PIV_GET_DATA,
              (byte) 0x3F,
              (byte) 0xFF,
              mcv);
      method(
              sm.getClass(),
              "unwrapCommand",
              byte[].class,
              short.class,
              short.class,
              byte[].class,
              short.class)
          .invoke(sm, getData, (short) 5, (short) 10, new byte[512], (short) 0);
      byte[] outgoing = new byte[300];
      java.util.Arrays.fill(outgoing, SYNTHETIC_PLAINTEXT_BYTE);
      method(
              chainBuffer.getClass(),
              "setOutgoing",
              byte[].class,
              short.class,
              short.class,
              boolean.class)
          .invoke(chainBuffer, outgoing, (short) 0, (short) outgoing.length, false);
      ((byte[]) field(piv, "secureMessagingCommand").get(piv))[0] = (byte) 1;
      ByteArrayOutputStream sent = new ByteArrayOutputStream();
      InvocationTargetException first =
          assertThrows(
              InvocationTargetException.class,
              () ->
                  method(piv.getClass(), "processOutgoingSecure", APDU.class, short.class)
                      .invoke(
                          piv,
                          capturingStreamingApdu(OpenFIPS201.INS_PIV_GET_DATA, (short) 256, sent),
                          ISO7816.SW_NO_ERROR));
      assertEquals(
          (short) 0x6100,
          (short) (((ISOException) first.getCause()).getReason() & (short) 0xFF00),
          "first chunk leaves the protected response pending");

      ResponseAPDU second =
          transmit(
              new CommandAPDU(
                  chainedMacOnlySecureCommand(
                      mcv,
                      PIVSecureMessaging.CLA_SECURE_MESSAGING,
                      OpenFIPS201.INS_GP_GET_RESPONSE,
                      (byte) 0x00,
                      (byte) 0x00,
                      mcv)));
      assertSw(0x9000, second, "protected GET RESPONSE completes the pending response");
      byte[] tail = second.getData();
      assertEquals(323 - 256, tail.length, "remaining wrapped response octets");
      assertArrayEquals(
          hex("990290008E08"),
          java.util.Arrays.copyOfRange(tail, tail.length - 14, tail.length - 8),
          "status template and R-MAC close the response");
      assertEquals(true, method(sm.getClass(), "isEstablished").invoke(sm));
    }
  }

  /**
   * A protected GET RESPONSE continues only a response started under PIV secure messaging. A
   * pending plaintext response cannot be reassembled as a protected command, so the exchange fails
   * as incorrect secure messaging data: SP 800-73-5 Part 2 Section 4.2.7 returns '69 88' "without
   * performing further secure messaging" and the session keys are destroyed.
   */
  @Test
  void protectedGetResponseDoesNotContinueAPlaintextResponse() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT PIV");
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet applet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(applet, "piv").get(applet);
      Object sm = field(piv, "secureMessaging").get(piv);
      Object chainBuffer = field(piv, "chainBuffer").get(piv);
      establishSyntheticSession(sm);

      byte[] outgoing = new byte[300];
      java.util.Arrays.fill(outgoing, SYNTHETIC_PLAINTEXT_BYTE);
      method(
              chainBuffer.getClass(),
              "setOutgoing",
              byte[].class,
              short.class,
              short.class,
              boolean.class)
          .invoke(chainBuffer, outgoing, (short) 0, (short) outgoing.length, false);
      InvocationTargetException first =
          assertThrows(
              InvocationTargetException.class,
              () ->
                  method(chainBuffer.getClass(), "processOutgoing", APDU.class, byte.class)
                      .invoke(
                          chainBuffer,
                          capturingStreamingApdu(
                              OpenFIPS201.INS_PIV_GET_DATA,
                              (short) 256,
                              new ByteArrayOutputStream()),
                          ChainBuffer.PROTECTION_PLAIN));
      assertEquals(
          (short) 0x6100,
          (short) (((ISOException) first.getCause()).getReason() & (short) 0xFF00),
          "the plaintext response is pending");

      byte[] mcv = new byte[16];
      ResponseAPDU protectedGetResponse =
          transmit(
              new CommandAPDU(
                  chainedMacOnlySecureCommand(
                      mcv,
                      PIVSecureMessaging.CLA_SECURE_MESSAGING,
                      OpenFIPS201.INS_GP_GET_RESPONSE,
                      (byte) 0x00,
                      (byte) 0x00,
                      mcv)));
      assertSw(0x6988, protectedGetResponse, "protected GET RESPONSE on a plaintext response");
      assertEquals(false, method(sm.getClass(), "isEstablished").invoke(sm));
      assertSw(
          0x6985,
          transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00, 0)),
          "the mismatched GET RESPONSE abandons the plaintext response");
    }
  }

  /**
   * A GP SCP-protected GET RESPONSE must not release a pending PIV secure messaging response
   * outside secure messaging; the protected response is abandoned with '69 85'.
   */
  @Test
  void globalPlatformGetResponseDoesNotReleaseAProtectedResponse() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT PIV");
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet applet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(applet, "piv").get(applet);
      Object sm = field(piv, "secureMessaging").get(piv);
      Object chainBuffer = field(piv, "chainBuffer").get(piv);
      establishSyntheticSession(sm);

      byte[] mcv = new byte[16];
      byte[] getData =
          chainedMacOnlySecureCommand(
              mcv,
              PIVSecureMessaging.CLA_SECURE_MESSAGING,
              OpenFIPS201.INS_PIV_GET_DATA,
              (byte) 0x3F,
              (byte) 0xFF,
              mcv);
      method(
              sm.getClass(),
              "unwrapCommand",
              byte[].class,
              short.class,
              short.class,
              byte[].class,
              short.class)
          .invoke(sm, getData, (short) 5, (short) 10, new byte[512], (short) 0);
      byte[] outgoing = new byte[300];
      java.util.Arrays.fill(outgoing, SYNTHETIC_PLAINTEXT_BYTE);
      method(
              chainBuffer.getClass(),
              "setOutgoing",
              byte[].class,
              short.class,
              short.class,
              boolean.class)
          .invoke(chainBuffer, outgoing, (short) 0, (short) outgoing.length, false);
      ((byte[]) field(piv, "secureMessagingCommand").get(piv))[0] = (byte) 1;
      InvocationTargetException first =
          assertThrows(
              InvocationTargetException.class,
              () ->
                  method(piv.getClass(), "processOutgoingSecure", APDU.class, short.class)
                      .invoke(
                          piv,
                          capturingStreamingApdu(
                              OpenFIPS201.INS_PIV_GET_DATA,
                              (short) 256,
                              new ByteArrayOutputStream()),
                          ISO7816.SW_NO_ERROR));
      assertEquals(
          (short) 0x6100,
          (short) (((ISOException) first.getCause()).getReason() & (short) 0xFF00),
          "first chunk leaves the protected response pending");

      try (org.mockito.MockedStatic<org.globalplatform.GPSystem> gp =
          Mockito.mockStatic(org.globalplatform.GPSystem.class)) {
        org.globalplatform.SecureChannel channel =
            Mockito.mock(org.globalplatform.SecureChannel.class);
        when(channel.getSecurityLevel())
            .thenReturn(
                (byte)
                    (org.globalplatform.SecureChannel.AUTHENTICATED
                        | org.globalplatform.SecureChannel.C_DECRYPTION
                        | org.globalplatform.SecureChannel.C_MAC));
        when(channel.unwrap(Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyShort()))
            .thenAnswer(invocation -> (short) invocation.getArgument(2));
        gp.when(org.globalplatform.GPSystem::getSecureChannel).thenReturn(channel);

        ResponseAPDU scpGetResponse = transmit(new CommandAPDU(0x84, 0xC0, 0x00, 0x00, 0));
        assertSw(0x6985, scpGetResponse, "GP SCP GET RESPONSE on a protected response");
        assertEquals(0, scpGetResponse.getData().length, "no response data is released");
      }
      assertEquals(
          false,
          method(piv.getClass(), "isSecureMessagingResponseActive").invoke(piv),
          "the protected response is abandoned");
    }
  }

  /**
   * A command sent with the PIV secure messaging class that is rejected before unwrap still fails
   * with a status other than '61 XX' or '90 00', which is an error in secure messaging (SP 800-73-5
   * Part 2 Section 4.3, footnote 25); card and host both zeroize the session keys.
   */
  @Test
  void secureMessagingClassOnGlobalPlatformInstructionDestroysSession() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT PIV");
    Applet applet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
    Object piv = field(applet, "piv").get(applet);
    Object sm = field(piv, "secureMessaging").get(piv);
    for (byte ins : new byte[] {(byte) 0x50, (byte) 0x82}) {
      try (AutoCloseable ignored = enterEngineContext()) {
        establishSyntheticSession(sm);
      }
      assertSw(
          ISO7816.SW_CLA_NOT_SUPPORTED,
          transmit(
              new CommandAPDU(
                  macOnlySecureCommand(
                      PIVSecureMessaging.CLA_SECURE_MESSAGING, ins, (byte) 0, (byte) 0))),
          "GP instruction with the PIV SM class");
      assertEquals(false, method(sm.getClass(), "isEstablished").invoke(sm), "session destroyed");
    }
  }

  /**
   * SP 800-73-5 Part 2 Section 4.2.7: a protected command that cannot be reassembled is reported
   * with an SM processing status, here '69 88', "without performing further secure messaging".
   */
  @Test
  void protectedChainLargerThanTheCommandBufferReturnsSmStatus() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT PIV");
    Applet applet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
    Object piv = field(applet, "piv").get(applet);
    Object sm = field(piv, "secureMessaging").get(piv);
    try (AutoCloseable ignored = enterEngineContext()) {
      establishSyntheticSession(sm);
    }
    byte[] complete = new byte[5 + 750];
    complete[ISO7816.OFFSET_INS] = OpenFIPS201.INS_PIV_GET_DATA;
    complete[ISO7816.OFFSET_P1] = (byte) 0x3F;
    complete[ISO7816.OFFSET_P2] = (byte) 0xFF;
    assertSw(
        0x9000,
        transmit(new CommandAPDU(commandFragment(complete, 5, 250, false))),
        "first protected frame");
    assertSw(
        PIVSecureMessaging.SW_SM_OBJECTS_INCORRECT,
        transmit(new CommandAPDU(commandFragment(complete, 255, 250, false))),
        "overflowing protected frame");
    assertEquals(false, method(sm.getClass(), "isEstablished").invoke(sm), "session destroyed");
  }

  /**
   * Every malformed protected data object in a single protected APDU returns its SP 800-73-5 Part 2
   * Section 4.2.7 status ('69 87' for a missing C-MAC, otherwise '69 88') and destroys the session
   * (Section 4.3).
   */
  @Test
  void malformedSmObjectsAreRejectedAndDestroySession() throws Exception {
    String block = "00112233445566778899AABBCCDDEEFF";
    String mac = "8E080102030405060708";
    String[][] rows = {
      {"duplicate 87", "871101" + block + "871101" + block + mac, "6988"},
      {"87 shorter than 17", "871001" + block.substring(2) + mac, "6988"},
      {"cryptogram not a block multiple", "871201" + block + "00" + mac, "6988"},
      {"87 without padding indicator", "871102" + block + mac, "6988"},
      {"97 value not 00", "970101" + mac, "6988"},
      {"97 length not 1", "97020000" + mac, "6988"},
      {"duplicate 8E", mac + mac, "6988"},
      {"8E not 8 octets", "8E0401020304", "6988"},
      {"8E not last", mac + "970100", "6988"},
      {"unknown tag", "85020000" + mac, "6988"},
      {"87 after 97", "970100" + "871101" + block + mac, "6988"},
      {"missing 8E", "970100", "6987"},
      {"no objects", "", "6987"},
    };
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet applet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(applet, "piv").get(applet);
      Object sm = field(piv, "secureMessaging").get(piv);
      for (String[] row : rows) {
        establishSyntheticSession(sm);
        seedWorkBuffers(piv);
        byte[] body = hex(row[1]);
        byte[] command = new byte[5 + body.length];
        command[ISO7816.OFFSET_CLA] = PIVSecureMessaging.CLA_SECURE_MESSAGING;
        command[ISO7816.OFFSET_INS] = OpenFIPS201.INS_PIV_GET_DATA;
        command[ISO7816.OFFSET_P1] = (byte) 0x3F;
        command[ISO7816.OFFSET_P2] = (byte) 0xFF;
        System.arraycopy(body, 0, command, 5, body.length);
        ISOException failure =
            assertThrows(
                ISOException.class, () -> unwrapProtected(piv, command, (short) body.length));
        assertEquals(
            (short) Integer.parseInt(row[2], 16), failure.getReason(), row[0] + ": status word");
        assertSessionDestroyed(piv, sm);
      }
    }
  }

  /**
   * The bounded parser for a rejected contactless PUT DATA chain applies the same Section 4.2.7
   * rules to every protected data object after the cryptogram, and to the decrypted padding.
   */
  @Test
  void malformedSmObjectsInRejectedCommandStreamDestroySession() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT PIV");
    Applet applet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
    Object piv = field(applet, "piv").get(applet);
    Object sm = field(piv, "secureMessaging").get(piv);

    byte[] valid = authenticatedEncryptedDataCommand(new byte[600]);
    int macOffset = valid.length - 10;
    byte[] withoutMac = java.util.Arrays.copyOf(valid, macOffset);
    byte[] unknownTag = valid.clone();
    unknownTag[macOffset] = (byte) 0x85;
    byte[] trailing = java.util.Arrays.copyOf(valid, valid.length + 1);
    byte[] badLe = new byte[valid.length + 3];
    System.arraycopy(valid, 0, badLe, 0, macOffset);
    System.arraycopy(hex("970101"), 0, badLe, macOffset, 3);
    System.arraycopy(valid, macOffset, badLe, macOffset + 3, 10);
    byte[] badPadding = authenticatedPaddedDataCommand(new byte[608]);
    Object[][] rows = {
      {"missing 8E", withoutMac, 0x6987},
      {"unknown tag after cryptogram", unknownTag, 0x6988},
      {"data after 8E", trailing, 0x6988},
      {"97 value not 00", badLe, 0x6988},
      {"no padding delimiter", badPadding, 0x6988},
    };
    for (Object[] row : rows) {
      byte[] command = (byte[]) row[1];
      try (AutoCloseable ignored = enterEngineContext()) {
        establishSyntheticSession(sm);
        method(piv.getClass(), "setIsContactless", boolean.class).invoke(piv, true);
      }
      int bodyLength = command.length - 5;
      assertSw(
          0x9000,
          transmit(new CommandAPDU(commandFragment(command, 5, 220, false))),
          row[0] + ": first frame");
      assertSw(
          0x9000,
          transmit(new CommandAPDU(commandFragment(command, 225, 220, false))),
          row[0] + ": second frame");
      assertSw(
          (Integer) row[2],
          transmit(new CommandAPDU(commandFragment(command, 445, bodyLength - 440, true))),
          row[0] + ": final frame");
      assertEquals(
          false, method(sm.getClass(), "isEstablished").invoke(sm), row[0] + ": session destroyed");
    }
  }

  /**
   * SP 800-73-5 Part 2 Section 3.1.1 leaves "all security status indicators" unchanged on PIV
   * reselection, and JCRE 3.0.5 Section 5.1 clears CLEAR_ON_DESELECT objects even when the SELECT
   * "Reselects the same applet". The session, the 9B authentication and PIN-Always therefore live
   * in CLEAR_ON_RESET memory.
   */
  @Test
  void securityStatusIndicatorsSurviveReselectionMemoryClearing() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet applet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(applet, "piv").get(applet);
      Object sm = field(piv, "secureMessaging").get(piv);
      Object csp = field(piv, "cspPIV").get(piv);
      for (String name :
          new String[] {"state", "commandMcv", "responseMcv", "encCounter", "responseState"}) {
        assertEquals(
            javacard.framework.JCSystem.CLEAR_ON_RESET,
            javacard.framework.JCSystem.isTransient(field(sm, name).get(sm)),
            name);
      }
      assertEquals(
          javacard.framework.JCSystem.CLEAR_ON_RESET,
          javacard.framework.JCSystem.isTransient(field(csp, "transientState").get(csp)),
          "security status flags");
      for (String keyName : new String[] {"skCfrm", "skMac", "skEnc", "skRmac"}) {
        assertEquals(
            javacard.security.KeyBuilder.TYPE_AES_TRANSIENT_RESET,
            ((AESKey) field(sm, keyName).get(sm)).getType(),
            keyName);
      }
    }
  }

  /** A genuine deselect sets every PIV security status indicator to FALSE (Section 3.1.1). */
  @Test
  void genuineDeselectClearsSessionAuthenticationAndPinAlways() throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT PIV");
    Applet applet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
    Object piv = field(applet, "piv").get(applet);
    Object sm = field(piv, "secureMessaging").get(piv);
    Object csp = field(piv, "cspPIV").get(piv);
    try (AutoCloseable ignored = enterEngineContext()) {
      establishSyntheticSession(sm);
      method(csp.getClass(), "setAuthenticatedKey", byte.class).invoke(csp, (byte) 0x9B);
      method(csp.getClass(), "markPINAlways").invoke(csp);
      method(piv.getClass(), "deselect").invoke(piv);
      assertEquals(false, method(sm.getClass(), "isEstablished").invoke(sm), "SM status");
      for (String keyName : new String[] {"skCfrm", "skMac", "skEnc", "skRmac"}) {
        assertTrue(!((AESKey) field(sm, keyName).get(sm)).isInitialized(), keyName);
      }
      byte[] flags = (byte[]) field(csp, "transientState").get(csp);
      assertEquals(
          0, flags[staticField(csp.getClass(), "STATE_PIN_ALWAYS").getShort(null)], "PIN-Always");
      assertEquals(
          0,
          flags[staticField(csp.getClass(), "STATE_AUTH_KEY").getShort(null)],
          "authenticated key");
    }
  }

  private ResponseAPDU transmit(CommandAPDU command) {
    return new ResponseAPDU(session.transceive(command.getBytes()));
  }

  private static APDU streamingApdu(byte ins) {
    return streamingApdu(ins, (short) 256);
  }

  private static APDU streamingApdu(byte ins, short le) {
    byte[] apduBuffer = new byte[5];
    apduBuffer[ISO7816.OFFSET_INS] = ins;
    APDU apdu = Mockito.mock(APDU.class);
    when(apdu.getBuffer()).thenReturn(apduBuffer);
    when(apdu.setOutgoing()).thenReturn(le);
    return apdu;
  }

  private static APDU capturingStreamingApdu(byte ins, ByteArrayOutputStream sent) {
    return capturingStreamingApdu(ins, (short) 256, sent);
  }

  private static APDU capturingStreamingApdu(byte ins, short le, ByteArrayOutputStream sent) {
    APDU apdu = streamingApdu(ins, le);
    doAnswer(
            invocation -> {
              byte[] source = invocation.getArgument(0);
              short offset = invocation.getArgument(1);
              short length = invocation.getArgument(2);
              sent.write(source, offset, length);
              return null;
            })
        .when(apdu)
        .sendBytesLong(Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyShort());
    return apdu;
  }

  private static short buildMacOnlyCommandInput(byte[] command, byte[] out) {
    short cursor = 0;
    for (short i = 0; i < 16; i++) {
      out[cursor++] = 0;
    }
    out[cursor++] = PIVSecureMessaging.CLA_SECURE_MESSAGING;
    out[cursor++] = command[ISO7816.OFFSET_INS];
    out[cursor++] = command[ISO7816.OFFSET_P1];
    out[cursor++] = command[ISO7816.OFFSET_P2];
    out[cursor++] = (byte) 0x80;
    for (short i = 0; i < 11; i++) {
      out[cursor++] = 0;
    }
    return cursor;
  }

  private static byte[] macOnlySecureCommand(byte cla, byte ins, byte p1, byte p2) {
    return chainedMacOnlySecureCommand(new byte[16], cla, ins, p1, p2, new byte[16]);
  }

  private static byte[] largeAuthenticatedEncryptedDataCommand() {
    short encryptedValueLength = (short) 289; // 0x01 padding indicator + 288 ciphertext bytes.
    short encryptedTlvLength = (short) (4 + encryptedValueLength);
    byte[] command = new byte[5 + encryptedTlvLength + 10];
    command[ISO7816.OFFSET_CLA] = PIVSecureMessaging.CLA_SECURE_MESSAGING;
    command[ISO7816.OFFSET_INS] = (byte) 0xCB;
    command[ISO7816.OFFSET_P1] = (byte) 0x3F;
    command[ISO7816.OFFSET_P2] = (byte) 0xFF;
    command[ISO7816.OFFSET_LC] = (byte) (command.length - ISO7816.OFFSET_CDATA);

    short cursor = 5;
    command[cursor++] = (byte) 0x87;
    command[cursor++] = (byte) 0x82;
    command[cursor++] = (byte) (encryptedValueLength >> 8);
    command[cursor++] = (byte) encryptedValueLength;
    command[cursor++] = (byte) 0x01;
    cursor = (short) (cursor + 288);
    command[cursor++] = (byte) 0x8E;
    command[cursor++] = (byte) 0x08;

    byte[] macInput = new byte[16 + 16 + encryptedTlvLength];
    short macCursor = 16;
    macInput[macCursor++] = PIVSecureMessaging.CLA_SECURE_MESSAGING;
    macInput[macCursor++] = command[ISO7816.OFFSET_INS];
    macInput[macCursor++] = command[ISO7816.OFFSET_P1];
    macInput[macCursor++] = command[ISO7816.OFFSET_P2];
    macInput[macCursor++] = (byte) 0x80;
    macCursor = (short) (macCursor + 11);
    System.arraycopy(command, 5, macInput, macCursor, encryptedTlvLength);
    macCursor = (short) (macCursor + encryptedTlvLength);

    byte[] mac = new byte[16];
    org.bouncycastle.crypto.macs.CMac cmac =
        new org.bouncycastle.crypto.macs.CMac(
            org.bouncycastle.crypto.engines.AESEngine.newInstance());
    cmac.init(new org.bouncycastle.crypto.params.KeyParameter(zeroSessionKey()));
    cmac.update(macInput, 0, macCursor);
    cmac.doFinal(mac, 0);
    System.arraycopy(mac, 0, command, cursor, 8);
    return command;
  }

  private static byte[] authenticatedEncryptedDataCommand(byte[] plaintext) throws Exception {
    return authenticatedPaddedDataCommand(iso7816Padded(plaintext));
  }

  private static byte[] authenticatedPaddedDataCommand(byte[] paddedPlaintext) throws Exception {
    byte[] counter = new byte[16];
    counter[15] = (byte) 1;
    byte[] iv = aesEcb(zeroSessionKey(), counter);
    byte[] ciphertext = aesCbcEncrypt(zeroSessionKey(), iv, paddedPlaintext);
    short encryptedValueLength = (short) (1 + ciphertext.length);
    short lengthFieldSize =
        encryptedValueLength < (short) 0x80
            ? (short) 1
            : (encryptedValueLength <= (short) 0x00FF ? (short) 2 : (short) 3);
    byte[] command = new byte[5 + 1 + lengthFieldSize + encryptedValueLength + 10];
    command[ISO7816.OFFSET_CLA] = PIVSecureMessaging.CLA_SECURE_MESSAGING;
    command[ISO7816.OFFSET_INS] = (byte) 0xDB;
    command[ISO7816.OFFSET_P1] = (byte) 0x3F;
    command[ISO7816.OFFSET_P2] = (byte) 0xFF;
    command[ISO7816.OFFSET_LC] = (byte) (command.length - ISO7816.OFFSET_CDATA);

    short cursor = 5;
    command[cursor++] = (byte) 0x87;
    if (lengthFieldSize == (short) 1) {
      command[cursor++] = (byte) encryptedValueLength;
    } else if (lengthFieldSize == (short) 2) {
      command[cursor++] = (byte) 0x81;
      command[cursor++] = (byte) encryptedValueLength;
    } else {
      command[cursor++] = (byte) 0x82;
      command[cursor++] = (byte) (encryptedValueLength >> 8);
      command[cursor++] = (byte) encryptedValueLength;
    }
    command[cursor++] = (byte) 0x01;
    System.arraycopy(ciphertext, 0, command, cursor, ciphertext.length);
    cursor = (short) (cursor + ciphertext.length);
    command[cursor++] = (byte) 0x8E;
    command[cursor++] = (byte) 0x08;

    byte[] mac = commandMac(command, (short) 5, (short) (cursor - 2));
    System.arraycopy(mac, 0, command, cursor, 8);
    return command;
  }

  /**
   * Builds one APDU fragment from a complete protected command body.
   *
   * <p>Every fragment keeps INS, P1, and P2 unchanged. The CLA chaining bit is set until the final
   * fragment so the fixture exercises one logical command rather than independent commands.
   *
   * @param complete complete protected APDU
   * @param bodyOffset first body octet to copy
   * @param bodyLength number of body octets to copy
   * @param finalFrame {@code true} for the last fragment
   * @return short-length command APDU for the requested fragment
   */
  private static byte[] commandFragment(
      byte[] complete, int bodyOffset, int bodyLength, boolean finalFrame) {
    if (bodyLength > OpenFIPS201.MAX_SHORT_APDU_DATA_LENGTH) {
      throw new IllegalArgumentException("A short command APDU frame cannot exceed 255 bytes");
    }
    byte[] fragment = new byte[5 + bodyLength];
    fragment[ISO7816.OFFSET_CLA] =
        finalFrame
            ? PIVSecureMessaging.CLA_SECURE_MESSAGING
            : PIVSecureMessaging.CLA_CHAINED_SECURE_MESSAGING;
    fragment[ISO7816.OFFSET_INS] = complete[ISO7816.OFFSET_INS];
    fragment[ISO7816.OFFSET_P1] = complete[ISO7816.OFFSET_P1];
    fragment[ISO7816.OFFSET_P2] = complete[ISO7816.OFFSET_P2];
    fragment[ISO7816.OFFSET_LC] = (byte) bodyLength;
    System.arraycopy(complete, bodyOffset, fragment, 5, bodyLength);
    return fragment;
  }

  private static byte[] iso7816Padded(byte[] plaintext) {
    int paddedLength = plaintext.length + (16 - (plaintext.length % 16));
    byte[] padded = new byte[paddedLength];
    System.arraycopy(plaintext, 0, padded, 0, plaintext.length);
    padded[plaintext.length] = (byte) 0x80;
    return padded;
  }

  private static byte[] aesEcb(byte[] key, byte[] block) throws Exception {
    javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding");
    cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(key, "AES"));
    return cipher.doFinal(block);
  }

  private static byte[] aesCbcEncrypt(byte[] key, byte[] iv, byte[] plaintext) throws Exception {
    javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/NoPadding");
    cipher.init(
        javax.crypto.Cipher.ENCRYPT_MODE,
        new javax.crypto.spec.SecretKeySpec(key, "AES"),
        new javax.crypto.spec.IvParameterSpec(iv));
    return cipher.doFinal(plaintext);
  }

  private static byte[] aesCmac(byte[] key, byte[] input) {
    byte[] mac = new byte[16];
    org.bouncycastle.crypto.macs.CMac cmac =
        new org.bouncycastle.crypto.macs.CMac(
            org.bouncycastle.crypto.engines.AESEngine.newInstance());
    cmac.init(new org.bouncycastle.crypto.params.KeyParameter(key));
    cmac.update(input, 0, input.length);
    cmac.doFinal(mac, 0);
    return mac;
  }

  private static byte[] commandMac(byte[] command, short bodyOffset, short bodyEnd) {
    byte[] macInput = new byte[16 + 16 + bodyEnd - bodyOffset];
    short cursor = 16;
    macInput[cursor++] = PIVSecureMessaging.CLA_SECURE_MESSAGING;
    macInput[cursor++] = command[ISO7816.OFFSET_INS];
    macInput[cursor++] = command[ISO7816.OFFSET_P1];
    macInput[cursor++] = command[ISO7816.OFFSET_P2];
    macInput[cursor++] = (byte) 0x80;
    cursor = (short) (cursor + 11);
    System.arraycopy(command, bodyOffset, macInput, cursor, bodyEnd - bodyOffset);
    cursor = (short) (cursor + bodyEnd - bodyOffset);

    byte[] mac = new byte[16];
    org.bouncycastle.crypto.macs.CMac cmac =
        new org.bouncycastle.crypto.macs.CMac(
            org.bouncycastle.crypto.engines.AESEngine.newInstance());
    cmac.init(new org.bouncycastle.crypto.params.KeyParameter(zeroSessionKey()));
    cmac.update(macInput, 0, cursor);
    cmac.doFinal(mac, 0);
    return mac;
  }

  /**
   * Builds a MAC-only secure messaging command whose C-MAC chains from the given MCV, writing the
   * full 16-byte C-MAC (the next MCV per NIST SP 800-73-5 Part 2 Section 4.2.3) into {@code
   * nextMcv}. The same array may be passed for {@code mcv} and {@code nextMcv}.
   */
  private static byte[] chainedMacOnlySecureCommand(
      byte[] mcv, byte cla, byte ins, byte p1, byte p2, byte[] nextMcv) {
    byte[] command = new byte[15];
    command[ISO7816.OFFSET_CLA] = cla;
    command[ISO7816.OFFSET_INS] = ins;
    command[ISO7816.OFFSET_P1] = p1;
    command[ISO7816.OFFSET_P2] = p2;
    command[ISO7816.OFFSET_LC] = (byte) 0x0A;
    command[5] = (byte) 0x8E;
    command[6] = (byte) 0x08;

    // C-MAC input per Part 2 Section 4.2.3: MCV || padded header || command data objects
    // preceding the '8E' (none for a MAC-only command).
    byte[] macInput = new byte[64];
    short cursor = 0;
    System.arraycopy(mcv, 0, macInput, 0, 16);
    cursor = 16;
    macInput[cursor++] = PIVSecureMessaging.CLA_SECURE_MESSAGING;
    macInput[cursor++] = ins;
    macInput[cursor++] = p1;
    macInput[cursor++] = p2;
    macInput[cursor++] = (byte) 0x80;
    cursor += 11;

    // AES-CMAC (NIST SP 800-38B) over the MAC input with the zero session MAC key used by these
    // tests. Computed host-side with BouncyCastle so command construction does not require a
    // simulator engine context.
    byte[] mac = new byte[16];
    org.bouncycastle.crypto.macs.CMac cmac =
        new org.bouncycastle.crypto.macs.CMac(
            org.bouncycastle.crypto.engines.AESEngine.newInstance());
    cmac.init(new org.bouncycastle.crypto.params.KeyParameter(zeroSessionKey()));
    cmac.update(macInput, 0, cursor);
    cmac.doFinal(mac, 0);
    System.arraycopy(mac, 0, command, 7, 8);
    System.arraycopy(mac, 0, nextMcv, 0, 16);
    return command;
  }

  /**
   * Asserts that a wrapped response encapsulates the expected application status in its '99' status
   * template (NIST SP 800-73-5 Part 2 Section 4.2.6).
   */
  private static void assertEncapsulatedStatus(
      short expectedSw, ResponseAPDU response, String context) {
    byte[] data = response.getData();
    assertTrue(data.length >= 4, context + ": response should carry a '99' status template");
    assertEquals((byte) 0x99, data[0], context + ": '99' status template tag");
    assertEquals((byte) 0x02, data[1], context + ": '99' status template length");
    short encapsulated = (short) (((data[2] & 0xFF) << 8) | (data[3] & 0xFF));
    assertEquals(expectedSw, encapsulated, context + ": encapsulated application status");
  }

  private static Field field(Object target, String name) throws Exception {
    Field field = target.getClass().getDeclaredField(name);
    field.setAccessible(true);
    return field;
  }

  private static short activeSessionKeyBytes() {
    return (short) (isCs2Build() ? 16 : 32);
  }

  private static short activeSessionKeyBits() {
    return (short) (activeSessionKeyBytes() * 8);
  }

  private static byte[] zeroSessionKey() {
    return new byte[activeSessionKeyBytes()];
  }

  private static byte[] zeroSessionKeys() {
    return new byte[activeSessionKeyBytes() * 4];
  }

  private static byte[] distinctSessionKeys() {
    short keyLength = activeSessionKeyBytes();
    byte[] keys = new byte[keyLength * 4];
    for (short slot = 0; slot < (short) 4; slot++) {
      for (short i = 0; i < keyLength; i++) {
        keys[(short) (slot * keyLength + i)] = (byte) (0x11 * (slot + 1));
      }
    }
    return keys;
  }

  private static Field staticField(Class<?> target, String name) throws Exception {
    Field field = target.getDeclaredField(name);
    field.setAccessible(true);
    return field;
  }

  private static Applet unwrapApplet(Applet appletProxy) throws Exception {
    for (Field proxyField : appletProxy.getClass().getDeclaredFields()) {
      if (!java.lang.reflect.InvocationHandler.class.isAssignableFrom(proxyField.getType())) {
        continue;
      }
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

  /** Returns a dynamically sized data object whose published content is {@code content}. */
  private static PIVDataObject publishedObject(byte[] content) {
    PIVDataObject object =
        new PIVDataObject(
            new byte[] {0x01}, (short) 0, (short) 1, (byte) 0, (byte) 0, (byte) 0x9B, (short) 0);
    byte[] staged = object.beginUpdate((short) content.length);
    System.arraycopy(content, 0, staged, 0, content.length);
    object.commitUpdate();
    return object;
  }

  /** Loads the suite's four session keys through the production three-argument entry point. */
  private static void loadSessionKeys(Object secureMessaging, byte[] keys) throws Exception {
    method(secureMessaging.getClass(), "setSessionKeys", byte[].class, short.class, short.class)
        .invoke(secureMessaging, keys, (short) 0, PIVOpacity.SESSION_KEY_LENGTH);
  }

  private static Method method(Class<?> target, String name, Class<?>... parameterTypes)
      throws Exception {
    Method method = target.getDeclaredMethod(name, parameterTypes);
    method.setAccessible(true);
    return method;
  }

  private AutoCloseable enterEngineContext() throws Exception {
    Method asCurrent = engine.getClass().getMethod("asCurrent");
    asCurrent.setAccessible(true);
    return (AutoCloseable) asCurrent.invoke(engine);
  }

  private static byte[] counter(Object secureMessaging) throws Exception {
    byte[] encCounter = (byte[]) field(secureMessaging, "encCounter").get(secureMessaging);
    byte[] copy = new byte[encCounter.length];
    System.arraycopy(encCounter, 0, copy, 0, encCounter.length);
    return copy;
  }

  private static void assertSw(int expectedSw, ResponseAPDU response, String context) {
    assertEquals(
        expectedSw,
        response.getSW(),
        context
            + " expected SW="
            + Integer.toHexString(expectedSw)
            + " but was "
            + String.format("0x%04X", response.getSW()));
  }

  private static byte[] hex(String value) {
    String normalized = value.replace(" ", "").replace("\n", "").replace("\t", "");
    byte[] bytes = new byte[normalized.length() / 2];
    for (int i = 0; i < normalized.length(); i += 2) {
      bytes[i / 2] =
          (byte)
              ((Character.digit(normalized.charAt(i), 16) << 4)
                  | Character.digit(normalized.charAt(i + 1), 16));
    }
    return bytes;
  }

  private static byte[] tlv(byte tag, byte[] value) {
    if (value.length > TLV.LENGTH_1BYTE_MAX) {
      throw new IllegalArgumentException("Test TLV helper supports short-form lengths only");
    }
    byte[] encoded = new byte[value.length + 2];
    encoded[0] = tag;
    encoded[1] = (byte) value.length;
    System.arraycopy(value, 0, encoded, 2, value.length);
    return encoded;
  }
}
