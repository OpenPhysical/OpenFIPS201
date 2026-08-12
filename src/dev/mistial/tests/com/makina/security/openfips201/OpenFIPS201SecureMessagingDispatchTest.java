package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

import apdu4j.core.BIBO;
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
  private static final short MAX_SAFE_SECURE_RESPONSE_PLAINTEXT = (short) 191;
  private static final byte[] OPENFIPS201_AID_BYTES = hex("A000000308000010000100");
  private static final AID OPENFIPS201_AID =
      new AID(OPENFIPS201_AID_BYTES, (short) 0, (byte) OPENFIPS201_AID_BYTES.length);

  private JavaCardEngine engine;
  private BIBO session;

  @BeforeEach
  void setUpCard() throws Exception {
    assumeTrue(isCs2Build(), "white-box SM dispatch tests use CS2 session-key fixtures");
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
  void secureOutgoingStreamsProtectedResponseAcrossPhysicalGetResponse() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(realApplet, "piv").get(realApplet);
      Object chainBuffer = field(piv, "chainBuffer").get(piv);
      Object secureMessaging = field(piv, "secureMessaging").get(piv);
      Class<?> secureMessagingClass = secureMessaging.getClass();
      method(secureMessagingClass, "setSessionKeys", byte[].class, short.class)
          .invoke(secureMessaging, new byte[64], (short) 0);
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
      when(apdu.setOutgoing()).thenReturn((short) 256);

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

      apduBuffer[ISO7816.OFFSET_INS] = (byte) 0xC0;
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
    assertSw(
        ISO7816.SW_WRONG_DATA,
        transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00, 0)),
        "GET RESPONSE must not resume the abandoned response");
  }

  @Test
  void objectChainRejectsProtectionContextChangeAndRollsBack() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      ChainBuffer chain = new ChainBuffer();
      PIVDataObject destination =
          new PIVDataObject((byte) 0x01, (byte) 0, (byte) 0, (byte) 0x9B);
      destination.allocate((short) 4);
      byte[] original = new byte[] {0x11, 0x22, 0x33, 0x44};
      System.arraycopy(original, 0, destination.content, 0, original.length);
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
      byte[] sessionKeys = new byte[64];
      method(secureMessagingClass, "setSessionKeys", byte[].class, short.class)
          .invoke(secureMessaging, sessionKeys, (short) 0);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);

      byte[] command = macOnlySecureCommand((byte) 0x0C, (byte) 0xCB, (byte) 0x3F, (byte) 0xFF);
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

      byte[] deliveredRmac = ((byte[]) field(secureMessaging, "responseMcv").get(secureMessaging)).clone();
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
          deliveredRmac,
          (byte[]) field(secureMessaging, "responseMcv").get(secureMessaging));
      assertEquals(
          false,
          method(secureMessagingClass, "isResponseStreamActive").invoke(secureMessaging));
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
      byte[] sessionKeys = new byte[64];
      method(secureMessagingClass, "setSessionKeys", byte[].class, short.class)
          .invoke(secureMessaging, sessionKeys, (short) 0);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);

      byte[] command = new byte[15];
      command[ISO7816.OFFSET_CLA] = (byte) 0x1C;
      command[ISO7816.OFFSET_INS] = (byte) 0xDB;
      command[ISO7816.OFFSET_P1] = (byte) 0x3F;
      command[ISO7816.OFFSET_P2] = (byte) 0x00;
      command[ISO7816.OFFSET_LC] = (byte) 0x0A;
      command[5] = (byte) 0x8E;
      command[6] = (byte) 0x08;
      byte[] work = new byte[128];
      byte[] macInput = new byte[64];
      short macLength = buildMacOnlyCommandInput(command, macInput);
      AESKey macKey = PIVCrypto.buildTransientAes128Key();
      macKey.setKey(sessionKeys, (short) 16);
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
      byte[] sessionKeys = new byte[64];
      method(secureMessagingClass, "setSessionKeys", byte[].class, short.class)
          .invoke(secureMessaging, sessionKeys, (short) 0);
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
                          (short) (command.length - 5),
                          work,
                          (short) 0));

      assertTrue(thrown.getCause() instanceof ISOException);
      assertEquals((short) 0x6988, ((ISOException) thrown.getCause()).getReason());
    }
  }

  @Test
  void unwrapMultiBlockEncryptedCommandUsesNonOverlappingCbcOutput() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(realApplet, "piv").get(realApplet);
      Object secureMessaging = field(piv, "secureMessaging").get(piv);
      Class<?> secureMessagingClass = secureMessaging.getClass();
      byte[] sessionKeys = new byte[64];
      method(secureMessagingClass, "setSessionKeys", byte[].class, short.class)
          .invoke(secureMessaging, sessionKeys, (short) 0);
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
                      (short) (command.length - 5),
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
      byte[] sessionKeys = new byte[64];
      method(secureMessagingClass, "setSessionKeys", byte[].class, short.class)
          .invoke(secureMessaging, sessionKeys, (short) 0);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);

      byte[] complete = macOnlySecureCommand((byte) 0x0C, (byte) 0xDB, (byte) 0x3F, (byte) 0x00);
      byte[] first = new byte[10];
      first[ISO7816.OFFSET_CLA] = (byte) 0x1C;
      first[ISO7816.OFFSET_INS] = complete[ISO7816.OFFSET_INS];
      first[ISO7816.OFFSET_P1] = complete[ISO7816.OFFSET_P1];
      first[ISO7816.OFFSET_P2] = complete[ISO7816.OFFSET_P2];
      first[ISO7816.OFFSET_LC] = (byte) 0x05;
      System.arraycopy(complete, 5, first, 5, 5);

      byte[] last = new byte[10];
      last[ISO7816.OFFSET_CLA] = (byte) 0x0C;
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
      byte[] sessionKeys = new byte[64];
      method(secureMessagingClass, "setSessionKeys", byte[].class, short.class)
          .invoke(secureMessaging, sessionKeys, (short) 0);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);

      byte[] command = macOnlySecureCommand((byte) 0x0C, (byte) 0xDB, (byte) 0x3F, (byte) 0x00);
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
          (short) 0x6988,
          ((ISOException) thrown.getCause()).getReason(),
          "Bad C-MAC is an incorrect secure messaging data object: '69 88' (Part 2 Section 4.2.7)");
      assertEquals(
          false,
          method(secureMessagingClass, "isEstablished").invoke(secureMessaging),
          "Session keys must be zeroized after a secure messaging error (Part 2 Section 4.3)");
    }
  }

  /**
   * Verifies that plaintext APDUs sent while VCI is established are rejected and destroy the
   * session.
   *
   * <p>NIST SP 800-73-5 Part 1 Section 5.5 defines VCI as communication over secure messaging; Part
   * 2 Section 4.3 requires session key destruction after SM errors.
   */
  @Test
  void plaintextApduDuringActiveVciSecureMessagingIsRejectedAndClearsSession() throws Exception {
    // OpenFIPS201 rejects plaintext PIV commands after VCI establishment except for the plaintext
    // OPACITY re-establishment command allowed by SP 800-73-5 Part 2 Section 4.1.8.
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT before plaintext APDU rejection");

    Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
    Object piv = field(realApplet, "piv").get(realApplet);
    Object secureMessaging = field(piv, "secureMessaging").get(piv);
    Class<?> secureMessagingClass = secureMessaging.getClass();

    try (AutoCloseable ignored = enterEngineContext()) {
      byte[] sessionKeys = new byte[64];
      method(secureMessagingClass, "setSessionKeys", byte[].class, short.class)
          .invoke(secureMessaging, sessionKeys, (short) 0);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);
    }

    ResponseAPDU response = transmit(new CommandAPDU(0x00, 0xCB, 0x3F, 0xFF, hex("5C017E"), 0));

    assertSw(
        ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
        response,
        "Plain APDU while VCI secure messaging is active");
    assertEquals(
        false,
        method(secureMessagingClass, "isEstablished").invoke(secureMessaging),
        "Plain APDU while VCI is active must destroy the secure messaging session");
  }

  @Test
  void plaintextOpacityReestablishmentDuringActiveSecureMessagingDoesNotClearSession()
      throws Exception {
    assertSw(
        0x9000,
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 0)),
        "SELECT before plaintext OPACITY re-establishment");

    Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
    Object piv = field(realApplet, "piv").get(realApplet);
    Object secureMessaging = field(piv, "secureMessaging").get(piv);
    Class<?> secureMessagingClass = secureMessaging.getClass();

    try (AutoCloseable ignored = enterEngineContext()) {
      byte[] sessionKeys = new byte[64];
      method(secureMessagingClass, "setSessionKeys", byte[].class, short.class)
          .invoke(secureMessaging, sessionKeys, (short) 0);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);
    }

    ResponseAPDU response =
        transmit(new CommandAPDU(0x00, 0x87, PIV.ID_ALG_ECC_SM & 0xFF, 0x04, hex("7C00"), 0));

    assertSw(
        0x6A88,
        response,
        "Plaintext OPACITY re-establishment reaches GENERAL AUTHENTICATE instead of SM teardown");
    assertEquals(
        true,
        method(secureMessagingClass, "isEstablished").invoke(secureMessaging),
        "Failed plaintext OPACITY re-establishment must not clear the existing SM session");
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
      byte[] sessionKeys = new byte[64];
      method(secureMessagingClass, "setSessionKeys", byte[].class, short.class)
          .invoke(secureMessaging, sessionKeys, (short) 0);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);

      // First protected command: INS 'FE' is unsupported, so command processing raises an
      // application error (SW_INS_NOT_SUPPORTED) after the secure messaging unwrap succeeded.
      byte[] mcv = new byte[16];
      byte[] first =
          chainedMacOnlySecureCommand(mcv, (byte) 0x0C, (byte) 0xFE, (byte) 0x00, (byte) 0x00, mcv);
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
          chainedMacOnlySecureCommand(mcv, (byte) 0x0C, (byte) 0xFE, (byte) 0x00, (byte) 0x00, mcv);
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
      byte[] sessionKeys = new byte[64];
      method(secureMessagingClass, "setSessionKeys", byte[].class, short.class)
          .invoke(secureMessaging, sessionKeys, (short) 0);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);

      byte[] command = macOnlySecureCommand((byte) 0x0C, (byte) 0xCB, (byte) 0x3F, (byte) 0xFF);
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
      byte[] sessionKeys = new byte[64];
      method(secureMessagingClass, "setSessionKeys", byte[].class, short.class)
          .invoke(secureMessaging, sessionKeys, (short) 0);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);

      byte[] command = macOnlySecureCommand((byte) 0x0C, (byte) 0xCB, (byte) 0x3F, (byte) 0xFF);
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

      apdu.getBuffer()[ISO7816.OFFSET_INS] = (byte) 0xC0;
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
      byte[] sessionKeys = new byte[64];
      method(secureMessagingClass, "setSessionKeys", byte[].class, short.class)
          .invoke(secureMessaging, sessionKeys, (short) 0);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);
      ((byte[]) field(piv, "secureMessagingCommand").get(piv))[0] = (byte) 1;

      APDU apdu = streamingApdu((byte) 0xCB, (short) 8);
      Method processOutgoing = method(pivClass, "processOutgoing", APDU.class);
      InvocationTargetException first =
          assertThrows(InvocationTargetException.class, () -> processOutgoing.invoke(piv, apdu));
      assertTrue(first.getCause() instanceof ISOException);
      assertEquals((short) 0x6106, ((ISOException) first.getCause()).getReason());

      apdu.getBuffer()[ISO7816.OFFSET_INS] = (byte) 0xC0;
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
      byte[] sessionKeys = new byte[64];
      method(secureMessagingClass, "setSessionKeys", byte[].class, short.class)
          .invoke(secureMessaging, sessionKeys, (short) 0);
      method(secureMessagingClass, "markEstablished", boolean.class).invoke(secureMessaging, false);

      byte[] firstMcv = new byte[16];
      byte[] command =
          chainedMacOnlySecureCommand(
              new byte[16], (byte) 0x0C, (byte) 0xCB, (byte) 0x3F, (byte) 0xFF, firstMcv);
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

      APDU apdu = streamingApdu((byte) 0xCB);
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
              firstMcv, (byte) 0x0C, (byte) 0xC0, (byte) 0x00, (byte) 0x00, new byte[16]);
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
      APDU getResponseApdu = streamingApdu((byte) 0xC0);
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

  private static short buildMacOnlyCommandInput(byte[] command, byte[] out) {
    short cursor = 0;
    for (short i = 0; i < 16; i++) {
      out[cursor++] = 0;
    }
    out[cursor++] = (byte) 0x0C;
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
    command[ISO7816.OFFSET_CLA] = (byte) 0x0C;
    command[ISO7816.OFFSET_INS] = (byte) 0xCB;
    command[ISO7816.OFFSET_P1] = (byte) 0x3F;
    command[ISO7816.OFFSET_P2] = (byte) 0xFF;
    command[ISO7816.OFFSET_LC] = (byte) (command.length - 5);

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
    macInput[macCursor++] = (byte) 0x0C;
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
    cmac.init(new org.bouncycastle.crypto.params.KeyParameter(new byte[16]));
    cmac.update(macInput, 0, macCursor);
    cmac.doFinal(mac, 0);
    System.arraycopy(mac, 0, command, cursor, 8);
    return command;
  }

  private static byte[] authenticatedEncryptedDataCommand(byte[] plaintext) throws Exception {
    byte[] paddedPlaintext = iso7816Padded(plaintext);
    byte[] counter = new byte[16];
    counter[15] = (byte) 1;
    byte[] iv = aesEcb(new byte[16], counter);
    byte[] ciphertext = aesCbcEncrypt(new byte[16], iv, paddedPlaintext);
    short encryptedValueLength = (short) (1 + ciphertext.length);
    byte[] command = new byte[5 + 2 + encryptedValueLength + 10];
    command[ISO7816.OFFSET_CLA] = (byte) 0x0C;
    command[ISO7816.OFFSET_INS] = (byte) 0xDB;
    command[ISO7816.OFFSET_P1] = (byte) 0x3F;
    command[ISO7816.OFFSET_P2] = (byte) 0xFF;
    command[ISO7816.OFFSET_LC] = (byte) (command.length - 5);

    short cursor = 5;
    command[cursor++] = (byte) 0x87;
    command[cursor++] = (byte) encryptedValueLength;
    command[cursor++] = (byte) 0x01;
    System.arraycopy(ciphertext, 0, command, cursor, ciphertext.length);
    cursor = (short) (cursor + ciphertext.length);
    command[cursor++] = (byte) 0x8E;
    command[cursor++] = (byte) 0x08;

    byte[] mac = commandMac(command, (short) 5, (short) (cursor - 2));
    System.arraycopy(mac, 0, command, cursor, 8);
    return command;
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

  private static byte[] commandMac(byte[] command, short bodyOffset, short bodyEnd) {
    byte[] macInput = new byte[16 + 16 + bodyEnd - bodyOffset];
    short cursor = 16;
    macInput[cursor++] = (byte) 0x0C;
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
    cmac.init(new org.bouncycastle.crypto.params.KeyParameter(new byte[16]));
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
    macInput[cursor++] = (byte) 0x0C;
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
    cmac.init(new org.bouncycastle.crypto.params.KeyParameter(new byte[16]));
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
}
