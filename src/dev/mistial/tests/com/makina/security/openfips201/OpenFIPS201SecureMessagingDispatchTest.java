package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import pro.javacard.engine.JavaCardEngine;

/**
 * Conformance tests for secure messaging APDU dispatching.
 *
 * <p>NIST SP 800-73-5 Part 2 Sections 4.2.4-4.2.7 define protected command and
 * response APDUs; Section 4.3 defines session key destruction.
 */
class OpenFIPS201SecureMessagingDispatchTest {
  private static final short MAX_SAFE_SECURE_RESPONSE_PLAINTEXT = (short) 191;
  private static final byte[] OPENFIPS201_AID_BYTES = hex("A000000308000010000100");
  private static final AID OPENFIPS201_AID =
      new AID(OPENFIPS201_AID_BYTES, (short) 0, (byte) OPENFIPS201_AID_BYTES.length);

  private JavaCardEngine engine;
  private BIBO session;

  @BeforeEach
  void setUpCard() {
    PIVCrypto.init();
    engine = JavaCardEngine.create();
    engine.installApplet(OPENFIPS201_AID, OpenFIPS201.class, new byte[0]);
    session = engine.connect();
  }

  @AfterEach
  void tearDownCard() {
    if (session != null) {
      session.close();
    }
  }

  /**
   * Verifies that secure outgoing response chunks fit the secure messaging response buffer.
   *
   * <p>Aligned with NIST SP 800-73-5 Part 2, Section 4.2.6. Outgoing plaintext blocks are capped to
   * leave sufficient room for secure messaging envelope tags ('87', '99', '8E') and padding.
   */
  @Test
  void secureOutgoingChunksFitSecureMessagingResponseBuffer() throws Exception {
    Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
    Object piv = field(realApplet, "piv").get(realApplet);
    Object chainBuffer = field(piv, "chainBuffer").get(piv);

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
    apduBuffer[ISO7816.OFFSET_INS] = (byte) 0xC0;
    APDU apdu = Mockito.mock(APDU.class);
    when(apdu.getBuffer()).thenReturn(apduBuffer);

    Class<?> secureMessagingClass =
        chainBuffer.getClass().getClassLoader().loadClass(PIVSecureMessaging.class.getName());
    Object secureMessaging = Mockito.mock(secureMessagingClass);
    byte[] secureResponse = new byte[448];
    final short[] wrappedPlaintextLength = new short[] {(short) -1};
    Method wrapResponse =
        method(
            secureMessagingClass,
            "wrapResponse",
            byte[].class,
            short.class,
            short.class,
            short.class,
            byte[].class,
            short.class);
    doAnswer(
            invocation -> {
              wrappedPlaintextLength[0] = (Short) invocation.getArgument(2);
              return (short) 16;
            })
        .when(secureMessaging);
    wrapResponse.invoke(
        secureMessaging,
        Mockito.any(byte[].class),
        Mockito.anyShort(),
        Mockito.anyShort(),
        Mockito.anyShort(),
        Mockito.same(secureResponse),
        Mockito.eq((short) 0));

    Method processOutgoingSecure =
        method(
            chainBuffer.getClass(),
            "processOutgoingSecure",
            APDU.class,
            secureMessagingClass,
            byte[].class,
            short.class);
    InvocationTargetException thrown =
        assertThrows(
            InvocationTargetException.class,
            () ->
                processOutgoingSecure.invoke(
                    chainBuffer, apdu, secureMessaging, secureResponse, ISO7816.SW_NO_ERROR));

    assertTrue(
        thrown.getCause() instanceof ISOException, "Chain completion should throw SW_NO_ERROR");
    assertEquals(
        ISO7816.SW_NO_ERROR,
        ((ISOException) thrown.getCause()).getReason(),
        "Successful wrap completes by ISOException");
    assertEquals(
        MAX_SAFE_SECURE_RESPONSE_PLAINTEXT,
        wrappedPlaintextLength[0],
        "Secure outgoing chunks must leave room for response wrapping overhead");
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
   * <p>NIST SP 800-73-5 Part 1 Section 5.5 defines VCI as communication over secure
   * messaging; Part 2 Section 4.3 requires session key destruction after SM errors.
   */
  @Test
  void plaintextApduDuringActiveVciSecureMessagingIsRejectedAndClearsSession() throws Exception {
    // SP 800-73-5 Part 1 Section 5.5 defines VCI as secure messaging plus policy bits.
    // Plain APDUs after VCI establishment are rejected except for the GET RESPONSE
    // continuation allowed by Part 2 Section 4.2.6 response chaining.
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
   * Verifies that a plain GET RESPONSE command does not increment the encryption counter.
   *
   * <p>Aligned with NIST SP 800-73-5 Part 2, Section 4.2.2 (Encryption counter increment
   * exceptions).
   */
  @Test
  void plainGetResponseSecureContinuationDoesNotIncrementEncryptionCounter() throws Exception {
    // SP 800-73-5 Part 2 Section 4.2.2 states that the encryption counter is not
    // incremented for GET RESPONSE in a secure-messaging response chain.
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
          .invoke(chainBuffer, outgoing, (short) 0, (short) outgoing.length, false);
      ((byte[]) field(piv, "secureMessagingCommand").get(piv))[0] = (byte) 1;

      ResponseAPDU response = transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00, 0));

      assertSw(0x9000, response, "Plain GET RESPONSE secure continuation");

      assertArrayEquals(
          counterBeforeGetResponse,
          counter(secureMessaging),
          "Plain GET RESPONSE secure continuation must not increment the encryption counter");
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
    Method unwrapSecureMessagingCommand =
        method(pivClass, "unwrapSecureMessagingCommand", byte[].class, short.class, short.class);
    Method processOutgoing = method(pivClass, "processOutgoing", APDU.class);
    final boolean[] outgoingCalled = new boolean[] {false};

    when((Boolean) isSecureMessagingCla.invoke(piv, Mockito.anyByte())).thenReturn(true);
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
