package com.makina.security.openfips201;

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

  @Test
  void secureOutgoingChunksFitSecureMessagingResponseBuffer() throws Exception {
    Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
    Object piv = field(realApplet, "piv").get(realApplet);
    Object chainBuffer = field(piv, "chainBuffer").get(piv);

    byte[] outgoing = new byte[256];
    method(chainBuffer.getClass(), "setOutgoing", byte[].class, short.class, short.class, boolean.class)
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

    assertTrue(thrown.getCause() instanceof ISOException, "Chain completion should throw SW_NO_ERROR");
    assertEquals(
        ISO7816.SW_NO_ERROR,
        ((ISOException) thrown.getCause()).getReason(),
        "Successful wrap completes by ISOException");
    assertEquals(
        MAX_SAFE_SECURE_RESPONSE_PLAINTEXT,
        wrappedPlaintextLength[0],
        "Secure outgoing chunks must leave room for response wrapping overhead");
  }

  @Test
  void unwrapPreservesCommandChainingBit() throws Exception {
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet realApplet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(realApplet, "piv").get(realApplet);
      Object secureMessaging = field(piv, "secureMessaging").get(piv);
      Class<?> secureMessagingClass = secureMessaging.getClass();
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
    Method processOutgoingSecure =
        method(pivClass, "processOutgoingSecure", APDU.class, short.class);
    final short[] outgoingSw = new short[] {(short) 0xFFFF};

    when((Boolean) isSecureMessagingCla.invoke(piv, Mockito.anyByte())).thenReturn(true);
    when((Short)
            unwrapSecureMessagingCommand.invoke(
                piv, Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyShort()))
        .thenReturn((short) 0);
    doAnswer(
            invocation -> {
              outgoingSw[0] = (Short) invocation.getArgument(1);
              throw new ISOException(ISO7816.SW_NO_ERROR);
            })
        .when(piv);
    processOutgoingSecure.invoke(piv, Mockito.any(APDU.class), Mockito.anyShort());

    pivField.set(realApplet, piv);

    ResponseAPDU response = transmit(new CommandAPDU(0x0C, 0xC0, 0x00, 0x00, 0));

    assertSw(0x9000, response, "Protected GET RESPONSE should be dispatched as secure outgoing");
    assertEquals(
        ISO7816.SW_NO_ERROR,
        outgoingSw[0],
        "Protected GET RESPONSE should continue the secure outgoing chain, not wrap 6D00");
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
