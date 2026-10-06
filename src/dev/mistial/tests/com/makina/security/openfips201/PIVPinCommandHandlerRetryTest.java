package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class PIVPinCommandHandlerRetryTest {
  @Test
  void contactlessRetriesExcludeTheIntermediateReserve() {
    // SP 800-73-5 Part 2 Section 3.2.1 requires VERIFY to preserve the issuer's
    // contactless intermediate retry reserve.
    assertEquals(0, PIVPinCommandHandler.usableRetries((byte) 1, (byte) 1, true));
    assertEquals(3, PIVPinCommandHandler.usableRetries((byte) 4, (byte) 1, true));
    assertEquals(4, PIVPinCommandHandler.usableRetries((byte) 4, (byte) 1, false));
  }

  @Test
  void contactlessVerifyExhaustionPreservesTheContactReserve() {
    Config config = new Config();
    update(
        config,
        new byte[] {
          (byte) 0xA0,
          0x24,
          (byte) 0x80,
          0x01,
          0x01,
          (byte) 0x81,
          0x01,
          0x00,
          (byte) 0x82,
          0x01,
          0x00,
          (byte) 0x83,
          0x01,
          (byte) 0xFF,
          (byte) 0x84,
          0x01,
          0x06,
          (byte) 0x85,
          0x01,
          0x08,
          (byte) 0x86,
          0x01,
          0x06,
          (byte) 0x87,
          0x01,
          0x05,
          (byte) 0x88,
          0x01,
          0x00,
          (byte) 0x89,
          0x01,
          0x00,
          (byte) 0x8A,
          0x01,
          0x00,
          (byte) 0x8B,
          0x01,
          0x00
        });

    PIV owner = Mockito.mock(PIV.class);
    PIVSecurityProvider provider = Mockito.mock(PIVSecurityProvider.class);
    PIVPIN pin = Mockito.mock(PIVPIN.class);
    Mockito.when(owner.isVciSatisfied()).thenReturn(true);
    Mockito.when(provider.getIsContactless()).thenReturn(true);
    Mockito.when(provider.getPIN(PIV.ID_CVM_LOCAL_PIN)).thenReturn(pin);

    final byte[] retries = {(byte) 6};
    Mockito.when(pin.getTriesRemaining()).thenAnswer(ignored -> retries[0]);
    Mockito.when(pin.check(Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyByte()))
        .thenAnswer(
            ignored -> {
              retries[0]--;
              return false;
            });

    PIVPinCommandHandler handler =
        new PIVPinCommandHandler(
            owner,
            config,
            provider,
            Mockito.mock(PIVDataStore.class),
            Mockito.mock(PIVSecureMessaging.class),
            new byte[512]);
    byte[] wrongPin = {
      (byte) '6', (byte) '5', (byte) '4', (byte) '3',
      (byte) '2', (byte) '1', (byte) 0xFF, (byte) 0xFF
    };

    for (short usable = 4; usable >= 0; usable--) {
      final short expected = usable;
      ISOException failure =
          assertThrows(
              ISOException.class,
              () -> handler.verify(PIV.ID_CVM_LOCAL_PIN, wrongPin, (short) 0, (short) 8));
      assertEquals((short) (PIV.SW_RETRIES_REMAINING | expected), failure.getReason());
    }
    ISOException blocked =
        assertThrows(
            ISOException.class,
            () -> handler.verify(PIV.ID_CVM_LOCAL_PIN, wrongPin, (short) 0, (short) 8));
    assertEquals(PIV.SW_AUTHENTICATION_METHOD_BLOCKED, blocked.getReason());
    assertEquals(1, retries[0], "Contactless attempts must preserve one contact retry");
  }

  @Test
  void emptyVerifyAtContactlessReserveReportsNoUsableRetries() {
    // SP 800-73-5 Part 2 Section 3.2.1: "If P1='00' and Lc and the command data field are absent,
    // the command CAN be used to retrieve the number of further retries allowed ('63 CX')". The
    // intermediate-retry '69 83' rule applies only when the command data field is present.
    Fixture fixture = new Fixture(true);
    fixture.pinRetries[0] = 1;

    assertSw(PIV.SW_RETRIES_REMAINING, () -> fixture.handler.verifyGetStatus(PIV.ID_CVM_LOCAL_PIN));

    fixture.pinRetries[0] = 0;
    assertSw(
        PIV.SW_AUTHENTICATION_METHOD_BLOCKED,
        () -> fixture.handler.verifyGetStatus(PIV.ID_CVM_LOCAL_PIN));
  }

  @Test
  void changeReferenceDataAtContactlessReserveReturns6983WithoutComparison() {
    // SP 800-73-5 Part 2 Section 3.2.2: over the VCI, at or below the intermediate retry value,
    // "the reference data associated with the key reference SHALL NOT be changed, and the PIV Card
    // Application SHALL return the status word '69 83'."
    Fixture fixture = new Fixture(true);
    fixture.pinRetries[0] = 1;

    assertSw(
        PIV.SW_AUTHENTICATION_METHOD_BLOCKED,
        () ->
            fixture.handler.changeReferenceData(
                PIV.ID_CVM_LOCAL_PIN, CHANGE_PAYLOAD, (short) 0, (short) 16));
    Mockito.verify(fixture.pin, Mockito.never())
        .check(Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyByte());
    Mockito.verify(fixture.provider, Mockito.never())
        .updatePIN(
            Mockito.anyByte(),
            Mockito.any(byte[].class),
            Mockito.anyShort(),
            Mockito.anyByte(),
            Mockito.anyByte());
    assertEquals(1, fixture.pinRetries[0], "The retry counter must remain unchanged");
  }

  @Test
  void changeReferenceDataContactlessFailureReportsUsableRetries() {
    Fixture fixture = new Fixture(true);
    fixture.pinRetries[0] = 4;

    // Four tries remain and one is the contact reserve; the failed comparison leaves two usable.
    assertSw(
        (short) (PIV.SW_RETRIES_REMAINING | 2),
        () ->
            fixture.handler.changeReferenceData(
                PIV.ID_CVM_LOCAL_PIN, CHANGE_PAYLOAD, (short) 0, (short) 16));
  }

  @Test
  void resetRetryCounterOverContactlessReturns6A81WithoutComparison() {
    // SP 800-73-5 Part 2 Table 2 marks RESET RETRY COUNTER "No" for contactless: "The PIV Card
    // Application shall return the status word of '6A 81' (Function not supported) when it
    // receives a card command on the contactless interface marked "No"".
    Fixture fixture = new Fixture(true);

    assertSw(
        ISO7816.SW_FUNC_NOT_SUPPORTED,
        () ->
            fixture.handler.resetRetryCounter(
                PIV.ID_CVM_LOCAL_PIN, CHANGE_PAYLOAD, (short) 0, (short) 16));
    Mockito.verify(fixture.puk, Mockito.never())
        .check(Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyByte());
    assertEquals(6, fixture.pukRetries[0], "The PUK retry counter must remain unchanged");
  }

  @Test
  void refusedGlobalPinChangeRestoresStatusAndSkipsNewValueVerification() {
    // GP Card Specification v2.3.1 Section 8.2.1 makes a CVM value change depend on the CVM
    // Management privilege. A refused change must not verify the unchanged CVM against the new
    // value, which would consume a Global PIN try, and must not report success.
    Fixture fixture = new Fixture(false);
    PIVPIN globalPin = Mockito.mock(PIVPIN.class);
    Mockito.when(fixture.provider.getPIN(PIV.ID_CVM_GLOBAL_PIN)).thenReturn(globalPin);
    Mockito.when(fixture.owner.isGlobalPinAdvertised()).thenReturn(true);
    Mockito.when(globalPin.getTriesRemaining()).thenReturn((byte) 3);
    Mockito.when(globalPin.check(Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyByte()))
        .thenReturn(true);
    Mockito.doAnswer(
            ignored -> {
              ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
              return null;
            })
        .when(fixture.provider)
        .updatePIN(
            Mockito.eq(PIV.ID_CVM_GLOBAL_PIN),
            Mockito.any(byte[].class),
            Mockito.anyShort(),
            Mockito.anyByte(),
            Mockito.anyByte());

    assertSw(
        ISO7816.SW_FUNC_NOT_SUPPORTED,
        () ->
            fixture.handler.changeReferenceData(
                PIV.ID_CVM_GLOBAL_PIN, CHANGE_PAYLOAD, (short) 0, (short) 16));
    Mockito.verify(globalPin, Mockito.times(1))
        .check(Mockito.any(byte[].class), Mockito.eq((short) 0), Mockito.anyByte());
    Mockito.verify(globalPin, Mockito.never())
        .check(Mockito.any(byte[].class), Mockito.eq((short) 8), Mockito.anyByte());
    Mockito.verify(globalPin).reset();
    Mockito.verify(fixture.provider, Mockito.never()).markPINAlways();
  }

  private static final byte[] CHANGE_PAYLOAD = {
    (byte) '1', (byte) '2', (byte) '3', (byte) '4',
    (byte) '5', (byte) '6', (byte) 0xFF, (byte) 0xFF,
    (byte) '9', (byte) '8', (byte) '7', (byte) '6',
    (byte) '5', (byte) '4', (byte) 0xFF, (byte) 0xFF
  };

  /**
   * A handler over mocked PIV state. The configuration enables the local and Global PIN and
   * contactless PIN use (not contactless PUK use), with contact/contactless retries of 6/5 for the
   * PIN and the PUK, so each reference keeps an intermediate (contact-only) reserve of one retry.
   */
  private static final class Fixture {
    final PIV owner = Mockito.mock(PIV.class);
    final PIVSecurityProvider provider = Mockito.mock(PIVSecurityProvider.class);
    final PIVPIN pin = Mockito.mock(PIVPIN.class);
    final PIVPIN puk = Mockito.mock(PIVPIN.class);
    final byte[] pinRetries = {(byte) 6};
    final byte[] pukRetries = {(byte) 6};
    final PIVPinCommandHandler handler;

    Fixture(boolean contactless) {
      Config config = new Config();
      update(
          config,
          new byte[] {
            (byte) 0xA0,
            0x0F,
            (byte) 0x81,
            0x01,
            (byte) 0xFF,
            (byte) 0x83,
            0x01,
            (byte) 0xFF,
            (byte) 0x86,
            0x01,
            0x06,
            (byte) 0x87,
            0x01,
            0x05,
            (byte) 0x89,
            0x01,
            0x00,
            (byte) 0xA1,
            0x09,
            (byte) 0x81,
            0x01,
            0x00,
            (byte) 0x83,
            0x01,
            0x06,
            (byte) 0x84,
            0x01,
            0x05
          });
      Mockito.when(owner.isVciSatisfied()).thenReturn(true);
      Mockito.when(provider.getIsContactless()).thenReturn(contactless);
      Mockito.when(provider.getPIN(PIV.ID_CVM_LOCAL_PIN)).thenReturn(pin);
      Mockito.when(provider.getPIN(PIV.ID_CVM_PUK)).thenReturn(puk);
      Mockito.when(pin.getTriesRemaining()).thenAnswer(ignored -> pinRetries[0]);
      Mockito.when(puk.getTriesRemaining()).thenAnswer(ignored -> pukRetries[0]);
      Mockito.when(pin.check(Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyByte()))
          .thenAnswer(
              ignored -> {
                pinRetries[0]--;
                return false;
              });
      Mockito.when(puk.check(Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyByte()))
          .thenAnswer(
              ignored -> {
                pukRetries[0]--;
                return false;
              });
      handler =
          new PIVPinCommandHandler(
              owner,
              config,
              provider,
              Mockito.mock(PIVDataStore.class),
              Mockito.mock(PIVSecureMessaging.class),
              new byte[512]);
    }
  }

  private static void assertSw(short expected, Runnable command) {
    ISOException failure = assertThrows(ISOException.class, command::run);
    assertEquals(expected, failure.getReason());
  }

  private static void update(Config config, byte[] encoded) {
    try (MockedStatic<JCSystem> mocked = Mockito.mockStatic(JCSystem.class)) {
      mocked
          .when(() -> JCSystem.makeTransientObjectArray(Mockito.anyShort(), Mockito.anyByte()))
          .thenReturn(new Object[1]);
      mocked
          .when(() -> JCSystem.makeTransientShortArray(Mockito.anyShort(), Mockito.anyByte()))
          .thenAnswer(call -> new short[(short) call.getArgument(0)]);
      TLVReader reader = TLVReader.getInstance();
      reader.init(encoded, (short) 0, (short) encoded.length);
      config.update(reader);
    }
  }
}
