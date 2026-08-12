package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
          0x26,
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
          0x00,
          (byte) 0x8C,
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

  private static void update(Config config, byte[] encoded) {
    try (MockedStatic<JCSystem> mocked = Mockito.mockStatic(JCSystem.class)) {
      mocked
          .when(() -> JCSystem.makeTransientObjectArray(Mockito.anyShort(), Mockito.anyByte()))
          .thenReturn(new Object[1]);
      mocked
          .when(() -> JCSystem.makeTransientShortArray(Mockito.anyShort(), Mockito.anyByte()))
          .thenReturn(new short[4]);
      TLVReader reader = TLVReader.getInstance();
      reader.init(encoded, (short) 0, (short) encoded.length);
      config.update(reader);
    }
  }
}
