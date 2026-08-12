package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class ChainBufferObjectTest {
  @Test
  void atomicObjectChainCommitsOnlyAfterItsFinalFrame() {
    // SP 800-73-5 Part 2, Section 3.1.1 requires chained command data to be
    // accumulated as one command; incomplete state must not become visible.
    try (MockedStatic<JCSystem> mocked = Mockito.mockStatic(JCSystem.class)) {
      mocked
          .when(() -> JCSystem.makeTransientObjectArray(Mockito.anyShort(), Mockito.anyByte()))
          .thenAnswer(invocation -> new Object[1]);
      mocked
          .when(() -> JCSystem.makeTransientShortArray(Mockito.anyShort(), Mockito.anyByte()))
          .thenReturn(new short[11]);

      ChainBuffer chain = new ChainBuffer();
      byte[] destination = new byte[4];
      chain.setIncomingObject(destination, (short) 0, (short) 4, true);

      byte[] first = {(byte) 0x10, (byte) 0xDB, 0x3F, 0x00, 0x02, 0x11, 0x22};
      ISOException firstStatus =
          assertThrows(
              ISOException.class,
              () ->
                  chain.processIncomingObject(
                      first, (short) 5, (short) 2, ChainBuffer.PROTECTION_SCP));
      assertEquals(0x9000, firstStatus.getReason() & 0xFFFF);
      assertArrayEquals(new byte[] {0x11, 0x22, 0x00, 0x00}, destination);

      byte[] last = {0x00, (byte) 0xDB, 0x3F, 0x00, 0x02, 0x33, 0x44};
      ISOException finalStatus =
          assertThrows(
              ISOException.class,
              () ->
                  chain.processIncomingObject(
                      last, (short) 5, (short) 2, ChainBuffer.PROTECTION_SCP));
      assertEquals(0x9000, finalStatus.getReason() & 0xFFFF);
      assertArrayEquals(new byte[] {0x11, 0x22, 0x33, 0x44}, destination);
      mocked.verify(JCSystem::beginTransaction);
      mocked.verify(JCSystem::commitTransaction);
    }
  }

  @Test
  void objectChainRejectsTransportProtectionChanges() {
    // SP 800-73-5 Part 2, Section 4.1 binds secure-messaging protection to
    // the complete command, so a later frame cannot downgrade its transport.
    try (MockedStatic<JCSystem> mocked = Mockito.mockStatic(JCSystem.class)) {
      mocked
          .when(() -> JCSystem.makeTransientObjectArray(Mockito.anyShort(), Mockito.anyByte()))
          .thenAnswer(invocation -> new Object[1]);
      mocked
          .when(() -> JCSystem.makeTransientShortArray(Mockito.anyShort(), Mockito.anyByte()))
          .thenReturn(new short[11]);

      ChainBuffer chain = new ChainBuffer();
      chain.setIncomingObject(new byte[4], (short) 0, (short) 4, false);
      byte[] first = {(byte) 0x10, (byte) 0xDB, 0x3F, 0x00, 0x02, 0x11, 0x22};
      assertEquals(
          0x9000,
          assertThrows(
                  ISOException.class,
                  () ->
                      chain.processIncomingObject(
                          first, (short) 5, (short) 2, ChainBuffer.PROTECTION_SCP))
              .getReason()
              & 0xFFFF);

      byte[] last = {0x00, (byte) 0xDB, 0x3F, 0x00, 0x02, 0x33, 0x44};
      assertEquals(
          0x6982,
          assertThrows(
                  ISOException.class,
                  () ->
                      chain.processIncomingObject(
                          last, (short) 5, (short) 2, ChainBuffer.PROTECTION_PLAIN))
              .getReason()
              & 0xFFFF);
    }
  }
}
