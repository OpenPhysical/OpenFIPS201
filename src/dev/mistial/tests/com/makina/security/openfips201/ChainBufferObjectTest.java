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
  void unpublishedFinalFragmentDoesNotRequireBulkCommitCapacity() {
    try (MockedStatic<JCSystem> system = Mockito.mockStatic(JCSystem.class);
        MockedStatic<javacard.framework.Util> util =
            Mockito.mockStatic(javacard.framework.Util.class, Mockito.CALLS_REAL_METHODS)) {
      mockTransientStorage(system);
      // The emulator implements non-atomic copy by delegating to arrayCopy. Model the
      // Java Card distinction explicitly so a BUFFER_FULL double tests the product call site.
      util.when(
              () ->
                  javacard.framework.Util.arrayCopyNonAtomic(
                      Mockito.any(byte[].class),
                      Mockito.anyShort(),
                      Mockito.any(byte[].class),
                      Mockito.anyShort(),
                      Mockito.anyShort()))
          .thenAnswer(
              call -> {
                byte[] source = call.getArgument(0);
                short sourceOffset = call.getArgument(1);
                byte[] destination = call.getArgument(2);
                short destinationOffset = call.getArgument(3);
                short length = call.getArgument(4);
                System.arraycopy(source, sourceOffset, destination, destinationOffset, length);
                return (short) (destinationOffset + length);
              });
      util.when(
              () ->
                  javacard.framework.Util.arrayCopy(
                      Mockito.any(byte[].class),
                      Mockito.anyShort(),
                      Mockito.any(byte[].class),
                      Mockito.anyShort(),
                      Mockito.anyShort()))
          .thenThrow(
              new javacard.framework.TransactionException(
                  javacard.framework.TransactionException.BUFFER_FULL));
      ChainBuffer chain = new ChainBuffer();
      byte[] unpublished = new byte[4];
      chain.setIncomingObject(unpublished, (short) 0, (short) 4, false);
      byte[] command = {(byte) 0, (byte) 0xDB, (byte) 0xFF, (byte) 0xFF, 4, 1, 2, 3, 4};
      assertEquals(
          0x9000,
          assertThrows(
                      ISOException.class,
                      () ->
                          chain.processIncomingObject(
                              command, (short) 5, (short) 4, ChainBuffer.PROTECTION_SCP))
                  .getReason()
              & 0xFFFF);
      assertArrayEquals(new byte[] {1, 2, 3, 4}, unpublished);
    }
  }

  @Test
  void atomicObjectChainCommitsOnlyAfterItsFinalFrame() {
    // SP 800-73-5 Part 2, Section 3.1.1 requires chained command data to be
    // accumulated as one command; incomplete state must not become visible.
    try (MockedStatic<JCSystem> mocked = Mockito.mockStatic(JCSystem.class)) {
      mockTransientStorage(mocked);

      ChainBuffer chain = new ChainBuffer();
      byte[] destination = new byte[4];
      chain.setIncomingObject(destination, (short) 0, (short) 4, true);

      byte[] first = {(byte) 0x10, (byte) 0xDB, (byte) 0xFF, (byte) 0xFF, 0x02, 0x11, 0x22};
      ISOException firstStatus =
          assertThrows(
              ISOException.class,
              () ->
                  chain.processIncomingObject(
                      first, (short) 5, (short) 2, ChainBuffer.PROTECTION_SCP));
      assertEquals(0x9000, firstStatus.getReason() & 0xFFFF);
      assertArrayEquals(new byte[] {0x11, 0x22, 0x00, 0x00}, destination);

      byte[] last = {0x00, (byte) 0xDB, (byte) 0xFF, (byte) 0xFF, 0x02, 0x33, 0x44};
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
      mockTransientStorage(mocked);

      ChainBuffer chain = new ChainBuffer();
      chain.setIncomingObject(new byte[4], (short) 0, (short) 4, false);
      byte[] first = {(byte) 0x10, (byte) 0xDB, (byte) 0xFF, (byte) 0xFF, 0x02, 0x11, 0x22};
      assertEquals(
          0x9000,
          assertThrows(
                      ISOException.class,
                      () ->
                          chain.processIncomingObject(
                              first, (short) 5, (short) 2, ChainBuffer.PROTECTION_SCP))
                  .getReason()
              & 0xFFFF);

      byte[] last = {0x00, (byte) 0xDB, (byte) 0xFF, (byte) 0xFF, 0x02, 0x33, 0x44};
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

  private static void mockTransientStorage(MockedStatic<JCSystem> system) {
    system
        .when(() -> JCSystem.makeTransientObjectArray(Mockito.anyShort(), Mockito.anyByte()))
        .thenAnswer(call -> new Object[(short) call.getArgument(0)]);
    system
        .when(() -> JCSystem.makeTransientShortArray(Mockito.anyShort(), Mockito.anyByte()))
        .thenAnswer(call -> new short[(short) call.getArgument(0)]);
  }
}
