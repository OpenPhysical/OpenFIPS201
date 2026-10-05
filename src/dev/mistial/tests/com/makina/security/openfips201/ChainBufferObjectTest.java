package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

  @Test
  void emptyIntermediateObjectFrameLeavesChainUnchanged() {
    // ISO/IEC 7816-4 Section 5.3.3: an empty frame with b5 set is still part of the chain. It must
    // be consumed with 9000 rather than dispatched as a new command that fails mid-chain.
    try (MockedStatic<JCSystem> mocked = Mockito.mockStatic(JCSystem.class)) {
      mockTransientStorage(mocked);
      ChainBuffer chain = new ChainBuffer();
      byte[] destination = new byte[4];
      chain.setIncomingObject(destination, (short) 0, (short) 4, false);

      byte[] first = {(byte) 0x10, (byte) 0xDB, (byte) 0xFF, (byte) 0xFF, 0x02, 0x11, 0x22};
      assertEquals(0x9000, objectStatus(chain, first, (short) 2));
      byte[] empty = {(byte) 0x10, (byte) 0xDB, (byte) 0xFF, (byte) 0xFF, 0x00};
      assertEquals(0x9000, objectStatus(chain, empty, (short) 0));
      byte[] last = {0x00, (byte) 0xDB, (byte) 0xFF, (byte) 0xFF, 0x02, 0x33, 0x44};
      assertEquals(0x9000, objectStatus(chain, last, (short) 2));
      assertArrayEquals(new byte[] {0x11, 0x22, 0x33, 0x44}, destination);
    }
  }

  @Test
  void apduChainLinkWithDifferentHeaderReturnsLastCommandExpected() {
    // ISO/IEC 7816-4 Section 5.3.3: "All CLA bytes of the commands shall be the same, except for
    // bit b5" and "All INS P1 P2 bytes of the commands shall be the same." A mismatching link is
    // rejected with '6883' and the chain is discarded.
    byte[][] mismatches = {
      {(byte) 0x80, (byte) 0x87, 0x11, (byte) 0x9A, 0x01, 0x02}, // CLA
      {0x00, (byte) 0x47, 0x11, (byte) 0x9A, 0x01, 0x02}, // INS
      {0x00, (byte) 0x87, 0x07, (byte) 0x9A, 0x01, 0x02}, // P1
      {0x00, (byte) 0x87, 0x11, (byte) 0x9C, 0x01, 0x02}, // P2
      {(byte) 0x90, (byte) 0x87, 0x11, (byte) 0x9A, 0x01, 0x02}, // CLA, middle link
    };
    for (byte[] link : mismatches) {
      try (MockedStatic<JCSystem> mocked = Mockito.mockStatic(JCSystem.class)) {
        mockTransientStorage(mocked);
        ChainBuffer chain = new ChainBuffer();
        byte[] out = new byte[16];
        byte[] first = {(byte) 0x10, (byte) 0x87, 0x11, (byte) 0x9A, 0x01, 0x01};
        assertEquals(0, chain.processIncomingAPDU(first, (short) 5, (short) 1, out, (short) 0));
        assertEquals(0x6883, apduStatus(chain, link, out));

        // The chain was discarded: the next command is processed on its own.
        byte[] single = {0x00, (byte) 0x87, 0x11, (byte) 0x9A, 0x01, 0x03};
        assertEquals(1, chain.processIncomingAPDU(single, (short) 5, (short) 1, out, (short) 0));
        assertEquals(0x03, out[0]);
      }
    }
  }

  @Test
  void checkIncomingApduAbandonsChainForAnotherInstruction() {
    try (MockedStatic<JCSystem> mocked = Mockito.mockStatic(JCSystem.class)) {
      mockTransientStorage(mocked);
      ChainBuffer chain = new ChainBuffer();
      byte[] out = new byte[16];
      byte[] first = {(byte) 0x10, (byte) 0x87, 0x00, (byte) 0x9A, 0x01, 0x01};
      assertEquals(0, chain.processIncomingAPDU(first, (short) 5, (short) 1, out, (short) 0));
      assertTrue(chain.isIncomingApduActive());

      // Same CLA, P1 and P2, different INS: not a continuation of the GENERAL AUTHENTICATE chain.
      byte[] other = {0x00, (byte) 0x47, 0x00, (byte) 0x9A, 0x01, 0x02};
      chain.checkIncomingAPDU(other);
      assertFalse(chain.isIncomingApduActive());
      assertEquals(1, chain.processIncomingAPDU(other, (short) 5, (short) 1, out, (short) 0));
      assertEquals(0x02, out[0]);
    }
  }

  @Test
  void everyReassemblyOverrunReportsWrongLength() {
    try (MockedStatic<JCSystem> mocked = Mockito.mockStatic(JCSystem.class)) {
      mockTransientStorage(mocked);
      ChainBuffer chain = new ChainBuffer();
      byte[] out = new byte[3];
      byte[] single = {0x00, (byte) 0x87, 0x00, (byte) 0x9A, 0x04, 1, 2, 3, 4};
      byte[] chained = {(byte) 0x10, (byte) 0x87, 0x00, (byte) 0x9A, 0x04, 1, 2, 3, 4};
      byte[] two = {(byte) 0x10, (byte) 0x87, 0x00, (byte) 0x9A, 0x02, 1, 2};
      byte[] lastTwo = {0x00, (byte) 0x87, 0x00, (byte) 0x9A, 0x02, 3, 4};

      assertEquals(0x6700, apduStatus(chain, single, out));
      assertEquals(0x6700, apduStatus(chain, chained, out));
      assertEquals(0, chain.processIncomingAPDU(two, (short) 5, (short) 2, out, (short) 0));
      assertEquals(0x6700, apduStatus(chain, lastTwo, out));
      assertFalse(chain.isIncomingApduActive());
    }
  }

  @Test
  void bytesRemainingStatusWordUsesShortLeEncoding() {
    // ISO/IEC 7816-4 Section 5.6: SW2 of '61XX' is used "as short L e field", where '00' is 256.
    assertEquals(0x6101, ChainBuffer.bytesRemainingStatusWord((short) 1) & 0xFFFF);
    assertEquals(0x61FF, ChainBuffer.bytesRemainingStatusWord((short) 255) & 0xFFFF);
    assertEquals(0x6100, ChainBuffer.bytesRemainingStatusWord((short) 256) & 0xFFFF);
    assertEquals(0x6100, ChainBuffer.bytesRemainingStatusWord((short) 4000) & 0xFFFF);
  }

  private static int objectStatus(ChainBuffer chain, byte[] command, short length) {
    return assertThrows(
                ISOException.class,
                () ->
                    chain.processIncomingObject(
                        command, (short) 5, length, ChainBuffer.PROTECTION_SCP))
            .getReason()
        & 0xFFFF;
  }

  private static int apduStatus(ChainBuffer chain, byte[] command, byte[] out) {
    short length = (short) (command.length - 5);
    return assertThrows(
                ISOException.class,
                () -> chain.processIncomingAPDU(command, (short) 5, length, out, (short) 0))
            .getReason()
        & 0xFFFF;
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
