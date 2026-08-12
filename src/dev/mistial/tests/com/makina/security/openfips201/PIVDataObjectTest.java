package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class PIVDataObjectTest {
  @Test
  void fixedCapacityReusesTransactionalBuffersAcrossUpdates() {
    PIVDataObject object = fixedObject((short) 8);

    try (MockedStatic<JCSystem> ignored = Mockito.mockStatic(JCSystem.class)) {
      byte[] firstStage = object.beginUpdate((short) 4);
      System.arraycopy(new byte[] {1, 2, 3, 4}, 0, firstStage, 0, 4);
      object.commitUpdate();
      byte[] firstPublished = object.content;

      byte[] secondStage = object.beginUpdate((short) 2);
      System.arraycopy(new byte[] {5, 6}, 0, secondStage, 0, 2);
      object.commitUpdate();

      assertSame(firstStage, firstPublished);
      assertSame(secondStage, object.content);
      assertSame(firstPublished, object.beginUpdate((short) 3));
      assertEquals(2, object.getLength());
      assertArrayEquals(new byte[] {5, 6}, new byte[] {object.content[0], object.content[1]});
    }
  }

  @Test
  void abortedAndOversizedUpdatesPreservePublishedContent() {
    PIVDataObject object = fixedObject((short) 4);

    try (MockedStatic<JCSystem> ignored = Mockito.mockStatic(JCSystem.class)) {
      byte[] stage = object.beginUpdate((short) 3);
      System.arraycopy(new byte[] {1, 2, 3}, 0, stage, 0, 3);
      object.commitUpdate();
      assertTrue(object.isInitialised());

      byte[] aborted = object.beginUpdate((short) 2);
      aborted[0] = 9;
      aborted[1] = 9;
      object.abortUpdate();
      assertEquals(3, object.getLength());
      assertArrayEquals(
          new byte[] {1, 2, 3},
          new byte[] {object.content[0], object.content[1], object.content[2]});

      ISOException error = assertThrows(ISOException.class, () -> object.beginUpdate((short) 5));
      assertEquals(0x6A84, error.getReason() & 0xFFFF);
      assertEquals(3, object.getLength());

      object.clear();
      assertFalse(object.isInitialised());
      assertSame(aborted, object.beginUpdate((short) 1));
    }
  }

  private static PIVDataObject fixedObject(short capacity) {
    return new PIVDataObject(
        new byte[] {0x7E},
        (short) 0,
        (short) 1,
        PIVObject.ACCESS_MODE_ALWAYS,
        PIVObject.ACCESS_MODE_ALWAYS,
        (byte) 0x9B,
        capacity);
  }
}
