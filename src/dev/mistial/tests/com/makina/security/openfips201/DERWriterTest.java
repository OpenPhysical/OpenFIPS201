package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.JavaCardEngine;

class DERWriterTest {

  private final JavaCardEngine engine = JavaCardEngine.create();
  private AutoCloseable context;

  @BeforeEach
  void enterEngine() throws Exception {
    Method asCurrent = engine.getClass().getMethod("asCurrent");
    context = (AutoCloseable) asCurrent.invoke(engine);
    resetSingletons();
    DERWriter.initialize();
  }

  @AfterEach
  void leaveEngine() throws Exception {
    // Later simulator installs allocate fresh writers in their own engine.
    resetSingletons();
    context.close();
  }

  @Test
  void positiveIntegerStripsRedundantLeadingZeros() {
    assertArrayEquals(new byte[] {0x02, 0x03, 0x01, 0x00, 0x01}, integer(0x00, 0x01, 0x00, 0x01));
  }

  @Test
  void positiveIntegerKeepsOneZeroBeforeHighBit() {
    assertArrayEquals(new byte[] {0x02, 0x02, 0x00, (byte) 0x80}, integer(0x00, 0x00, 0x80));
    assertArrayEquals(new byte[] {0x02, 0x02, 0x00, (byte) 0xFF}, integer(0xFF));
  }

  @Test
  void positiveIntegerEncodesZeroAsSingleOctet() {
    assertArrayEquals(new byte[] {0x02, 0x01, 0x00}, integer(0x00));
    assertArrayEquals(new byte[] {0x02, 0x01, 0x00}, integer(0x00, 0x00, 0x00));
  }

  @Test
  void positiveIntegerRejectsEmptyMagnitude() {
    DERWriter writer = DERWriter.getInstance();
    byte[] out = new byte[8];
    writer.init(out, (short) 0);
    ISOException thrown =
        assertThrows(
            ISOException.class,
            () -> writer.writePositiveInteger(new byte[1], (short) 0, (short) 0));
    assertEquals(ISO7816.SW_UNKNOWN, thrown.getReason());
  }

  @Test
  void nestedStructuresCompactToShortestLength() {
    DERWriter writer = DERWriter.getInstance();
    byte[] out = new byte[0x200];
    writer.init(out, (short) 0);
    writer.begin((byte) 0x30);
    writer.write(new byte[0x7F], (short) 0, (short) 0x7F);
    writer.end();
    assertEquals((short) 0x81, writer.getOffset());
    assertEquals(0x30, out[0]);
    assertEquals(0x7F, out[1]);

    writer.init(out, (short) 0);
    writer.begin((byte) 0x30);
    writer.write(new byte[0x80], (short) 0, (short) 0x80);
    writer.end();
    assertArrayEquals(new byte[] {0x30, (byte) 0x81, (byte) 0x80}, Arrays.copyOf(out, 3));

    writer.init(out, (short) 0);
    writer.begin((byte) 0x30);
    writer.write(new byte[0x100], (short) 0, (short) 0x100);
    writer.end();
    assertArrayEquals(new byte[] {0x30, (byte) 0x82, 0x01, 0x00}, Arrays.copyOf(out, 4));
  }

  @Test
  void overflowFailsClosed() {
    DERWriter writer = DERWriter.getInstance();
    byte[] out = new byte[4];
    writer.init(out, (short) 0);
    ISOException thrown =
        assertThrows(ISOException.class, () -> writer.write(new byte[5], (short) 0, (short) 5));
    assertEquals(ISO7816.SW_FILE_FULL, thrown.getReason());
  }

  @Test
  void cursorStateIsTransient() throws Exception {
    for (DERWriter writer :
        new DERWriter[] {DERWriter.getInstance(), DERWriter.getNestedInstance()}) {
      assertNotEquals(
          JCSystem.NOT_A_TRANSIENT_OBJECT, JCSystem.isTransient(field(writer, "state")));
      assertNotEquals(
          JCSystem.NOT_A_TRANSIENT_OBJECT, JCSystem.isTransient(field(writer, "bufferRef")));
    }
  }

  private static byte[] integer(int... magnitude) {
    byte[] in = new byte[magnitude.length];
    for (int i = 0; i < magnitude.length; i++) in[i] = (byte) magnitude[i];
    DERWriter writer = DERWriter.getInstance();
    byte[] out = new byte[0x20];
    writer.init(out, (short) 0);
    writer.writePositiveInteger(in, (short) 0, (short) in.length);
    return Arrays.copyOf(out, writer.getOffset());
  }

  private static Object field(Object target, String name) throws Exception {
    Field field = target.getClass().getDeclaredField(name);
    field.setAccessible(true);
    return field.get(target);
  }

  private static void resetSingletons() throws Exception {
    for (String name : new String[] {"instance", "nestedInstance"}) {
      Field field = DERWriter.class.getDeclaredField(name);
      field.setAccessible(true);
      field.set(null, null);
    }
  }
}
