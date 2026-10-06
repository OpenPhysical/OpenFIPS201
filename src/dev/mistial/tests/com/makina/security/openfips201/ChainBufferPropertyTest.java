package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Random;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * Differential property tests for {@link ChainBuffer} command-chain reassembly.
 *
 * <p>Seeded random sequences of command frames are fed to {@link ChainBuffer#processIncomingAPDU}
 * and {@link ChainBuffer#processIncomingObject}, and every outcome is compared with an independent
 * reference model of ISO/IEC 7816-4 Section 5.3.3 command chaining: "All CLA bytes of the commands
 * shall be the same, except for bit b5" and "All INS P1 P2 bytes of the commands shall be the
 * same". Random fragmentations of random payloads must reassemble exactly. Malformed sequences must
 * produce only the documented statuses:
 *
 * <ul>
 *   <li>'68 83' for an APDU-chain link with another header ("the last command of the chain is
 *       expected");
 *   <li>'67 00' for reassembly overrun, and for an object chain whose final frame does not complete
 *       the declared length;
 *   <li>'69 82' for an object-chain frame whose transport protection differs from the first frame;
 *   <li>'69 85' when an APDU chain is offered while another chain operation is active.
 * </ul>
 *
 * <p>Every failure discards the logical command; an object is published only by its exact final
 * frame, and a later valid chain always succeeds.
 */
class ChainBufferPropertyTest {
  private static final long SEED = 0x4348_4149_4E42L;
  private static final int SEQUENCES = 1500;
  private static final int OPERATIONS = 24;
  private static final int OBJECT_CAPACITY = 600;
  private static final byte[][] HEADERS = {
    {0x00, (byte) 0x87, 0x11, (byte) 0x9A},
    {0x00, (byte) 0x87, 0x07, (byte) 0x9A},
    {0x00, (byte) 0x47, 0x00, (byte) 0x9A},
    {(byte) 0x0C, (byte) 0x87, 0x11, (byte) 0x9A},
    {(byte) 0x80, (byte) 0x87, 0x11, (byte) 0x9A},
  };
  private static final byte[] PROTECTIONS = {
    ChainBuffer.PROTECTION_PLAIN, ChainBuffer.PROTECTION_PIV_SM, ChainBuffer.PROTECTION_SCP
  };
  private static final int OK = 0x9000;
  private static final int RETURNED = -1;

  @Test
  void apduChainReassemblyAgreesWithReferenceModel() {
    try (MockedStatic<JCSystem> system = mockTransientStorage()) {
      int completed = 0;
      int rejected = 0;
      for (int s = 0; s < SEQUENCES; s++) {
        Random random = caseRandom(s);
        ChainBuffer chain = new ChainBuffer();
        byte[] out = new byte[16 + random.nextInt(300)];
        short outOffset = (short) random.nextInt(5);
        ApduModel model = new ApduModel(out.length - outOffset);
        // A dominant header keeps most chains on one logical command.
        byte[] main = HEADERS[random.nextInt(HEADERS.length)];
        for (int op = 0; op < OPERATIONS; op++) {
          String label = "sequence " + s + " operation " + op;
          if (random.nextInt(20) == 0) {
            byte[] response = new byte[8];
            chain.setOutgoing(response, (short) 0, (short) response.length, false);
            model.outgoing();
            continue;
          }
          byte[] header = random.nextInt(6) == 0 ? HEADERS[random.nextInt(HEADERS.length)] : main;
          boolean chaining = random.nextInt(3) != 0;
          int length = random.nextInt(8) == 0 ? 0 : random.nextInt(random.nextBoolean() ? 32 : 160);
          byte[] apdu = frame(random, header, chaining, length);
          if (random.nextBoolean()) {
            chain.checkIncomingAPDU(apdu);
            model.check(apdu);
          }

          int expected = model.process(apdu, length);
          int actual;
          short returned = 0;
          try {
            returned = chain.processIncomingAPDU(apdu, (short) 5, (short) length, out, outOffset);
            actual = RETURNED;
          } catch (ISOException e) {
            actual = e.getReason() & 0xFFFF;
          }
          assertEquals(expected, actual, label);
          if (actual == RETURNED) {
            assertEquals(model.returned, returned, label);
            if (returned > 0 || !chaining) {
              assertArrayEquals(
                  model.completed,
                  Arrays.copyOfRange(out, outOffset, outOffset + returned),
                  label + ": reassembled data");
              completed++;
            }
          } else {
            rejected++;
          }
          assertEquals(model.active, chain.isIncomingApduActive(), label + ": chain state");
        }

        // No sequence leaves state that blocks the next logical command.
        chain.abort();
        byte[] single = frame(random, main, false, 1 + random.nextInt(16));
        int length = single.length - 5;
        assertEquals(
            length,
            chain.processIncomingAPDU(single, (short) 5, (short) length, out, (short) 0),
            "sequence " + s + ": recovery");
        assertArrayEquals(Arrays.copyOfRange(single, 5, single.length), Arrays.copyOf(out, length));
      }
      assertTrue(completed > SEQUENCES, "completed commands: " + completed);
      assertTrue(rejected > SEQUENCES, "rejected frames: " + rejected);
    }
  }

  @Test
  void objectChainReassemblyAgreesWithReferenceModel() {
    try (MockedStatic<JCSystem> system = mockTransientStorage()) {
      int published = 0;
      int rejected = 0;
      for (int s = 0; s < SEQUENCES; s++) {
        Random random = caseRandom(SEQUENCES + s);
        ChainBuffer chain = new ChainBuffer();
        PIVDataObject object = dataObject();
        ObjectModel model = new ObjectModel();
        byte[] main = HEADERS[random.nextInt(HEADERS.length)];
        byte protection = PROTECTIONS[random.nextInt(PROTECTIONS.length)];
        for (int op = 0; op < OPERATIONS; op++) {
          String label = "sequence " + s + " operation " + op;
          int choice = random.nextInt(16);
          if (choice == 0 || (choice < 4 && !model.active)) {
            short length =
                (short) (1 + random.nextInt(random.nextBoolean() ? 64 : OBJECT_CAPACITY));
            chain.setIncomingObject(object, length);
            model.begin(length);
            continue;
          }
          if (choice == 4) {
            // A command-data chain offered while the object chain is active.
            byte[] apdu = frame(random, main, false, 1);
            int expected = model.apduOffered();
            int actual;
            try {
              chain.processIncomingAPDU(apdu, (short) 5, (short) 1, new byte[8], (short) 0);
              actual = RETURNED;
            } catch (ISOException e) {
              actual = e.getReason() & 0xFFFF;
            }
            assertEquals(expected, actual, label);
            assertPublished(model, object, label);
            continue;
          }

          byte[] header = random.nextInt(8) == 0 ? HEADERS[random.nextInt(HEADERS.length)] : main;
          byte frameProtection =
              random.nextInt(10) == 0
                  ? PROTECTIONS[random.nextInt(PROTECTIONS.length)]
                  : protection;
          boolean chaining = random.nextInt(4) != 0;
          int length = frameLength(random, model);
          byte[] apdu = frame(random, header, chaining, length);
          int expected = model.process(apdu, length, frameProtection);
          int actual;
          try {
            chain.processIncomingObject(apdu, (short) 5, (short) length, frameProtection);
            actual = RETURNED;
          } catch (ISOException e) {
            actual = e.getReason() & 0xFFFF;
          }
          assertEquals(expected, actual, label);
          if (actual != OK && actual != RETURNED) rejected++;
          if (model.justPublished) published++;
          assertPublished(model, object, label);
        }

        // A complete chain after any sequence publishes exactly its payload.
        byte[] payload = new byte[1 + random.nextInt(OBJECT_CAPACITY)];
        random.nextBytes(payload);
        chain.setIncomingObject(object, (short) payload.length);
        int offset = 0;
        while (offset < payload.length) {
          int length = Math.min(payload.length - offset, 1 + random.nextInt(255));
          boolean last = offset + length == payload.length;
          byte[] apdu = frame(random, main, !last, 0);
          apdu = Arrays.copyOf(apdu, 5 + length);
          System.arraycopy(payload, offset, apdu, 5, length);
          apdu[ISO7816.OFFSET_LC] = (byte) length;
          int status;
          try {
            chain.processIncomingObject(apdu, (short) 5, (short) length, protection);
            status = RETURNED;
          } catch (ISOException e) {
            status = e.getReason() & 0xFFFF;
          }
          assertEquals(OK, status, "sequence " + s + ": recovery frame");
          offset += length;
        }
        assertEquals(payload.length, object.getLength(), "sequence " + s + ": recovery length");
        assertArrayEquals(payload, Arrays.copyOf(object.content, payload.length));
      }
      assertTrue(published > SEQUENCES / 4, "published objects: " + published);
      assertTrue(rejected > SEQUENCES, "rejected frames: " + rejected);
    }
  }

  /** Reference model of {@link ChainBuffer#processIncomingAPDU} chaining state. */
  private static final class ApduModel {
    final int room;
    boolean active;
    boolean outgoingActive;
    byte[] header;
    final ByteArrayOutputStream data = new ByteArrayOutputStream();
    int returned;
    byte[] completed;

    ApduModel(int room) {
      this.room = room;
    }

    void outgoing() {
      reset();
      outgoingActive = true;
    }

    void check(byte[] apdu) {
      if (active && !sameCommand(header, apdu)) reset();
    }

    int process(byte[] apdu, int length) {
      if (outgoingActive) {
        reset();
        return ISO7816.SW_CONDITIONS_NOT_SATISFIED & 0xFFFF;
      }
      boolean last = (apdu[ISO7816.OFFSET_CLA] & 0x10) == 0;
      if (active && !sameCommand(header, apdu)) {
        reset();
        return ISO7816.SW_LAST_COMMAND_EXPECTED & 0xFFFF;
      }
      if (data.size() + length > room) {
        reset();
        return ISO7816.SW_WRONG_LENGTH & 0xFFFF;
      }
      data.write(apdu, 5, length);
      if (last) {
        completed = data.toByteArray();
        returned = completed.length;
        reset();
        return RETURNED;
      }
      if (!active) {
        active = true;
        header = apdu.clone();
      }
      returned = 0;
      return RETURNED;
    }

    void reset() {
      active = false;
      outgoingActive = false;
      header = null;
      data.reset();
    }
  }

  /** Reference model of {@link ChainBuffer#processIncomingObject} and object publication. */
  private static final class ObjectModel {
    boolean active;
    int declared;
    int remaining;
    byte[] header;
    byte protection;
    final ByteArrayOutputStream data = new ByteArrayOutputStream();
    byte[] published;
    boolean justPublished;

    void begin(int length) {
      reset();
      active = true;
      declared = length;
      remaining = length;
    }

    int apduOffered() {
      if (!active) return RETURNED;
      reset();
      return ISO7816.SW_CONDITIONS_NOT_SATISFIED & 0xFFFF;
    }

    int process(byte[] apdu, int length, byte frameProtection) {
      justPublished = false;
      if (!active) return RETURNED;
      boolean first = remaining == declared;
      if (first) {
        header = apdu.clone();
        protection = frameProtection;
      }
      if (!first && !sameCommand(header, apdu)) {
        reset();
        return RETURNED;
      }
      if (!first && protection != frameProtection) {
        reset();
        return ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED & 0xFFFF;
      }
      if ((apdu[ISO7816.OFFSET_CLA] & 0x10) != 0) {
        if (length == 0) return OK;
        if (length >= remaining) {
          reset();
          return ISO7816.SW_WRONG_LENGTH & 0xFFFF;
        }
        data.write(apdu, 5, length);
        remaining -= length;
        return OK;
      }
      if (length == 0 || length != remaining) {
        reset();
        return ISO7816.SW_WRONG_LENGTH & 0xFFFF;
      }
      data.write(apdu, 5, length);
      published = data.toByteArray();
      justPublished = true;
      reset();
      return OK;
    }

    void reset() {
      active = false;
      header = null;
      data.reset();
    }
  }

  /**
   * Returns the generator of sequence {@code n}. Adjacent {@code java.util.Random} seeds give
   * correlated first draws, so the index is mixed with the SplitMix64 finalizer first.
   */
  private static Random caseRandom(long n) {
    long z = SEED + n * 0x9E3779B97F4A7C15L;
    z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
    z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
    return new Random(z ^ (z >>> 31));
  }

  private static int frameLength(Random random, ObjectModel model) {
    switch (random.nextInt(7)) {
      case 0:
        return 0;
      case 1: // Exactly the remaining length.
      case 2:
        return model.active ? Math.min(255, model.remaining) : random.nextInt(32);
      case 3: // Overrun.
        return model.active ? Math.min(255, model.remaining + random.nextInt(3)) : 1;
      default:
        return random.nextInt(random.nextBoolean() ? 32 : 200);
    }
  }

  private static boolean sameCommand(byte[] recorded, byte[] apdu) {
    return (recorded[ISO7816.OFFSET_CLA] & 0xEF) == (apdu[ISO7816.OFFSET_CLA] & 0xEF)
        && recorded[ISO7816.OFFSET_INS] == apdu[ISO7816.OFFSET_INS]
        && recorded[ISO7816.OFFSET_P1] == apdu[ISO7816.OFFSET_P1]
        && recorded[ISO7816.OFFSET_P2] == apdu[ISO7816.OFFSET_P2];
  }

  private static void assertPublished(ObjectModel model, PIVDataObject object, String label) {
    if (model.published == null) {
      assertEquals(0, object.getLength(), label + ": nothing published");
      return;
    }
    assertEquals(model.published.length, object.getLength(), label + ": published length");
    assertArrayEquals(
        model.published,
        Arrays.copyOf(object.content, model.published.length),
        label + ": published content");
  }

  private static byte[] frame(Random random, byte[] header, boolean chaining, int length) {
    byte[] apdu = new byte[5 + length];
    System.arraycopy(header, 0, apdu, 0, 4);
    if (chaining) apdu[ISO7816.OFFSET_CLA] |= 0x10;
    apdu[ISO7816.OFFSET_LC] = (byte) length;
    for (int i = 5; i < apdu.length; i++) apdu[i] = (byte) random.nextInt(256);
    return apdu;
  }

  /** Returns a data object with a fixed capacity for the largest generated declared length. */
  private static PIVDataObject dataObject() {
    return new PIVDataObject(
        new byte[] {0x01},
        (short) 0,
        (short) 1,
        PIVObject.ACCESS_MODE_ALWAYS,
        PIVObject.ACCESS_MODE_ALWAYS,
        (byte) 0x9B,
        (short) OBJECT_CAPACITY);
  }

  private static MockedStatic<JCSystem> mockTransientStorage() {
    MockedStatic<JCSystem> system = Mockito.mockStatic(JCSystem.class);
    system
        .when(() -> JCSystem.makeTransientObjectArray(Mockito.anyShort(), Mockito.anyByte()))
        .thenAnswer(call -> new Object[(short) call.getArgument(0)]);
    system
        .when(() -> JCSystem.makeTransientShortArray(Mockito.anyShort(), Mockito.anyByte()))
        .thenAnswer(call -> new short[(short) call.getArgument(0)]);
    return system;
  }
}
