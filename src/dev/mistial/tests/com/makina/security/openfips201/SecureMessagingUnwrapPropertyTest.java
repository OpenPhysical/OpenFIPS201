package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import apdu4j.core.BIBO;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.AESKey;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.JavaCardEngine;

/**
 * Differential property test for the protected-command unwrap of {@link
 * PIV#unwrapSecureMessagingCommand}.
 *
 * <p>Seeded protected commands are built under a synthetic session (all-zero session keys, zero
 * MCV, encryption counter 1), then mutated structurally and at the byte level, split into random
 * ISO/IEC 7816-4 command chains ('1C' then '0C'), and unwrapped. Each outcome is compared with an
 * independent reference model of SP 800-73-5 Part 2 Sections 4.2.2 through 4.2.4:
 *
 * <ul>
 *   <li>the data field is an optional '87' (padding-content indicator '01' followed by a non-empty
 *       whole number of AES blocks), an optional '97 01 00', then exactly one '8E 08' that ends the
 *       data field; tags are single bytes and lengths use the shortest BER form;
 *   <li>the C-MAC is the first eight octets of AES-CMAC(SK_MAC, MCV || padded header || data
 *       objects before '8E');
 *   <li>the plaintext carries ISO/IEC 7816-4 padding of one through sixteen octets confined to the
 *       last block.
 * </ul>
 *
 * <p>Section 4.2.7 fixes the SW processing status of a failed exchange: "'69 87' - Expected secure
 * messaging data objects are missing" and "'69 88' - Secure messaging data objects are incorrect".
 * The applet contract is that '69 87' is returned only when the data objects parse and '8E' is
 * absent, every other unwrap failure (including a reassembled command larger than the
 * protected-command buffer) is '69 88', no other status escapes, and Section 4.3 session-key
 * destruction follows every failure.
 */
class SecureMessagingUnwrapPropertyTest {
  private static final long SEED = 0x534D_5557_5250L;
  private static final int CASES = 6000;
  private static final int MAX_FRAME = 255;
  private static final int SW_MISSING = 0x6987;
  private static final int SW_INCORRECT = 0x6988;
  private static final byte TAG_ENCRYPTED = (byte) 0x87;
  private static final byte TAG_LE = (byte) 0x97;
  private static final byte TAG_MAC = (byte) 0x8E;
  private static final byte[] INSTRUCTIONS = {
    (byte) 0xCB, (byte) 0xDB, (byte) 0x87, (byte) 0x20, (byte) 0x24, (byte) 0x2C, (byte) 0x47
  };
  private static final byte[] UNKNOWN_TAGS = {
    (byte) 0x85, (byte) 0x86, (byte) 0x8F, (byte) 0x96, (byte) 0x99, (byte) 0x00, (byte) 0xFF
  };
  private static final byte[] OPENFIPS201_AID_BYTES = hex("A000000308000010000100");
  private static final AID OPENFIPS201_AID =
      new AID(OPENFIPS201_AID_BYTES, (short) 0, (byte) OPENFIPS201_AID_BYTES.length);

  private JavaCardEngine engine;
  private BIBO session;

  @BeforeEach
  void setUpCard() throws Exception {
    engine = JavaCardEngine.create();
    try (AutoCloseable ignored = enterEngineContext()) {
      PIVCrypto.terminate();
      PIVCrypto.init();
    }
    engine.installApplet(OPENFIPS201_AID, OpenFIPS201.class, new byte[0]);
    session = engine.connect();
    ResponseAPDU select =
        new ResponseAPDU(
            session.transceive(new CommandAPDU(0, 0xA4, 4, 0, OPENFIPS201_AID_BYTES).getBytes()));
    assertEquals(0x9000, select.getSW(), "SELECT");
  }

  @AfterEach
  void tearDownCard() {
    if (session != null) session.close();
  }

  @Test
  void unwrapAgreesWithReferenceModel() throws Exception {
    int accepted = 0;
    int missing = 0;
    int incorrect = 0;
    int chained = 0;
    try (AutoCloseable ignored = enterEngineContext()) {
      Applet applet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(applet, "piv").get(applet);
      Object sm = field(piv, "secureMessaging").get(piv);
      int capacity = ((byte[]) field(piv, "smCommand").get(piv)).length - ISO7816.OFFSET_CDATA;
      Method unwrap =
          method(
              piv.getClass(),
              "unwrapSecureMessagingCommand",
              byte[].class,
              short.class,
              short.class);
      Method clearCommand = method(piv.getClass(), "clearSecureMessagingCommand");
      Method establish = method(sm.getClass(), "markEstablished", boolean.class);
      Method setKeys =
          method(sm.getClass(), "setSessionKeys", byte[].class, short.class, short.class);

      for (int i = 0; i < CASES; i++) {
        Random random = caseRandom(i);
        byte[] header = {
          INSTRUCTIONS[random.nextInt(INSTRUCTIONS.length)],
          (byte) random.nextInt(256),
          (byte) random.nextInt(256)
        };
        byte[] body = mutatedBody(random, header, capacity);
        if (random.nextInt(8) == 0)
          header[1 + random.nextInt(2)] ^= (byte) (1 << random.nextInt(8));
        Object expected = reference(header, body, capacity);
        List<byte[]> frames = frames(random, header, body);
        String label = "case " + i + " header " + hexString(header) + " body " + hexString(body);

        setKeys.invoke(sm, new byte[keyLength() * 4], (short) 0, PIVOpacity.SESSION_KEY_LENGTH);
        establish.invoke(sm, false);
        clearCommand.invoke(piv);
        if (frames.size() > 1) chained++;

        Object actual = null;
        for (int f = 0; f < frames.size(); f++) {
          byte[] frame = frames.get(f);
          boolean last = f == frames.size() - 1;
          try {
            short length =
                (short)
                    unwrap.invoke(
                        piv, frame, (short) ISO7816.OFFSET_CDATA, (short) (frame.length - 5));
            if (!last) fail(label + ": intermediate frame " + f + " completed the command");
            byte[] reassembled = (byte[]) field(piv, "smCommand").get(piv);
            actual = Arrays.copyOfRange(reassembled, 5, 5 + length);
            assertEquals((byte) 0x00, frame[ISO7816.OFFSET_CLA], label + ": unwrapped CLA");
            if (5 + length <= frame.length) {
              assertArrayEquals(
                  (byte[]) actual,
                  Arrays.copyOfRange(frame, 5, 5 + length),
                  label + ": plaintext copied to the APDU buffer");
            }
          } catch (InvocationTargetException failure) {
            if (!(failure.getCause() instanceof ISOException)) {
              throw new AssertionError(label + ": non-ISO exception", failure.getCause());
            }
            int sw = ((ISOException) failure.getCause()).getReason() & 0xFFFF;
            if (!last && sw == 0x9000) continue;
            actual = sw;
            break;
          }
        }

        if (expected instanceof byte[]) {
          assertTrue(
              actual instanceof byte[], label + ": expected plaintext, was " + swText(actual));
          assertArrayEquals((byte[]) expected, (byte[]) actual, label);
          assertEquals(true, method(sm.getClass(), "isEstablished").invoke(sm), label);
          assertArrayEquals(
              fullMac(header, body), (byte[]) field(sm, "commandMcv").get(sm), label + ": MCV");
          accepted++;
        } else {
          assertEquals(expected, actual, label + ": SW processing status");
          assertSessionDestroyed(piv, sm, label);
          if ((Integer) expected == SW_MISSING) missing++;
          else incorrect++;
        }
      }
    }
    assertTrue(accepted > CASES / 8, "valid commands: " + accepted);
    assertTrue(missing > CASES / 100, "commands without '8E': " + missing);
    assertTrue(incorrect > CASES / 4, "incorrect commands: " + incorrect);
    assertTrue(chained > CASES / 4, "chained commands: " + chained);
  }

  // ---------------------------------------------------------------------------------------------
  // Generator
  // ---------------------------------------------------------------------------------------------

  /** One protected data object as tag, encoded length field and value. */
  private static final class DataObject {
    final byte tag;
    byte[] length;
    byte[] value;

    DataObject(byte tag, byte[] value) {
      this.tag = tag;
      this.value = value;
      this.length = minimalLength(value.length);
    }

    byte[] encode() {
      return concat(new byte[] {tag}, length, value);
    }
  }

  /**
   * Returns the generator of case {@code n}. Adjacent {@code java.util.Random} seeds give
   * correlated first draws, so the case index is mixed with the SplitMix64 finalizer first.
   */
  private static Random caseRandom(long n) {
    long z = SEED + n * 0x9E3779B97F4A7C15L;
    z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
    z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
    return new Random(z ^ (z >>> 31));
  }

  private static byte[] mutatedBody(Random random, byte[] header, int capacity) throws Exception {
    int plaintextLength = random.nextInt(4) == 0 ? 0 : random.nextInt(capacity - 48);
    byte[] padded = iso7816Padded(randomBytes(random, plaintextLength));
    if (random.nextInt(6) == 0) corruptPadding(random, padded);

    List<DataObject> objects = new ArrayList<>();
    if (plaintextLength > 0 || random.nextBoolean()) {
      byte[] ciphertext = aesCbc(Cipher.ENCRYPT_MODE, commandIv(), padded);
      objects.add(new DataObject(TAG_ENCRYPTED, concat(new byte[] {0x01}, ciphertext)));
    }
    if (random.nextInt(3) == 0) objects.add(new DataObject(TAG_LE, new byte[] {0x00}));

    boolean macPresent = true;
    boolean macLast = true;
    int macLength = 8;
    int structural = random.nextInt(3) == 0 ? 1 + random.nextInt(3) : 0;
    for (int m = 0; m < structural; m++) {
      switch (random.nextInt(12)) {
        case 0: // Non-minimal BER length on a present object.
          if (!objects.isEmpty()) {
            DataObject target = objects.get(random.nextInt(objects.size()));
            target.length = longFormLength(target.value.length, random);
          }
          break;
        case 1: // Wrong padding-content indicator.
          for (DataObject object : objects) {
            if (object.tag == TAG_ENCRYPTED) object.value[0] = (byte) (2 + random.nextInt(254));
          }
          break;
        case 2: // Ciphertext that is not a whole number of blocks.
          for (DataObject object : objects) {
            if (object.tag == TAG_ENCRYPTED) {
              int delta = 1 + random.nextInt(15);
              object.value =
                  random.nextBoolean() && object.value.length > delta
                      ? Arrays.copyOf(object.value, object.value.length - delta)
                      : concat(object.value, randomBytes(random, delta));
              object.length = minimalLength(object.value.length);
            }
          }
          break;
        case 3: // '87' shorter than an indicator and one block.
          objects.add(
              0,
              new DataObject(
                  TAG_ENCRYPTED,
                  concat(new byte[] {0x01}, randomBytes(random, random.nextInt(16)))));
          break;
        case 4: // Duplicate an object.
          if (!objects.isEmpty()) {
            DataObject source = objects.get(random.nextInt(objects.size()));
            objects.add(
                random.nextInt(objects.size() + 1),
                new DataObject(source.tag, source.value.clone()));
          }
          break;
        case 5: // Reorder the objects.
          if (objects.size() > 1) objects.add(objects.remove(0));
          break;
        case 6: // Unknown object.
          objects.add(
              random.nextInt(objects.size() + 1),
              new DataObject(
                  UNKNOWN_TAGS[random.nextInt(UNKNOWN_TAGS.length)],
                  randomBytes(random, random.nextInt(20))));
          break;
        case 7: // Malformed '97'.
          objects.add(
              new DataObject(
                  TAG_LE,
                  random.nextBoolean()
                      ? randomBytes(random, random.nextInt(2) * 2)
                      : new byte[] {(byte) (1 + random.nextInt(255))}));
          break;
        case 8:
          macPresent = false;
          break;
        case 9:
          macLength = random.nextBoolean() ? 4 : 16;
          break;
        case 10:
          macLast = false;
          break;
        default: // Wrong padding inside an otherwise valid '87'.
          for (DataObject object : objects) {
            if (object.tag == TAG_ENCRYPTED
                && object.value.length > 16
                && (object.value.length - 1) % 16 == 0) {
              byte[] plain = aesCbc(Cipher.DECRYPT_MODE, commandIv(), tail(object.value));
              corruptPadding(random, plain);
              object.value =
                  concat(new byte[] {0x01}, aesCbc(Cipher.ENCRYPT_MODE, commandIv(), plain));
            }
          }
          break;
      }
    }

    ByteArrayOutputStream body = new ByteArrayOutputStream();
    for (DataObject object : objects) body.write(object.encode());
    byte[] authenticated = body.toByteArray();
    if (macPresent) {
      byte[] mac = Arrays.copyOf(cmac(header, authenticated, authenticated.length), macLength);
      body.write(concat(new byte[] {TAG_MAC, (byte) macLength}, mac));
      if (!macLast) body.write(new DataObject(TAG_LE, new byte[] {0x00}).encode());
    }
    return mutateBytes(random, body.toByteArray());
  }

  private static byte[] mutateBytes(Random random, byte[] body) {
    int raw = random.nextInt(4) == 0 ? 1 + random.nextInt(2) : 0;
    for (int m = 0; m < raw; m++) {
      switch (random.nextInt(6)) {
        case 0:
          body = Arrays.copyOf(body, random.nextInt(body.length + 1));
          break;
        case 1:
          if (body.length > 0) body[random.nextInt(body.length)] ^= (byte) (1 << random.nextInt(8));
          break;
        case 2: // Bit flip in the trailing '8E' object.
          if (body.length > 0) {
            body[body.length - 1 - random.nextInt(Math.min(10, body.length))] ^=
                (byte) (1 << random.nextInt(8));
          }
          break;
        case 3: // Rewrite a length octet at an object boundary.
          if (body.length > 1) body[1] = (byte) random.nextInt(256);
          break;
        case 4:
          body = concat(body, randomBytes(random, 1 + random.nextInt(4)));
          break;
        default:
          if (body.length > 0) {
            int at = random.nextInt(body.length);
            body =
                random.nextBoolean()
                    ? concat(Arrays.copyOf(body, at), Arrays.copyOfRange(body, at + 1, body.length))
                    : concat(
                        Arrays.copyOf(body, at),
                        new byte[] {(byte) random.nextInt(256)},
                        Arrays.copyOfRange(body, at, body.length));
          }
          break;
      }
    }
    return body;
  }

  private static void corruptPadding(Random random, byte[] padded) {
    int last = padded.length - 1;
    switch (random.nextInt(4)) {
      case 0: // No delimiter in the final block.
        Arrays.fill(padded, padded.length - 16, padded.length, (byte) 0x00);
        break;
      case 1: // Non-zero octet after the delimiter.
        padded[last] = (byte) (1 + random.nextInt(255));
        if (padded[last] == (byte) 0x80) padded[last] = 0x01;
        break;
      case 2: // Delimiter followed by a full zero block: more than sixteen padding octets.
        if (padded.length >= 32) {
          Arrays.fill(padded, padded.length - 16, padded.length, (byte) 0x00);
          padded[padded.length - 17] = (byte) 0x80;
        }
        break;
      default:
        padded[random.nextInt(padded.length)] ^= (byte) (1 << random.nextInt(8));
        break;
    }
  }

  /** Splits the body into a random ISO/IEC 7816-4 command chain of short APDU frames. */
  private static List<byte[]> frames(Random random, byte[] header, byte[] body) {
    int minimum = (body.length + MAX_FRAME - 1) / MAX_FRAME;
    int count = Math.max(Math.max(1, minimum), random.nextInt(3) == 0 ? 2 + random.nextInt(3) : 1);
    List<byte[]> frames = new ArrayList<>();
    int offset = 0;
    for (int f = 0; f < count; f++) {
      int remaining = body.length - offset;
      int length = remaining;
      if (f < count - 1) {
        int lower = Math.max(0, remaining - (count - f - 1) * MAX_FRAME);
        int upper = Math.min(MAX_FRAME, remaining);
        length = lower + random.nextInt(upper - lower + 1);
      }
      byte[] frame = new byte[5 + length];
      frame[ISO7816.OFFSET_CLA] = f == count - 1 ? (byte) 0x0C : (byte) 0x1C;
      frame[ISO7816.OFFSET_INS] = header[0];
      frame[ISO7816.OFFSET_P1] = header[1];
      frame[ISO7816.OFFSET_P2] = header[2];
      frame[ISO7816.OFFSET_LC] = (byte) length;
      System.arraycopy(body, offset, frame, 5, length);
      offset += length;
      frames.add(frame);
    }
    return frames;
  }

  // ---------------------------------------------------------------------------------------------
  // Reference model
  // ---------------------------------------------------------------------------------------------

  /** Returns the expected plaintext, or the expected Section 4.2.7 status as an Integer. */
  private static Object reference(byte[] header, byte[] body, int capacity) throws Exception {
    if (body.length > capacity) return SW_INCORRECT;
    int cursor = 0;
    int end = body.length;
    int encrypted = -1;
    int encryptedLength = 0;
    int mac = -1;
    byte expectedTag = TAG_ENCRYPTED;
    while (cursor < end) {
      byte tag = body[cursor];
      int[] tlv = referenceHeader(body, cursor, end);
      if (tlv == null || tlv[0] + tlv[1] > end) return SW_INCORRECT;
      int valueOffset = tlv[0];
      int length = tlv[1];
      int next = valueOffset + length;
      if (tag == TAG_ENCRYPTED) {
        if (expectedTag != TAG_ENCRYPTED || length < 17 || body[valueOffset] != 0x01) {
          return SW_INCORRECT;
        }
        if ((length - 1) % 16 != 0) return SW_INCORRECT;
        encrypted = valueOffset + 1;
        encryptedLength = length - 1;
        expectedTag = TAG_LE;
      } else if (tag == TAG_LE) {
        if (expectedTag == TAG_MAC || length != 1 || body[valueOffset] != 0x00) {
          return SW_INCORRECT;
        }
        expectedTag = TAG_MAC;
      } else if (tag == TAG_MAC) {
        if (mac != -1 || length != 8 || next != end) return SW_INCORRECT;
        mac = cursor;
        expectedTag = 0;
      } else {
        return SW_INCORRECT;
      }
      cursor = next;
    }
    if (mac == -1) return SW_MISSING;

    byte[] expectedMac = cmac(header, body, mac);
    if (!Arrays.equals(
        Arrays.copyOf(expectedMac, 8), Arrays.copyOfRange(body, mac + 2, mac + 10))) {
      return SW_INCORRECT;
    }
    if (encrypted == -1) return new byte[0];
    byte[] padded =
        aesCbc(
            Cipher.DECRYPT_MODE,
            commandIv(),
            Arrays.copyOfRange(body, encrypted, encrypted + encryptedLength));
    for (int i = padded.length - 1; i >= padded.length - 16; i--) {
      if (padded[i] == (byte) 0x80) return Arrays.copyOf(padded, i);
      if (padded[i] != 0) return SW_INCORRECT;
    }
    return SW_INCORRECT;
  }

  /**
   * Single-octet tag header with a shortest-form definite length of at most two subsequent octets
   * (0 to 0x7FFF); returns {value offset, value length} or null.
   */
  private static int[] referenceHeader(byte[] data, int offset, int end) {
    if (offset + 1 >= end) return null;
    int first = data[offset + 1] & 0xFF;
    if (first < 0x80) return new int[] {offset + 2, first};
    if (first == 0x81) {
      if (offset + 2 >= end) return null;
      int length = data[offset + 2] & 0xFF;
      return length < 0x80 ? null : new int[] {offset + 3, length};
    }
    if (first == 0x82) {
      if (offset + 3 >= end) return null;
      int length = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
      return length < 0x100 || length > 0x7FFF ? null : new int[] {offset + 4, length};
    }
    return null;
  }

  private static byte[] fullMac(byte[] header, byte[] body) throws Exception {
    int mac = body.length - 10;
    return cmac(header, body, mac);
  }

  /** AES-CMAC(SK_MAC, zero MCV || '0C' INS P1 P2 '80' 00..00 || data[0, length)). */
  private static byte[] cmac(byte[] header, byte[] data, int length) {
    byte[] input = new byte[32 + length];
    input[16] = (byte) 0x0C;
    System.arraycopy(header, 0, input, 17, 3);
    input[20] = (byte) 0x80;
    System.arraycopy(data, 0, input, 32, length);
    CMac cmac = new CMac(AESEngine.newInstance());
    cmac.init(new KeyParameter(new byte[keyLength()]));
    cmac.update(input, 0, input.length);
    byte[] mac = new byte[16];
    cmac.doFinal(mac, 0);
    return mac;
  }

  /** Command IV: AES(SK_ENC, encryption counter 1), SP 800-73-5 Part 2 Section 4.2.2. */
  private static byte[] commandIv() throws Exception {
    byte[] counter = new byte[16];
    counter[15] = 1;
    Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[keyLength()], "AES"));
    return cipher.doFinal(counter);
  }

  private static byte[] aesCbc(int mode, byte[] iv, byte[] data) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
    cipher.init(mode, new SecretKeySpec(new byte[keyLength()], "AES"), new IvParameterSpec(iv));
    return cipher.doFinal(data);
  }

  private static int keyLength() {
    return "CS7".equalsIgnoreCase(System.getProperty("vci.suite", "CS2")) ? 32 : 16;
  }

  // ---------------------------------------------------------------------------------------------
  // Session checks and reflection
  // ---------------------------------------------------------------------------------------------

  private static void assertSessionDestroyed(Object piv, Object sm, String label) throws Exception {
    assertEquals(false, method(sm.getClass(), "isEstablished").invoke(sm), label);
    for (String keyName : new String[] {"skCfrm", "skMac", "skEnc", "skRmac"}) {
      assertTrue(!((AESKey) field(sm, keyName).get(sm)).isInitialized(), label + " " + keyName);
    }
    for (String bufferName : new String[] {"scratch", "smCommand", "smResponse"}) {
      assertTrue(allZero((byte[]) field(piv, bufferName).get(piv)), label + " " + bufferName);
    }
    for (String name : new String[] {"commandMcv", "encCounter", "commandStreamBlock"}) {
      assertTrue(allZero((byte[]) field(sm, name).get(sm)), label + " " + name);
    }
  }

  private static boolean allZero(byte[] buffer) {
    int combined = 0;
    for (byte value : buffer) combined |= value;
    return combined == 0;
  }

  private AutoCloseable enterEngineContext() throws Exception {
    Method asCurrent = engine.getClass().getMethod("asCurrent");
    asCurrent.setAccessible(true);
    return (AutoCloseable) asCurrent.invoke(engine);
  }

  private static Applet unwrapApplet(Applet appletProxy) throws Exception {
    for (Field proxyField : appletProxy.getClass().getDeclaredFields()) {
      if (!InvocationHandler.class.isAssignableFrom(proxyField.getType())) continue;
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

  private static Field field(Object target, String name) throws Exception {
    Field field = target.getClass().getDeclaredField(name);
    field.setAccessible(true);
    return field;
  }

  private static Method method(Class<?> target, String name, Class<?>... parameterTypes)
      throws Exception {
    Method method = target.getDeclaredMethod(name, parameterTypes);
    method.setAccessible(true);
    return method;
  }

  // ---------------------------------------------------------------------------------------------
  // Byte helpers
  // ---------------------------------------------------------------------------------------------

  private static byte[] minimalLength(int length) {
    if (length < 0x80) return new byte[] {(byte) length};
    if (length < 0x100) return new byte[] {(byte) 0x81, (byte) length};
    return new byte[] {(byte) 0x82, (byte) (length >> 8), (byte) length};
  }

  private static byte[] longFormLength(int length, Random random) {
    if (length < 0x80 && random.nextBoolean()) return new byte[] {(byte) 0x81, (byte) length};
    if (length < 0x100) return new byte[] {(byte) 0x82, (byte) (length >> 8), (byte) length};
    return new byte[] {(byte) 0x83, 0x00, (byte) (length >> 8), (byte) length};
  }

  private static byte[] iso7816Padded(byte[] plaintext) {
    byte[] padded = new byte[plaintext.length + 16 - plaintext.length % 16];
    System.arraycopy(plaintext, 0, padded, 0, plaintext.length);
    padded[plaintext.length] = (byte) 0x80;
    return padded;
  }

  private static byte[] tail(byte[] value) {
    return Arrays.copyOfRange(value, 1, value.length);
  }

  private static byte[] randomBytes(Random random, int length) {
    byte[] bytes = new byte[length];
    random.nextBytes(bytes);
    return bytes;
  }

  private static byte[] concat(byte[]... parts) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (byte[] part : parts) out.write(part, 0, part.length);
    return out.toByteArray();
  }

  private static String swText(Object outcome) {
    return outcome instanceof Integer ? String.format("%04X", (Integer) outcome) : "plaintext";
  }

  private static String hexString(byte[] data) {
    StringBuilder text = new StringBuilder();
    for (byte value : data) text.append(String.format("%02X", value));
    return text.toString();
  }

  private static byte[] hex(String value) {
    byte[] bytes = new byte[value.length() / 2];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = (byte) Integer.parseInt(value.substring(2 * i, 2 * i + 2), 16);
    }
    return bytes;
  }
}
