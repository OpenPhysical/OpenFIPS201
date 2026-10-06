package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Test;

/**
 * Seeded corpus of mutated GET DATA and PUT DATA commands sent through the card edge.
 *
 * <p>Each case starts from a well-formed SP 800-73-5 Part 2 Section 3.1.2 GET DATA or Section 3.3.2
 * PUT DATA command and applies random class, parameter, Le, data-field and command-chaining
 * mutations. Every status word must be one the governing specifications define (see {@link
 * #isSpecifiedStatus}); in particular '6F 00' (no precise diagnosis) never escapes. After every
 * case a known-good GET DATA must return the object, unchanged unless the case was a complete,
 * accepted PUT DATA of a well-formed '53' object.
 */
class OpenFIPS201DataCommandCorpusTest extends OpenFIPS201TestSupport {
  private static final long SEED = 0x4344_4154_4143L;
  private static final int CASES = 1200;
  private static final byte[] OBJECT_ID = hex("5FFF10");
  private static final byte[] OBJECT_TAG_LIST = hex("5C035FFF10");
  private static final byte[][] TAG_LISTS = {
    OBJECT_TAG_LIST, hex("5C017E"), hex("5C027F61"), hex("5C035FC102"), hex("5C035FFF11")
  };
  private static final int[] CLASSES = {0x00, 0x10, 0x80, 0x84, 0x90, 0x94, 0x0C, 0x1C};

  @Test
  void mutatedDataCommandsReturnOnlySpecifiedStatusesAndKeepTheCardUsable() {
    createObject();
    Map<Integer, Integer> statuses = new TreeMap<>();
    int[] updates = new int[1];
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before the corpus");
          byte[] seed = hex("5303010203");
          assertSw(0x9000, putData(0x84, concat(OBJECT_TAG_LIST, seed)), "seed the object");
          byte[] current = seed;
          for (int i = 0; i < CASES; i++) {
            Random random = caseRandom(i);
            boolean put = random.nextBoolean();
            byte[] data = put ? putDataField(random) : getDataField(random);
            int cla = put ? (random.nextInt(4) == 0 ? 0x00 : 0x84) : 0x00;
            int p1p2 = 0x3FFF;
            int mutations = random.nextInt(3) == 0 ? 0 : 1 + random.nextInt(3);
            for (int m = 0; m < mutations; m++) {
              switch (random.nextInt(8)) {
                case 0:
                  cla = CLASSES[random.nextInt(CLASSES.length)];
                  break;
                case 1:
                  p1p2 =
                      random.nextBoolean()
                          ? random.nextInt(0x10000)
                          : 0x3FFF ^ (1 << random.nextInt(16));
                  break;
                default:
                  data = mutateData(random, data);
                  break;
              }
            }
            int ne =
                random.nextInt(3) == 0
                    ? 0
                    : (random.nextInt(4) == 0 ? 1 + random.nextInt(255) : 256);
            boolean chained = data.length > 255 || random.nextInt(4) == 0;
            boolean headerChanged = false;
            List<ResponseAPDU> responses = new ArrayList<>();
            int offset = 0;
            do {
              int length =
                  chained ? Math.min(data.length - offset, random.nextInt(256)) : data.length;
              boolean last = !chained || offset + length >= data.length;
              int frameCla = last ? cla & ~0x10 : cla | 0x10;
              int frameP1p2 = p1p2;
              if (chained && random.nextInt(12) == 0) {
                frameP1p2 ^= 1 << random.nextInt(16);
                headerChanged = true;
              }
              byte[] fragment = Arrays.copyOfRange(data, offset, offset + length);
              ResponseAPDU response =
                  transmit(
                      command(frameCla, put ? 0xDB : 0xCB, frameP1p2, fragment, last ? ne : 0));
              String label =
                  "case "
                      + i
                      + " CLA "
                      + Integer.toHexString(frameCla)
                      + " data "
                      + hexString(data);
              assertTrue(
                  isSpecifiedStatus(response.getSW()), label + " returned " + swHex(response));
              statuses.merge(response.getSW(), 1, Integer::sum);
              responses.add(response);
              offset += length;
              if (last || response.getSW() != 0x9000) break;
            } while (true);

            ResponseAPDU probe = transmit(0x00, 0xCB, 0x3F, 0xFF, OBJECT_TAG_LIST, 256);
            byte[] value = collectResponse(probe, "case " + i + ": known-good GET DATA");
            if (!Arrays.equals(current, value)) {
              assertTrue(put, "case " + i + ": GET DATA changed the object");
              assertTrue(
                  responses.get(responses.size() - 1).getSW() == 0x9000,
                  "case " + i + ": a rejected command changed the object");
              if (!headerChanged && startsWith(data, OBJECT_TAG_LIST)) {
                assertArrayEquals(
                    Arrays.copyOfRange(data, OBJECT_TAG_LIST.length, data.length),
                    value,
                    "case " + i + ": stored object");
              }
              assertTrue(isSingleObject(value), "case " + i + ": stored a malformed object");
              current = value;
              updates[0]++;
            }
          }
          assertSw(0x9000, putData(0x84, concat(OBJECT_TAG_LIST, seed)), "final PUT DATA");
        });
    assertArrayEquals(
        hex("5303010203"),
        collectResponse(transmit(0x00, 0xCB, 0x3F, 0xFF, OBJECT_TAG_LIST, 256), "final GET DATA"));
    assertSw(0x9000, transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN), "VERIFY");

    // The corpus must reach the success, rejection and chaining paths, not only early rejection.
    assertTrue(updates[0] > CASES / 50, "accepted PUT DATA updates: " + updates[0]);
    for (int sw : new int[] {0x9000, 0x6700, 0x6982, 0x6A80, 0x6A82, 0x6A86}) {
      assertTrue(statuses.getOrDefault(sw, 0) > 0, String.format("status %04X: %s", sw, statuses));
    }
  }

  /**
   * Status words defined for GET DATA and PUT DATA by SP 800-73-5 Part 2 Sections 3.1.2 and 3.3.2
   * ('6A 80', '6A 81', '6A 82', '6A 84', '69 82'), by Section 4.2.7 for a secure-messaging class
   * ('69 82', '69 87', '69 88'), and by ISO/IEC 7816-4 Section 5.6 Tables 5 and 6 for transport,
   * class, instruction, parameter and chaining errors. '6F 00' ("no precise diagnosis") is not in
   * the set: it is reported only for an unexpected applet fault.
   */
  private static boolean isSpecifiedStatus(int sw) {
    if ((sw & 0xFF00) == 0x6100) return true; // Response bytes still available.
    switch (sw) {
      case 0x9000:
      case 0x6700: // Wrong length.
      case 0x6882: // Secure messaging not supported.
      case 0x6883: // Last command of the chain expected.
      case 0x6884: // Command chaining not supported.
      case 0x6982: // Security status not satisfied.
      case 0x6985: // Conditions of use not satisfied.
      case 0x6987: // Expected secure messaging data objects missing.
      case 0x6988: // Incorrect secure messaging data objects.
      case 0x6A80: // Incorrect parameters in the command data field.
      case 0x6A81: // Function not supported.
      case 0x6A82: // File or application not found.
      case 0x6A84: // Not enough memory space in the file.
      case 0x6A86: // Incorrect parameters P1-P2.
      case 0x6A88: // Referenced data or reference data not found.
      case 0x6D00: // Instruction code not supported or invalid.
      case 0x6E00: // Class not supported.
        return true;
      default:
        return false;
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

  private static byte[] getDataField(Random random) {
    return TAG_LISTS[random.nextInt(TAG_LISTS.length)].clone();
  }

  private static byte[] putDataField(Random random) {
    byte[] value = new byte[random.nextInt(4) == 0 ? random.nextInt(300) : random.nextInt(40)];
    random.nextBytes(value);
    byte[] tagList =
        random.nextInt(4) == 0 ? TAG_LISTS[random.nextInt(TAG_LISTS.length)] : OBJECT_TAG_LIST;
    return concat(tagList, tlv((byte) 0x53, value));
  }

  private static byte[] mutateData(Random random, byte[] data) {
    switch (random.nextInt(8)) {
      case 0:
        return Arrays.copyOf(data, random.nextInt(data.length + 1));
      case 1:
        if (data.length > 0) data[random.nextInt(data.length)] ^= (byte) (1 << random.nextInt(8));
        return data;
      case 2: // A random length octet.
        if (data.length > 1)
          data[random.nextBoolean() ? 1 : Math.min(6, data.length - 1)] =
              (byte) random.nextInt(256);
        return data;
      case 3: // Non-minimal length on the tag list.
        if (data.length > 1 && (data[1] & 0x80) == 0) {
          return concat(
              Arrays.copyOf(data, 1),
              new byte[] {(byte) 0x81},
              Arrays.copyOfRange(data, 1, data.length));
        }
        return data;
      case 4:
        byte[] tail = new byte[1 + random.nextInt(4)];
        random.nextBytes(tail);
        return concat(data, tail);
      case 5: // Duplicate the tag list.
        return concat(Arrays.copyOf(data, Math.min(5, data.length)), data);
      case 6:
        if (random.nextBoolean()) return new byte[0];
        return nonMinimalObjectLength(data);
      default:
        if (data.length == 0) return data;
        int at = random.nextInt(data.length);
        return concat(Arrays.copyOf(data, at), Arrays.copyOfRange(data, at + 1, data.length));
    }
  }

  /** Re-encodes the length of a '53' object that follows a tag list in a longer BER form. */
  private static byte[] nonMinimalObjectLength(byte[] data) {
    if (data.length < 7 || data[5] != (byte) 0x53) return data;
    int first = data[6] & 0xFF;
    if (first < 0x80) {
      return concat(
          Arrays.copyOf(data, 6),
          new byte[] {(byte) 0x81},
          Arrays.copyOfRange(data, 6, data.length));
    }
    if (first == 0x81 && data.length > 7) {
      return concat(
          Arrays.copyOf(data, 6),
          new byte[] {(byte) 0x82, 0x00},
          Arrays.copyOfRange(data, 7, data.length));
    }
    return data;
  }

  private static CommandAPDU command(int cla, int ins, int p1p2, byte[] data, int ne) {
    int p1 = (p1p2 >> 8) & 0xFF;
    int p2 = p1p2 & 0xFF;
    if (data.length == 0)
      return ne == 0 ? new CommandAPDU(cla, ins, p1, p2) : new CommandAPDU(cla, ins, p1, p2, ne);
    return ne == 0
        ? new CommandAPDU(cla, ins, p1, p2, data)
        : new CommandAPDU(cla, ins, p1, p2, data, ne);
  }

  /** True when {@code value} is exactly one BER-TLV with tag '53' and a shortest-form length. */
  private static boolean isSingleObject(byte[] value) {
    if (value.length < 2 || value[0] != (byte) 0x53) return false;
    int first = value[1] & 0xFF;
    if (first < 0x80) return value.length == 2 + first;
    if (first == 0x81)
      return value.length >= 3
          && (value[2] & 0xFF) >= 0x80
          && value.length == 3 + (value[2] & 0xFF);
    if (first == 0x82 && value.length >= 4) {
      int length = ((value[2] & 0xFF) << 8) | (value[3] & 0xFF);
      return length >= 0x100 && value.length == 4 + length;
    }
    return false;
  }

  private static boolean startsWith(byte[] data, byte[] prefix) {
    return data.length >= prefix.length
        && Arrays.equals(Arrays.copyOf(data, prefix.length), prefix);
  }

  private static String hexString(byte[] data) {
    StringBuilder text = new StringBuilder();
    for (byte value : data) text.append(String.format("%02X", value));
    return text.toString();
  }

  private ResponseAPDU putData(int cla, byte[] data) {
    return transmit(cla, 0xDB, 0x3F, 0xFF, data);
  }

  private void createObject() {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before object creation");
          assertSw(
              0x9000,
              transmit(
                  0x84,
                  0xDB,
                  0xFF,
                  0xFF,
                  tlv(
                      (byte) 0x64,
                      concat(
                          tlv((byte) 0x8B, OBJECT_ID),
                          new byte[] {
                            (byte) 0x8C,
                            0x01,
                            0x7F,
                            (byte) 0x8D,
                            0x01,
                            0x7F,
                            (byte) 0x91,
                            0x01,
                            StandardCardProfile.ADMIN_KEY_REF,
                            (byte) 0x92,
                            0x02,
                            0x02,
                            0x00
                          }))),
              "create object");
        });
  }
}
