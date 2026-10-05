package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.util.Arrays;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Test;

/**
 * ISO/IEC 7816-4 Sections 5.3.3 and 5.3.4 command and response chaining at the card edge, and the
 * PUT DATA / GET DATA data-field rules of SP 800-73-5 Part 2 Sections 3.1 and 3.3.1.
 */
class OpenFIPS201CommandChainingConformanceTest extends OpenFIPS201TestSupport {
  private static final int SW_COMMAND_CHAINING_NOT_SUPPORTED = 0x6884;
  private static final byte[] NEW_PIN = hex("3234363831333537");
  // A proprietary object outside the SP 800-73-5 Part 1 Table 3 namespace.
  private static final byte[] OBJECT_ID = hex("5FFF10");
  private static final byte[] OBJECT_TAG_LIST = hex("5C035FFF10");

  @Test
  void chainingBitIsRejectedWithoutExecutingNonChainingCommands() {
    assertSw(0x9000, selectApplet(), "SELECT before chaining-bit checks");
    int retries = assert63cxAndGetRetries(transmit(0x00, 0x20, 0x00, 0x80), "PIN status");

    assertSw(
        SW_COMMAND_CHAINING_NOT_SUPPORTED,
        transmit(0x10, 0x20, 0x00, 0x80, StandardCardProfile.PIN),
        "VERIFY does not support command chaining");
    assertEquals(
        retries,
        assert63cxAndGetRetries(transmit(0x00, 0x20, 0x00, 0x80), "PIN status"),
        "A rejected VERIFY fragment neither verifies the PIN nor consumes a retry");

    assertSw(
        SW_COMMAND_CHAINING_NOT_SUPPORTED,
        transmit(0x10, 0x2C, 0x00, 0x80, concat(StandardCardProfile.PUK, NEW_PIN)),
        "RESET RETRY COUNTER does not support command chaining");
    assertSw(
        SW_COMMAND_CHAINING_NOT_SUPPORTED,
        transmit(0x10, 0x24, 0x00, 0x80, concat(StandardCardProfile.PIN, NEW_PIN)),
        "CHANGE REFERENCE DATA does not support command chaining without OCC");
    assertSw(
        0x9000,
        transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN),
        "The PIN is unchanged by the rejected fragments");

    assertSw(
        SW_COMMAND_CHAINING_NOT_SUPPORTED,
        transmit(new CommandAPDU(0x10, 0xCB, 0x3F, 0xFF, hex("5C017E"))),
        "GET DATA does not support command chaining");
  }

  @Test
  void selectWithShortNeContinuesTheApplicationPropertyTemplate() {
    ResponseAPDU full = selectApplet();
    assertSw(0x9000, full, "SELECT with Le=00");
    byte[] template = full.getData();
    assertTrue(template.length > 8, "the APT exceeds the short Ne used below");

    ResponseAPDU first =
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 8));
    assertEquals(0x6100 | (template.length - 8), first.getSW(), "SELECT continues with 61 XX");
    assertEquals(8, first.getData().length);
    assertArrayEquals(template, collectResponse(first, "GET RESPONSE completes the APT"));
  }

  @Test
  void getResponseRequiresItsHeaderAndAPendingResponse() {
    assertSw(
        0x6985,
        transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00, 256)),
        "GET RESPONSE with nothing pending");

    ResponseAPDU first =
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 8));
    assertEquals(0x6100, first.getSW() & 0xFF00, "SELECT leaves a pending response");
    assertSw(
        0x6A86,
        transmit(new CommandAPDU(0x00, 0xC0, 0x12, 0x34, 256)),
        "ISO/IEC 7816-4 Table 120: P1-P2 '0000' (any other value is RFU)");
    assertSw(
        0x6985,
        transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00, 256)),
        "A rejected GET RESPONSE abandons the pending response");

    first = transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 8));
    assertEquals(0x6100, first.getSW() & 0xFF00, "SELECT leaves a pending response");
    assertSw(
        SW_COMMAND_CHAINING_NOT_SUPPORTED,
        transmit(new CommandAPDU(0x10, 0xC0, 0x00, 0x00, 256)),
        "GET RESPONSE does not support command chaining");
    assertSw(
        0x6985,
        transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00, 256)),
        "A rejected GET RESPONSE abandons the pending response");
  }

  /**
   * GET RESPONSE continues a response only within the class family of the command that started it.
   * GP SCP protects commands only, so a plaintext GET RESPONSE ('00' or '80') continues any
   * response on the plaintext path; a GP SCP GET RESPONSE continues only a response started under
   * GP SCP.
   */
  @Test
  void getResponseIsBoundToTheClassFamilyOfTheInitiatingCommand() {
    createObject(OBJECT_ID, 0x0040);
    byte[] object = hex("530A00112233445566778899");
    byte[] template = selectApplet().getData();
    ResponseAPDU first =
        transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 8));
    assertEquals(0x6100, first.getSW() & 0xFF00, "SELECT leaves a pending response");
    ResponseAPDU rest = transmit(new CommandAPDU(0x80, 0xC0, 0x00, 0x00, 256));
    assertSw(0x9000, rest, "A proprietary-class plaintext GET RESPONSE continues the response");
    assertArrayEquals(template, concat(first.getData(), rest.getData()));

    withMockedScp(
        () -> {
          ResponseAPDU plain =
              transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, OPENFIPS201_AID_BYTES, 8));
          assertEquals(0x6100, plain.getSW() & 0xFF00, "SELECT leaves a pending response");
          assertSw(
              0x6985,
              transmit(new CommandAPDU(0x84, 0xC0, 0x00, 0x00, 256)),
              "A GP SCP GET RESPONSE does not continue a plaintext response");
          assertSw(
              0x6985,
              transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00, 256)),
              "The mismatched GET RESPONSE abandons the pending response");

          assertSw(0x9000, selectApplet(), "SELECT before PUT DATA");
          assertSw(0x9000, putData(0x84, concat(OBJECT_TAG_LIST, object)), "seed");

          ResponseAPDU scpFirst =
              transmit(new CommandAPDU(0x84, 0xCB, 0x3F, 0xFF, OBJECT_TAG_LIST, 4));
          assertEquals(0x6100, scpFirst.getSW() & 0xFF00, "GET DATA leaves a pending response");
          ResponseAPDU scpRest = transmit(new CommandAPDU(0x84, 0xC0, 0x00, 0x00, 256));
          assertSw(0x9000, scpRest, "A GP SCP GET RESPONSE continues a GP SCP response");
          assertArrayEquals(object, concat(scpFirst.getData(), scpRest.getData()));

          scpFirst = transmit(new CommandAPDU(0x84, 0xCB, 0x3F, 0xFF, OBJECT_TAG_LIST, 4));
          assertEquals(0x6100, scpFirst.getSW() & 0xFF00, "GET DATA leaves a pending response");
          assertArrayEquals(
              object,
              concat(
                  scpFirst.getData(),
                  collectResponse(
                      transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00, 256)),
                      "A plaintext GET RESPONSE continues the unprotected response")));
        });
  }

  @Test
  void emptyIntermediatePutDataFrameDoesNotBreakTheChain() {
    createObject(OBJECT_ID, 0x0200);
    byte[] value = new byte[256];
    for (int i = 0; i < value.length; i++) value[i] = (byte) i;
    byte[] field = concat(OBJECT_TAG_LIST, hex("53820100"), value);
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before chained PUT DATA");
          assertSw(0x9000, putData(0x94, Arrays.copyOfRange(field, 0, 60)), "first frame");
          assertSw(0x9000, transmit(0x94, 0xDB, 0x3F, 0xFF), "empty intermediate frame");
          assertSw(0x9000, putData(0x94, Arrays.copyOfRange(field, 60, 160)), "middle frame");
          assertSw(0x9000, putData(0x84, Arrays.copyOfRange(field, 160, field.length)), "last");
        });
    assertArrayEquals(
        concat(hex("53820100"), value),
        collectResponse(transmit(0x00, 0xCB, 0x3F, 0xFF, OBJECT_TAG_LIST, 256), "GET DATA"),
        "the chained object is committed intact");
  }

  /**
   * PUT DATA requires the shortest BER length coding (ISO/IEC 7816-4 Section 6.3 "recommends to use
   * the shortest possible coding of the length field"; the applet requires it). A long form that a
   * shorter form could encode is malformed command data, '6A 80', and stores nothing.
   */
  @Test
  void putDataRejectsNonMinimalLengthEncodings() {
    createObject(OBJECT_ID, 0x0200);
    byte[] value = new byte[0x80];
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before PUT DATA");
          assertSw(0x9000, putData(0x84, concat(OBJECT_TAG_LIST, hex("5303010203"))), "seed");
          assertSw(
              0x6A80,
              putData(0x84, concat(OBJECT_TAG_LIST, hex("538103010203"))),
              "'81' long form for a length below 0x80");
          assertSw(
              0x6A80,
              putData(0x84, concat(OBJECT_TAG_LIST, hex("53820003010203"))),
              "'82' long form for a length below 0x80");
          assertSw(
              0x6A80,
              putData(0x84, concat(OBJECT_TAG_LIST, hex("53820080"), value)),
              "'82' long form for a length below 0x100");
          assertSw(
              0x6A80,
              putData(0x84, hex("5C81035FFF105303010203")),
              "'81' long form for the tag list length");
        });
    assertArrayEquals(
        hex("5303010203"),
        collectResponse(transmit(0x00, 0xCB, 0x3F, 0xFF, OBJECT_TAG_LIST, 256), "GET DATA"),
        "rejected commands leave the object unchanged");
  }

  @Test
  void emptyPutDataObjectMustEndTheCommandData() {
    createObject(OBJECT_ID, 0x0040);
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before PUT DATA");
          assertSw(0x9000, putData(0x84, concat(OBJECT_TAG_LIST, hex("5303010203"))), "seed");
          // SP 800-73-5 Part 2 Table 10: the data field is the tag list and the '53' object only.
          assertSw(
              0x6700,
              putData(0x84, concat(OBJECT_TAG_LIST, hex("5300DEADBEEF"))),
              "trailing bytes after an empty object");
          assertSw(
              0x6700,
              putData(0x94, concat(OBJECT_TAG_LIST, hex("5300"))),
              "an empty object cannot announce further frames");
        });
    assertArrayEquals(
        hex("5303010203"),
        collectResponse(transmit(0x00, 0xCB, 0x3F, 0xFF, OBJECT_TAG_LIST, 256), "GET DATA"),
        "rejected commands leave the object unchanged");

    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before PUT DATA");
          assertSw(0x9000, putData(0x84, concat(OBJECT_TAG_LIST, hex("5300"))), "clear");
        });
    assertArrayEquals(
        hex("5300"),
        collectResponse(transmit(0x00, 0xCB, 0x3F, 0xFF, OBJECT_TAG_LIST, 256), "GET DATA"));
  }

  @Test
  void emptyBitGroupTemplateIsReturnedAsTemplate() {
    createObject(hex("7F61"), 0x0041);
    // SP 800-73-5 Part 1 Section 3.3.6, footnote 6: "A BIT Group Template with no BITs is encoded
    // as '7F 61 03 02 01 00'." Part 2 Section 3.1.2 returns it without a '53' wrapper.
    assertArrayEquals(
        hex("7F6103020100"),
        collectResponse(transmit(0x00, 0xCB, 0x3F, 0xFF, hex("5C027F61"), 256), "GET DATA 7F61"));
  }

  @Test
  void fipsProfileEnforcesTable8MinimumCapacities() {
    assumeTrue(Boolean.getBoolean("fips.mode"), "Table 8 capacities apply to the FIPS profile");
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before object creation");
          assertSw(
              0x6A80,
              transmit(0x84, 0xDB, 0xFF, 0xFF, createRequest(hex("5FC105"), 0x7F, 0x08, 1856)),
              "SP 800-73-5 Part 1 Table 8: 5FC105 holds at least 1857 bytes");
          assertSw(
              0x9000,
              transmit(0x84, 0xDB, 0xFF, 0xFF, createRequest(hex("5FC105"), 0x7F, 0x08, 1857)),
              "the Table 8 minimum is accepted");
        });
  }

  private void createObject(byte[] id, int capacity) {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectApplet(), "SELECT before object creation");
          assertSw(
              0x9000,
              transmit(0x84, 0xDB, 0xFF, 0xFF, createRequest(id, 0x7F, 0x7F, capacity)),
              "create object");
        });
  }

  private static byte[] createRequest(byte[] id, int contact, int contactless, int capacity) {
    return tlv(
        (byte) 0x64,
        concat(
            tlv((byte) 0x8B, id),
            new byte[] {
              (byte) 0x8C,
              0x01,
              (byte) contact,
              (byte) 0x8D,
              0x01,
              (byte) contactless,
              (byte) 0x91,
              0x01,
              StandardCardProfile.ADMIN_KEY_REF,
              (byte) 0x92,
              0x02,
              (byte) (capacity >> 8),
              (byte) capacity
            }));
  }

  private ResponseAPDU putData(int cla, byte[] data) {
    return transmit(cla, 0xDB, 0x3F, 0xFF, data);
  }
}
