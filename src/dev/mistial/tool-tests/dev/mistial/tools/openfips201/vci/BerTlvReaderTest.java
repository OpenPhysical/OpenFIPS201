package dev.mistial.tools.openfips201.vci;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class BerTlvReaderTest {
  @Test
  void readsShortAndExtendedLengths() {
    BerTlvReader.Tlv shortTlv = BerTlvReader.read(new byte[] {(byte) 0x53, 0x02, 0x11, 0x22}, 0);
    assertEquals(0x53, shortTlv.tag);
    assertEquals(2, shortTlv.valueOffset);
    assertEquals(2, shortTlv.length);
    assertEquals(4, shortTlv.nextOffset);

    byte[] length81 = new byte[132];
    length81[0] = 0x70;
    length81[1] = (byte) 0x81;
    length81[2] = (byte) 0x81;
    BerTlvReader.Tlv tlv81 = BerTlvReader.read(length81, 0);
    assertEquals(0x70, tlv81.tag);
    assertEquals(3, tlv81.valueOffset);
    assertEquals(129, tlv81.length);

    byte[] length82 = new byte[261];
    length82[0] = (byte) 0x7F;
    length82[1] = 0x21;
    length82[2] = (byte) 0x82;
    length82[3] = 0x01;
    length82[4] = 0x00;
    BerTlvReader.Tlv tlv82 = BerTlvReader.read(length82, 0);
    assertEquals(0x7F21, tlv82.tag);
    assertEquals(5, tlv82.valueOffset);
    assertEquals(256, tlv82.length);
  }

  @Test
  void rejectsTruncatedOrUnsupportedEncodings() {
    assertThrows(IllegalArgumentException.class, () -> BerTlvReader.read(new byte[] {0x53}, 0));
    assertThrows(
        IllegalArgumentException.class, () -> BerTlvReader.read(new byte[] {0x53, (byte) 0x81}, 0));
    assertThrows(
        IllegalArgumentException.class,
        () -> BerTlvReader.read(new byte[] {0x53, (byte) 0x82, 0x01}, 0));
    assertThrows(
        IllegalArgumentException.class, () -> BerTlvReader.read(new byte[] {0x53, (byte) 0x80}, 0));
    assertThrows(
        IllegalArgumentException.class, () -> BerTlvReader.read(new byte[] {0x53, 0x02, 0x01}, 0));
  }

  @Test
  void locatesByTag() {
    byte[] data = new byte[] {0x53, 0x01, 0x00, (byte) 0x7F, 0x21, 0x01, 0x7A};
    BerTlvReader.Tlv found = BerTlvReader.locate(data, 0, 0x7F21);
    assertEquals(3, found.tagOffset);
    assertEquals(6, found.valueOffset);
    assertEquals(1, found.length);
    assertNull(BerTlvReader.locate(data, 0, 0x70));
  }

  @Test
  void readsThreeBytePivObjectTags() {
    BerTlvReader.Tlv tlv = BerTlvReader.read(new byte[] {0x5F, (byte) 0xC1, 0x22, 0x01, 0x7F}, 0);
    assertEquals(0x5FC122, tlv.tag);
    assertEquals(4, tlv.valueOffset);
    assertEquals(1, tlv.length);
    assertEquals(5, tlv.nextOffset);
  }
}
