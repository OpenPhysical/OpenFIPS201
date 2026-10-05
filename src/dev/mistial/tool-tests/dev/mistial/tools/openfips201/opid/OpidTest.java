/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.opid;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import dev.mistial.tools.openfips201.common.HexUtil;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class OpidTest {
  @Test
  void luhnVectors() throws Exception {
    JsonObject root = OpidVectors.load("luhn.json");
    int count = 0;
    for (JsonElement element : root.getAsJsonArray("vectors")) {
      JsonObject vector = element.getAsJsonObject();
      String payload = vector.get("payload").getAsString();
      int check = vector.get("check").getAsInt();
      assertEquals(check, Luhn.checkDigit(payload), payload);
      assertTrue(Luhn.isValid(payload + check), payload);
      assertFalse(Luhn.isValid(payload + ((check + 1) % 10)), payload);
      count++;
    }
    assertTrue(count >= 4);
    assertEquals(3, Luhn.checkDigit("12349123412345678"));
    assertEquals(1, Luhn.checkDigit("411111111111111"));
    assertEquals(4, Luhn.checkDigit("555555555555444"));
    assertEquals(3, Luhn.checkDigit("7992739871"));
  }

  @Test
  void luhnRejectsNonAsciiDigits() {
    assertThrows(IllegalArgumentException.class, () -> Luhn.checkDigit("12a4"));
    assertThrows(IllegalArgumentException.class, () -> Luhn.checkDigit("12٣"));
    assertThrows(IllegalArgumentException.class, () -> Luhn.checkDigit(""));
    assertThrows(IllegalArgumentException.class, () -> Luhn.isValid("7"));
    assertThrows(IllegalArgumentException.class, () -> Luhn.isValid("1234 5"));
  }

  @Test
  void validVectorsDeriveEveryIdentifier() throws Exception {
    JsonObject root = OpidVectors.load("opid-valid.json");
    int count = 0;
    for (JsonElement element : root.getAsJsonArray("vectors")) {
      JsonObject v = element.getAsJsonObject();
      String printed = v.get("printed").getAsString();
      Opid opid = Opid.of(v.get("iin").getAsInt(), Long.parseLong(v.get("e").getAsString()));

      assertEquals(printed, opid.toPrinted());
      assertEquals(printed, opid.toString());
      assertEquals(v.get("display").getAsString(), opid.toDisplay());
      assertEquals(v.get("check").getAsInt(), opid.check);
      assertEquals(opid, Opid.parseCanonical(printed));
      assertEquals(opid, Opid.parse(printed));
      assertEquals(opid, Opid.parse(opid.toDisplay()));
      assertEquals(opid.hashCode(), Opid.parse(opid.toDisplay()).hashCode());
      assertEquals(Luhn.checkDigit(printed.substring(0, 16)), opid.check);

      assertEquals(v.get("guid").getAsString(), OpidIdentifiers.guidString(opid));
      assertEquals(
          v.get("guidBytesHex").getAsString(), HexUtil.format(OpidIdentifiers.guidBytes(opid)));
      assertEquals(v.get("uuidOid").getAsString(), OpidIdentifiers.uuidOid(opid));
      assertEquals(6, v.get("poa").getAsInt());
      assertEquals(
          v.get("fascnHex").getAsString(), HexUtil.format(OpidIdentifiers.fascNBytes(opid)));
      assertEquals(
          v.get("cccHex").getAsString(), HexUtil.format(OpidIdentifiers.cccCardIdentifier(opid)));
      assertEquals(23, OpidIdentifiers.cccCardIdentifier(opid).length);
      assertEquals(
          OpidIdentifiers.fascN(opid),
          FascNCodec.decode(HexUtil.parse(v.get("fascnHex").getAsString())));
      count++;
    }
    assertTrue(count >= 4);
  }

  @Test
  void invalidVectorsAreRejectedByBothParsers() throws Exception {
    JsonObject root = OpidVectors.load("opid-invalid.json");
    for (JsonElement element : root.getAsJsonArray("vectors")) {
      String input = element.getAsJsonObject().get("input").getAsString();
      assertThrows(IllegalArgumentException.class, () -> Opid.parseCanonical(input), input);
      assertThrows(IllegalArgumentException.class, () -> Opid.parse(input), input);
    }
    for (JsonElement element : root.getAsJsonArray("fields")) {
      JsonObject v = element.getAsJsonObject();
      assertThrows(
          IllegalArgumentException.class,
          () -> Opid.of(v.get("iin").getAsInt(), v.get("e").getAsLong()),
          v.toString());
    }
  }

  @Test
  void strictParserRefusesSeparators() {
    Opid opid = Opid.parseCanonical("12341234567890122");
    assertEquals(1234, opid.iin);
    assertEquals(123456789012L, opid.e);
    assertEquals(2, opid.check);
    assertEquals("1234 1234 5678 90122", opid.toDisplay());
    assertThrows(IllegalArgumentException.class, () -> Opid.parseCanonical("1234 1234 5678 90122"));
    assertThrows(IllegalArgumentException.class, () -> Opid.parseCanonical("1234-1234-5678-90122"));
    assertThrows(IllegalArgumentException.class, () -> Opid.parseCanonical(null));
  }

  @Test
  void lenientParserStripsSpacesAndDashesOnly() {
    Opid expected = Opid.parseCanonical("12341234567890122");
    assertEquals(expected, Opid.parse("1234 1234 5678 90122"));
    assertEquals(expected, Opid.parse("1234-1234-5678-90122"));
    assertEquals(expected, Opid.parse(" 1234-1234 5678-90122 "));
    assertThrows(IllegalArgumentException.class, () -> Opid.parse("1234_1234567890122"));
    assertThrows(IllegalArgumentException.class, () -> Opid.parse("1234\t1234567890122"));
    assertThrows(IllegalArgumentException.class, () -> Opid.parse("123491234123456783"));
  }

  @Test
  void guidIsBigEndianRfc9562UuidV8() {
    Opid opid = Opid.parseCanonical("12341234567890122");
    assertEquals("12341234-5678-8901-8022-4F504E504859", OpidIdentifiers.guidString(opid));
    byte[] guid = OpidIdentifiers.guidBytes(opid);
    assertArrayEquals(HexUtil.parse("123412345678890180224F504E504859"), guid);
    // time_low is not byte-swapped (the Microsoft mixed-endian layout would start 34 12 34 12).
    assertEquals(0x12, guid[0]);
    assertEquals(0x34, guid[1]);
    assertEquals(8, (guid[6] & 0xF0) >>> 4, "RFC 9562 version nibble");
    assertEquals(0x80, guid[8] & 0xF0, "variant nibble 8");
    UUID uuid =
        new UUID(
            new BigInteger(1, Arrays.copyOfRange(guid, 0, 8)).longValue(),
            new BigInteger(1, Arrays.copyOfRange(guid, 8, 16)).longValue());
    assertEquals(8, uuid.version());
    assertEquals(2, uuid.variant());
    assertEquals(uuid.toString().toUpperCase(), OpidIdentifiers.guidString(opid));
    assertEquals("2.25." + new BigInteger(1, guid), OpidIdentifiers.uuidOid(opid));
  }

  @Test
  void fascNDerivationFollowsPivIProfile() {
    FascN fascN = OpidIdentifiers.fascN(Opid.parseCanonical("12341234567890122"));
    assertEquals(9999, fascN.agencyCode);
    assertEquals(9999, fascN.systemCode);
    assertEquals(999999, fascN.credentialNumber);
    assertEquals(3, fascN.credentialSeries);
    assertEquals(4, fascN.individualCredentialIssue);
    assertEquals(1256789012L, fascN.personIdentifier);
    assertEquals(3, fascN.organizationalCategory);
    assertEquals(1234, fascN.organizationalIdentifier);
    assertEquals(6, fascN.personAssociation);
  }

  @Test
  void ofComputesCheckAndValidatesRanges() {
    Opid opid = Opid.of(1, 5);
    assertEquals("0001000000000005", opid.toPrinted().substring(0, 16));
    assertEquals(7, opid.check);
    assertTrue(Luhn.isValid(opid.toPrinted()));
    assertThrows(IllegalArgumentException.class, () -> Opid.of(1, Opid.E_MODULUS));
    assertThrows(IllegalArgumentException.class, () -> Opid.of(10000, 0));
    assertNotEquals(opid, Opid.of(2, 5));
  }
}
