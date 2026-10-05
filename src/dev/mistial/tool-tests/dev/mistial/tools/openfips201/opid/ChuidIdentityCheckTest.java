/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.opid;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import dev.mistial.tools.openfips201.common.HexUtil;
import java.io.ByteArrayOutputStream;
import org.junit.jupiter.api.Test;

class ChuidIdentityCheckTest {
  private static final Opid OPID = Opid.parseCanonical("12341234567890122");
  private static final byte[] EXPIRATION = HexUtil.parse("3230333031323331");

  @Test
  void acceptsMatchingChuidWithAndWithoutWrapper() {
    byte[] value = chuid(OpidIdentifiers.fascNBytes(OPID), OpidIdentifiers.guidBytes(OPID), true);
    assertDoesNotThrow(() -> ChuidIdentityCheck.verify(value, OPID));
    assertDoesNotThrow(() -> ChuidIdentityCheck.verify(tlv(0x53, value), OPID));
  }

  @Test
  void rejectsMismatchedIdentifiers() {
    Opid other = Opid.of(OPID.iin, OPID.e + 1);
    byte[] wrongFascN =
        chuid(OpidIdentifiers.fascNBytes(other), OpidIdentifiers.guidBytes(OPID), true);
    byte[] wrongGuid =
        chuid(OpidIdentifiers.fascNBytes(OPID), OpidIdentifiers.guidBytes(other), true);
    assertThrows(IllegalArgumentException.class, () -> ChuidIdentityCheck.verify(wrongFascN, OPID));
    assertThrows(IllegalArgumentException.class, () -> ChuidIdentityCheck.verify(wrongGuid, OPID));
  }

  @Test
  void requiresPersonAssociationSix() throws Exception {
    FascN derived = OpidIdentifiers.fascN(OPID);
    assertEquals(6, derived.personAssociation);
    JsonObject root = OpidVectors.load("opid-invalid.json");
    int count = 0;
    for (JsonElement element : root.getAsJsonArray("chuidPoa")) {
      int poa = element.getAsJsonObject().get("poa").getAsInt();
      FascN other =
          new FascN(
              derived.agencyCode,
              derived.systemCode,
              derived.credentialNumber,
              derived.credentialSeries,
              derived.individualCredentialIssue,
              derived.personIdentifier,
              derived.organizationalCategory,
              derived.organizationalIdentifier,
              poa);
      byte[] value = chuid(FascNCodec.encode(other), OpidIdentifiers.guidBytes(OPID), true);
      assertThrows(
          IllegalArgumentException.class,
          () -> ChuidIdentityCheck.verify(value, OPID),
          "poa " + poa);
      count++;
    }
    assertTrue(count >= 3);
  }

  @Test
  void rejectsGuidInMixedEndianOrder() {
    byte[] guid = OpidIdentifiers.guidBytes(OPID);
    byte[] swapped = guid.clone();
    swapped[0] = guid[3];
    swapped[1] = guid[2];
    swapped[2] = guid[1];
    swapped[3] = guid[0];
    swapped[4] = guid[5];
    swapped[5] = guid[4];
    swapped[6] = guid[7];
    swapped[7] = guid[6];
    byte[] value = chuid(OpidIdentifiers.fascNBytes(OPID), swapped, true);
    assertThrows(IllegalArgumentException.class, () -> ChuidIdentityCheck.verify(value, OPID));
  }

  @Test
  void rejectsMissingDuplicateOrMalformedElements() {
    byte[] fascN = OpidIdentifiers.fascNBytes(OPID);
    byte[] guid = OpidIdentifiers.guidBytes(OPID);
    byte[] noGuid = concat(tlv(0x30, fascN), tlv(0x35, EXPIRATION));
    byte[] noFascN = concat(tlv(0x34, guid), tlv(0x35, EXPIRATION));
    byte[] duplicate = concat(tlv(0x30, fascN), tlv(0x34, guid), tlv(0x34, guid));
    byte[] shortGuid = concat(tlv(0x30, fascN), tlv(0x34, new byte[15]));
    byte[] truncated = concat(tlv(0x30, fascN), HexUtil.parse("3410"));
    byte[] badFascN = fascN.clone();
    badFascN[24] ^= 1;
    byte[] corrupted = chuid(badFascN, guid, false);
    byte[] trailing = concat(tlv(0x53, chuid(fascN, guid, false)), new byte[] {0});
    for (byte[] value :
        new byte[][] {noGuid, noFascN, duplicate, shortGuid, truncated, corrupted, trailing}) {
      assertThrows(IllegalArgumentException.class, () -> ChuidIdentityCheck.verify(value, OPID));
    }
    assertThrows(
        IllegalArgumentException.class, () -> ChuidIdentityCheck.verify(new byte[0], OPID));
  }

  private static byte[] chuid(byte[] fascN, byte[] guid, boolean withTrailer) {
    byte[] body = concat(tlv(0x30, fascN), tlv(0x34, guid), tlv(0x35, EXPIRATION));
    return withTrailer ? concat(body, tlv(0x3E, new byte[0]), tlv(0xFE, new byte[0])) : body;
  }

  private static byte[] tlv(int tag, byte[] value) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(tag);
    if (value.length > 0x7F) {
      out.write(0x81);
    }
    out.write(value.length);
    out.write(value, 0, value.length);
    return out.toByteArray();
  }

  private static byte[] concat(byte[]... parts) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (byte[] part : parts) {
      out.write(part, 0, part.length);
    }
    return out.toByteArray();
  }
}
