/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.mistial.tools.openfips201.common.HexUtil;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.junit.jupiter.api.Test;

class Pkcs11SigningKeyTest {
  @Test
  void derEncodesRawEcdsaSignature() throws Exception {
    byte[] raw =
        HexUtil.parse(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
                + "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");

    byte[] der = Pkcs11SigningKey.derEncodeEcdsa(raw, 32);
    ASN1Sequence sequence = ASN1Sequence.getInstance(der);

    assertArrayEquals(
        HexUtil.parse("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        fixed(((ASN1Integer) sequence.getObjectAt(0)).getPositiveValue().toByteArray(), 32));
    assertArrayEquals(
        HexUtil.parse("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"),
        fixed(((ASN1Integer) sequence.getObjectAt(1)).getPositiveValue().toByteArray(), 32));
  }

  @Test
  void rejectsUnexpectedRawEcdsaLength() {
    assertThrows(
        IllegalArgumentException.class,
        () -> Pkcs11SigningKey.derEncodeEcdsa(new byte[63], 32));
  }

  private static byte[] fixed(byte[] value, int length) {
    byte[] out = new byte[length];
    int copy = Math.min(value.length, length);
    System.arraycopy(value, value.length - copy, out, length - copy, copy);
    return out;
  }
}
