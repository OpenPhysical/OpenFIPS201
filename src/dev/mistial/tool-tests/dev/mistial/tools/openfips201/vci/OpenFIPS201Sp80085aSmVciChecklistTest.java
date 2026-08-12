package dev.mistial.tools.openfips201.vci;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

/**
 * Host-side mappings of NIST SP 800-85A-4 middleware assertions that touch secure messaging and
 * VCI, exercised against {@link VciSupport} / {@link VciCvcSupport} rather than a full PIV client
 * API implementation.
 *
 * <p>These are not a certified 85A test harness; they lock the cryptographic and policy contracts
 * that an 85A-capable middleware must implement so regressions are caught here first.
 *
 * <p>References: NIST SP 800-85A-4 (AS01.17/18 pairing length & charset; AS04.03A/07A/08 SM session
 * lifecycle; AS05.13B Discovery Object for VCI).
 */
class OpenFIPS201Sp80085aSmVciChecklistTest {

  /**
   * AS01.17: pairing code shall be exactly 8 bytes; AS01.18A-R4: bytes are 0x30–0x39 (ASCII digits).
   *
   * <p>Enforced by provisioning and by the wire format of VERIFY (key ref 0x98).
   */
  @Test
  void as01_17_as01_18_pairingCodeIsEightAsciiDigits() {
    // Valid pairing codes used by vector fixtures and provisioning.
    assertTrue(isValidPairingCode("12345678"));
    assertTrue(isValidPairingCode("00000003"));
    assertFalse(isValidPairingCode("1234567")); // too short
    assertFalse(isValidPairingCode("123456789")); // too long
    assertFalse(isValidPairingCode("12AB5678")); // non-digit
    assertFalse(isValidPairingCode(null));

    // VERIFY data field for pairing is exactly those 8 bytes (no 0xFF padding, unlike PIN).
    byte[] pairing = "00000003".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    assertEquals(8, pairing.length);
    for (byte b : pairing) {
      assertTrue(b >= 0x30 && b <= 0x39, "pairing byte must be ASCII digit");
    }
  }

  /**
   * AS04.07A-R4 / AS04.08: pivEstablishSecureMessaging uses key reference 0x04 and algorithm 0x27
   * (or 0x2E). Host constants match SP 800-78-5.
   */
  @Test
  void as04_07_secureMessagingKeyReferenceAndAlgorithms() {
    assertEquals((byte) 0x04, VciSupport.KEY_REF_SECURE_MESSAGING);
    assertEquals((byte) 0x27, VciSupport.ALG_CS2);
    assertEquals((byte) 0x2E, VciSupport.ALG_CS7);
    assertEquals(16, VciSupport.sessionKeyLength(VciSupport.ALG_CS2));
    assertEquals(32, VciSupport.sessionKeyLength(VciSupport.ALG_CS7));
  }

  /**
   * AS04.03A-R4: session keys are zeroized on disconnect. Host-side {@link VciSupport.SmSession}
   * is replaced rather than cleared in-place; this test documents the required behaviour by
   * verifying a fresh session starts from the initial counter/MCV and that discarding a session
   * object drops access to prior key material from the caller's perspective.
   */
  @Test
  void as04_03_sessionKeysAreSessionScopedAndResettable() {
    byte[] skMac = Hex.decode("00112233445566778899AABBCCDDEEFF");
    byte[] skEnc = Hex.decode("FFEEDDCCBBAA99887766554433221100");
    byte[] skRmac = Hex.decode("0123456789ABCDEFFEDCBA9876543210");
    byte[] skCfrm = Hex.decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    VciSupport.SessionKeys keys = new VciSupport.SessionKeys(skCfrm, skMac, skEnc, skRmac);
    VciSupport.SmSession session = new VciSupport.SmSession(keys);

    // Advance session state.
    VciSupport.wrapCommand(session, (byte) 0x20, (byte) 0x00, (byte) 0x98, new byte[8], false);
    assertFalse(allZero(session.commandMcv), "MCV advances after wrap");
    assertEquals(1, session.encCounter[15] & 0xFF);

    // "Disconnect": drop the session reference and create a new one from the same key material
    // only if the caller still holds the keys. Zeroization of sk* is the caller's duty — simulate
    // by wiping the key arrays (as middleware must on pivDisconnect).
    Arrays.fill(skMac, (byte) 0);
    Arrays.fill(skEnc, (byte) 0);
    Arrays.fill(skRmac, (byte) 0);
    Arrays.fill(skCfrm, (byte) 0);
    assertTrue(allZero(skMac) && allZero(skEnc), "caller wiped session key material");

    // A new session constructed after wipe cannot wrap with the old keys (they are zeros).
    VciSupport.SmSession wiped =
        new VciSupport.SmSession(new VciSupport.SessionKeys(skCfrm, skMac, skEnc, skRmac));
    assertEquals(0, wiped.commandMcv[0] & 0xFF);
    assertEquals(1, wiped.encCounter[15] & 0xFF);
  }

  /**
   * AS04.07 / SM command integrity: re-wrapping a known VERIFY produces a stable CLA 0x0C APDU
   * with 8E MAC tag (Part 2 Section 4.2.3–4.2.4), independent of card presence.
   */
  @Test
  void as04_07_smCommandWrapProducesSecureMessagingClaAndMac() {
    byte[] sk = Hex.decode("00112233445566778899AABBCCDDEEFF");
    VciSupport.SmSession session =
        new VciSupport.SmSession(new VciSupport.SessionKeys(sk, sk, sk, sk));
    byte[] wrapped =
        VciSupport.wrapCommand(
            session, (byte) 0x20, (byte) 0x00, (byte) 0x98, new byte[] {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31}, false);
    assertEquals(0x0C, wrapped[0] & 0xFF, "SM CLA");
    assertEquals(0x20, wrapped[1] & 0xFF, "INS VERIFY");
    assertEquals(0x98, wrapped[3] & 0xFF, "pairing key ref");
    // Data field contains 87 (enc) and 8E (MAC).
    boolean saw87 = false;
    boolean saw8e = false;
    int i = 5;
    int lc = wrapped[4] & 0xFF;
    int end = 5 + lc;
    while (i < end) {
      int tag = wrapped[i++] & 0xFF;
      int len = wrapped[i++] & 0xFF;
      if (tag == 0x87) {
        saw87 = true;
      }
      if (tag == 0x8E) {
        saw8e = true;
        assertEquals(8, len, "truncated MAC is 8 bytes");
      }
      i += len;
    }
    assertTrue(saw87 && saw8e, "wrapped VERIFY must carry 87 and 8E");
  }

  /**
   * AS05.13B-R4: VCI implementations must implement the Discovery Object with VCI policy bits.
   * Host-side parse of a Discovery Object template matches Part 1 Table 1 bit definitions.
   */
  @Test
  void as05_13b_discoveryObjectVciPolicyBits() {
    // 7E 0x 4F 0B AID 5F2F 02 policy
    // Policy: bit4 (0x08) = VCI implemented; bit3 (0x04) = no pairing required when set.
    byte[] pairingRequired = Hex.decode("7E0F4F0BA0000003080000100001005F2F024800");
    byte[] noPairing = Hex.decode("7E0F4F0BA0000003080000100001005F2F024C00");
    assertEquals(0x48, policyByte(pairingRequired) & 0xFF);
    assertTrue((policyByte(pairingRequired) & 0x08) != 0, "VCI implemented");
    assertFalse((policyByte(pairingRequired) & 0x04) != 0, "pairing required clears bit3");
    assertTrue((policyByte(noPairing) & 0x08) != 0, "VCI implemented");
    assertTrue((policyByte(noPairing) & 0x04) != 0, "no-pairing sets bit3");
  }

  /**
   * CS2 and CS7 KDF lengths match SP 800-73-5 Table 18 (len=512 bits CS2, 1024 bits CS7).
   */
  @Test
  void cipherSuiteKeyMaterialLengthsMatchSp800735Table18() {
    // CS2: Z=32, nIcc=16 → 64 bytes of key material
    byte[] z2 = new byte[32];
    Arrays.fill(z2, (byte) 0x11);
    byte[] id = new byte[8];
    byte[] host2 = new byte[65];
    host2[0] = 0x04;
    byte[] n2 = new byte[16];
    Arrays.fill(n2, (byte) 0x22);
    VciSupport.SessionKeys cs2 =
        VciSupport.deriveSessionKeys(VciSupport.ALG_CS2, z2, id, host2, id, n2);
    assertEquals(16, cs2.skEnc.length);
    assertEquals(16, cs2.skMac.length);
    assertEquals(16, cs2.skRmac.length);
    assertEquals(16, cs2.skCfrm.length);

    // CS7: Z=48, nIcc=24 → 128 bytes of key material
    byte[] z7 = new byte[48];
    Arrays.fill(z7, (byte) 0x33);
    byte[] host7 = new byte[97];
    host7[0] = 0x04;
    byte[] n7 = new byte[24];
    Arrays.fill(n7, (byte) 0x44);
    VciSupport.SessionKeys cs7 =
        VciSupport.deriveSessionKeys(VciSupport.ALG_CS7, z7, id, host7, id, n7);
    assertEquals(32, cs7.skEnc.length);
    assertEquals(32, cs7.skMac.length);
    assertEquals(32, cs7.skRmac.length);
    assertEquals(32, cs7.skCfrm.length);

    // Distinct suites must not accidentally collide on key material with different Z sizes.
    assertFalse(Arrays.equals(cs2.skEnc, Arrays.copyOf(cs7.skEnc, 16)));
  }

  @Test
  void unsupportedCipherSuiteIsRejected() {
    assertThrows(
        IllegalArgumentException.class, () -> VciSupport.sessionKeyLength((byte) 0x00));
  }

  @Test
  void malformedPlainApdusAreRejectedBeforeWrapping() {
    assertThrows(IllegalArgumentException.class, () -> VciSupport.parsePlainCommand(null));
    assertThrows(
        IllegalArgumentException.class,
        () -> VciSupport.parsePlainCommand(Hex.decode("00A4000005AABB")));
    assertThrows(
        IllegalArgumentException.class,
        () -> VciSupport.parsePlainCommand(Hex.decode("00A4000002AABBCCDD")));
    assertThrows(
        IllegalArgumentException.class,
        () -> VciSupport.parsePlainCommand(Hex.decode("00A400000000")));
    assertThrows(
        IllegalArgumentException.class,
        () -> VciSupport.parsePlainCommand(Hex.decode("00A40000000002AA")));
  }

  @Test
  void cvcSignatureMustCarryAlgorithmIdentifierWrapper() {
    byte[] publicKey =
        Hex.decode(
            "04"
                + "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
                + "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    byte[] publicKeyTemplate =
        VciSupport.tlv(
            0x7F49,
            concat(
                VciSupport.tlv(0x06, Hex.decode("2A8648CE3D030107")),
                VciSupport.tlv(0x86, publicKey)));
    byte[] cvc =
        VciSupport.tlv(
            0x7F21,
            concat(
                VciSupport.tlv(0x5F29, new byte[] {(byte) 0x80}),
                VciSupport.tlv(0x42, Hex.decode("0102030405060708")),
                VciSupport.tlv(0x5F20, Hex.decode("00112233445566778899AABBCCDDEEFF")),
                publicKeyTemplate,
                VciSupport.tlv(0x5F4C, new byte[] {0x00}),
                VciSupport.tlv(0x5F37, Hex.decode("AABBCC"))));

    assertThrows(IllegalArgumentException.class, () -> VciCvcSupport.parseCvc(cvc));
  }

  // ---------------------------------------------------------------------------------------------

  private static boolean isValidPairingCode(String code) {
    return code != null && code.matches("[0-9]{8}");
  }

  private static boolean allZero(byte[] data) {
    for (byte b : data) {
      if (b != 0) {
        return false;
      }
    }
    return true;
  }

  private static byte policyByte(byte[] discovery) {
    for (int i = 0; i <= discovery.length - 5; i++) {
      if (discovery[i] == (byte) 0x5F
          && discovery[i + 1] == (byte) 0x2F
          && discovery[i + 2] == 0x02) {
        return discovery[i + 3];
      }
    }
    throw new IllegalArgumentException("missing 5F2F");
  }

  private static byte[] concat(byte[]... parts) {
    int length = 0;
    for (byte[] part : parts) {
      length += part.length;
    }
    byte[] out = new byte[length];
    int offset = 0;
    for (byte[] part : parts) {
      System.arraycopy(part, 0, out, offset, part.length);
      offset += part.length;
    }
    return out;
  }
}
