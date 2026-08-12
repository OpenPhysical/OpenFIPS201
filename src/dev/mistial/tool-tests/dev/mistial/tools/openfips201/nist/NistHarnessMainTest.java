package dev.mistial.tools.openfips201.nist;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.common.SecureMessagingAdvertisement;
import org.junit.jupiter.api.Test;

class NistHarnessMainTest {

  @Test
  void detectsOnlySecureMessagingAlgorithmsInsideApplicationPropertyTemplate() {
    // NIST SP 800-73-5 Part 2, Section 3.1.1 and Table 5: CS2/CS7 support backed by an
    // appropriately sized SM key is advertised as 80 01 27 or 80 01 2E inside tag AC.
    assertTrue(SecureMessagingAdvertisement.isPresent(hex("610BAC09800127800107060100")));
    assertTrue(SecureMessagingAdvertisement.isPresent(hex("6108AC0680012E060100")));
    assertFalse(SecureMessagingAdvertisement.isPresent(hex("610BAC09800108800107060100")));
  }

  @Test
  void ignoresCipherSuiteBytesOutsideTheAlgorithmTemplate() {
    // The same section makes AC the authoritative discovery location. A byte in
    // an application label or URI cannot make an SM-only test applicable.
    assertFalse(SecureMessagingAdvertisement.isPresent(hex("6109500327802EAC020600")));
  }

  private static byte[] hex(String value) {
    byte[] decoded = new byte[value.length() / 2];
    for (int i = 0; i < decoded.length; i++) {
      decoded[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
    }
    return decoded;
  }
}
