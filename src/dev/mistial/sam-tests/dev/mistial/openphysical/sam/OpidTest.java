package dev.mistial.openphysical.sam;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tests.issuersam.OpidV2Reference;
import java.nio.charset.StandardCharsets;
import javacard.framework.JCSystem;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/** White-box tests of Luhn and of the 17-digit OPID rendering and parsing. */
class OpidTest {

  @Test
  void luhnVectors() {
    assertEquals(3, luhn("12349123412345678"));
    assertEquals(1, luhn("411111111111111"));
    assertEquals(4, luhn("555555555555444"));
    assertEquals(3, luhn("7992739871"));
    assertEquals(0, luhn("0"));
  }

  @Test
  void luhnMatchesReferenceForRandomPayloads() {
    java.util.SplittableRandom random = new java.util.SplittableRandom(7);
    for (int i = 0; i < 2000; i++) {
      StringBuilder payload = new StringBuilder();
      for (int j = 0; j < 16; j++) payload.append((char) ('0' + random.nextInt(10)));
      assertEquals(OpidV2Reference.luhn(payload.toString()), luhn(payload.toString()));
    }
  }

  @Test
  void rendersIinThenEncipheredDigitsThenLuhn() {
    try (MockedStatic<JCSystem> system = Mockito.mockStatic(JCSystem.class)) {
      WhiteBox.mockTransientStorage(system);
      SamState state = new SamState();
      System.arraycopy(new byte[] {0, 0, 4, 2}, 0, state.issuerDigits, 0, 4);
      byte[] e = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 1};
      byte[] out = new byte[17];
      assertEquals(17, Opid.render(state, e, (short) 0, out, (short) 0));
      String payload = "0042987654321001";
      assertEquals(
          payload + OpidV2Reference.luhn(payload), new String(out, StandardCharsets.US_ASCII));

      byte[] parsed = new byte[17];
      assertTrue(Opid.parse(out, (short) 0, parsed, (short) 0));
      assertArrayEquals(new byte[] {0, 0, 4, 2}, java.util.Arrays.copyOf(parsed, 4));
      out[16] = (byte) ('0' + (out[16] - '0' + 1) % 10);
      assertFalse(Opid.parse(out, (short) 0, parsed, (short) 0), "bad Luhn");
      out[3] = (byte) 'x';
      assertFalse(Opid.parse(out, (short) 0, parsed, (short) 0), "non-digit");
    }
  }

  private static int luhn(String payload) {
    byte[] digits = new byte[payload.length()];
    for (int i = 0; i < digits.length; i++) digits[i] = (byte) (payload.charAt(i) - '0');
    return Opid.luhn(digits, (short) 0, (short) digits.length);
  }
}
