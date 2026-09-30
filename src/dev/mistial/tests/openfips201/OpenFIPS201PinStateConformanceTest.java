package dev.mistial.tests.openfips201;

import com.makina.security.openfips201.PivTestConstants;
import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.util.concurrent.TimeUnit;
import javacard.framework.ISO7816;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** State-preservation checks for PIV reference-data commands. */
@Timeout(value = 15, unit = TimeUnit.SECONDS)
class OpenFIPS201PinStateConformanceTest extends OpenFIPS201TestSupport {
  private static final int INS_VERIFY = 0x20;
  private static final int INS_CHANGE_REFERENCE_DATA =
      Byte.toUnsignedInt(PivTestConstants.INS_CHANGE_REFERENCE_DATA);
  private static final int LOCAL_PIN_REFERENCE =
      Byte.toUnsignedInt(StandardCardProfile.LOCAL_PIN_REF);

  @Test
  void administrativePukUpdateRejectsNonWireWidthsWithoutChangingThePuk() {
    withMockedScp(
        () -> {
          assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before PUK width checks");
          for (int length :
              new int[] {
                StandardCardProfile.PUK.length - 1,
                StandardCardProfile.PUK.length + 1,
                2 * StandardCardProfile.PUK.length
              }) {
            byte[] replacement = new byte[length];
            java.util.Arrays.fill(replacement, (byte) '9');
            assertSw(
                ISO7816.SW_WRONG_LENGTH,
                transmit(
                    0x84,
                    INS_CHANGE_REFERENCE_DATA,
                    1,
                    Byte.toUnsignedInt(StandardCardProfile.PUK_REF),
                    replacement),
                "Administrative PUK must retain the configured eight-byte wire width");
          }
        });
    assertSw(
        ISO7816.SW_NO_ERROR,
        transmit(
            0,
            Byte.toUnsignedInt(PivTestConstants.INS_RESET_RETRY_COUNTER),
            0,
            LOCAL_PIN_REFERENCE,
            concat(StandardCardProfile.PUK, StandardCardProfile.PIN)),
        "Rejected widths must leave the previous PUK usable");
  }

  @Test
  void invalidNewPinLeavesSecurityStatusAndRetryCounterUnchanged() {
    assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before CHANGE REFERENCE DATA state test");

    byte[] wrongButWellFormedPin = hex("393939393939FFFF");
    assertSw(
        0x63C5,
        transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE, wrongButWellFormedPin),
        "Wrong PIN should consume one retry and leave PIN unverified");

    byte[] malformedNewPin = hex("31323334353647FF");
    assertSw(
        ISO7816.SW_WRONG_DATA,
        transmit(
            0x00,
            INS_CHANGE_REFERENCE_DATA,
            0x00,
            LOCAL_PIN_REFERENCE,
            concat(StandardCardProfile.PIN, malformedNewPin)),
        "SP 800-73-5 Part 2 Section 3.2.2 requires malformed new reference data to fail");

    assertSw(
        0x63C5,
        transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE),
        "A 6A80 new-PIN failure must preserve both security status and retry state");
  }
}
