package dev.mistial.tests.openfips201;

import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** State-preservation checks for PIV reference-data commands. */
@Timeout(value = 15, unit = TimeUnit.SECONDS)
class OpenFIPS201PinStateConformanceTest extends OpenFIPS201TestSupport {
  private static final int INS_VERIFY = 0x20;
  private static final int INS_CHANGE_REFERENCE_DATA = 0x24;
  private static final int LOCAL_PIN_REFERENCE = 0x80;

  @Test
  void invalidNewPinLeavesSecurityStatusAndRetryCounterUnchanged() {
    assertSw(0x9000, selectApplet(), "SELECT before CHANGE REFERENCE DATA state test");

    byte[] wrongButWellFormedPin = hex("393939393939FFFF");
    assertSw(
        0x63C5,
        transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE, wrongButWellFormedPin),
        "Wrong PIN should consume one retry and leave PIN unverified");

    byte[] malformedNewPin = hex("31323334353647FF");
    assertSw(
        0x6A80,
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
