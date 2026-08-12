package dev.mistial.tests.openfips201;

import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** End-to-end checks for issuer PIN policy applied through the PIV command interface. */
@Timeout(value = 15, unit = TimeUnit.SECONDS)
class OpenFIPS201PinPolicyTest extends OpenFIPS201TestSupport {
  private static final int INS_VERIFY = 0x20;
  private static final int INS_CHANGE_REFERENCE_DATA = 0x24;
  private static final int INS_RESET_RETRY_COUNTER = 0x2C;
  private static final int LOCAL_PIN_REFERENCE = 0x80;
  private static final int PUK_REFERENCE = 0x81;

  @Test
  void sequencePolicyRejectsAscendingAndDescendingReplacementPins() {
    configurePinPolicy(hex("8A0104"));
    assertSw(0x9000, selectApplet(), "SELECT before PIN sequence policy checks");

    assertSw(
        0x6A80,
        changePin(StandardCardProfile.PIN, hex("323334353637FFFF")),
        "A four-or-longer ascending sequence must be rejected");
    assertSw(
        0x6A80,
        changePin(StandardCardProfile.PIN, hex("373635343332FFFF")),
        "A four-or-longer descending sequence must be rejected");

    assertSw(
        0x63C6,
        transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE),
        "Rejected replacements must leave the original PIN unverified and retries unchanged");
  }

  @Test
  void sequencePolicyAllowsReplacementWithoutAForbiddenRun() {
    configurePinPolicy(hex("8A0104"));
    assertSw(0x9000, selectApplet(), "SELECT before accepted PIN sequence policy check");

    byte[] replacement = hex("313335373930FFFF");
    assertSw(
        0x9000,
        changePin(StandardCardProfile.PIN, replacement),
        "A replacement without a four-character run must be accepted");
    assertSw(
        0x9000,
        transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE, replacement),
        "The accepted replacement must become the active PIN");
  }

  @Test
  void distinctivenessPolicyRejectsThresholdButAllowsFewerRepeats() {
    configurePinPolicy(hex("8B0103"));
    assertSw(0x9000, selectApplet(), "SELECT before PIN distinctiveness policy checks");

    assertSw(
        0x6A80,
        changePin(StandardCardProfile.PIN, hex("313131323334FFFF")),
        "A digit repeated at the configured threshold must be rejected");

    byte[] replacement = hex("313132333435FFFF");
    assertSw(
        0x9000,
        changePin(StandardCardProfile.PIN, replacement),
        "Fewer repeats than the configured threshold must remain valid");
  }

  @Test
  void changedPukAuthorizesResetRetryCounter() {
    assertSw(0x9000, selectApplet(), "SELECT before PUK replacement check");
    byte[] replacementPuk = hex("3837363534333231");
    assertSw(
        0x9000,
        transmit(
            0x00,
            INS_CHANGE_REFERENCE_DATA,
            0x00,
            PUK_REFERENCE,
            concat(StandardCardProfile.PUK, replacementPuk)),
        "SP 800-73-5 Part 2 Section 3.2.2 permits changing local PUK reference data");

    byte[] replacementPin = hex("393837363534FFFF");
    assertSw(
        0x9000,
        transmit(
            0x00,
            INS_RESET_RETRY_COUNTER,
            0x00,
            LOCAL_PIN_REFERENCE,
            concat(replacementPuk, replacementPin)),
        "The replacement PUK must authorize RESET RETRY COUNTER under Section 3.2.3");
    assertSw(
        0x9000,
        transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE, replacementPin),
        "RESET RETRY COUNTER must install the replacement PIN");
  }

  private javax.smartcardio.ResponseAPDU changePin(byte[] current, byte[] replacement) {
    return transmit(
        0x00, INS_CHANGE_REFERENCE_DATA, 0x00, LOCAL_PIN_REFERENCE, concat(current, replacement));
  }

  private void configurePinPolicy(byte[] policyElements) {
    byte[] pinPolicy = tlv((byte) 0xA0, policyElements);
    byte[] updateConfig = tlv((byte) 0x68, pinPolicy);
    withMockedScp(
        () ->
            assertSw(
                0x9000,
                transmit(0x84, 0xDB, 0xFF, 0xFF, updateConfig),
                "Configure issuer PIN policy over SCP"));
  }
}
