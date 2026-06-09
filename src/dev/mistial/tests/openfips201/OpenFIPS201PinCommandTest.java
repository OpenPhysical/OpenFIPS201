package dev.mistial.tests.openfips201;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import javax.smartcardio.ResponseAPDU;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * SP 800-73-style tests for PIN and retry-counter command behavior.
 *
 * <p>The focus here is state transitions and status words:
 * - Which failures decrement retries (63Cx)
 * - Which failures are format errors without decrement (6A80)
 * - Which commands only reset verification state but not retry counters
 */
@Timeout(value = 15, unit = TimeUnit.SECONDS)
class OpenFIPS201PinCommandTest extends OpenFIPS201TestSupport {

  private static final int INS_VERIFY = 0x20;
  private static final int INS_CHANGE_REFERENCE_DATA = 0x24;
  private static final int INS_RESET_RETRY_COUNTER = 0x2C;

  private static final int LOCAL_PIN_REFERENCE = 0x80;
  private static final int PUK_REFERENCE = 0x81;

  // Validly formatted PIN value (numeric + optional 0xFF padding), but intentionally wrong.
  private static final byte[] WRONG_PIN_FORMAT_VALID = hex("313233343536FFFF");

  // Invalid format for local/global PIN: includes a non-numeric byte before padding.
  private static final byte[] WRONG_PIN_FORMAT_INVALID = hex("31323334353647FF");

  // Wrong PUK guess (PUK is random in default card state); used to drive 63Cx behavior.
  private static final byte[] WRONG_PUK = hex("3031323334353637");
  private static final byte[] NEW_PIN_VALID = hex("393837363534FFFF");
  private static final byte[] NEW_PIN_INVALID = hex("31323334353647FF");

  @Test
  void verifyStatusInitiallyReturnsRetriesRemaining() {
    assertSw(0x9000, selectApplet(), "SELECT before VERIFY status");
    ResponseAPDU status = transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE);

    int retries = assert63cxAndGetRetries(status, "VERIFY status before any verification");
    assertTrue(retries > 0, "Fresh card should expose positive retries for local PIN");
  }

  @Test
  void verifyWithInvalidPinFormatReturns6A80WithoutDecrement() {
    assertSw(0x9000, selectApplet(), "SELECT before VERIFY format test");
    int before = assert63cxAndGetRetries(transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE), "Initial retries");

    // Format-invalid PIN should fail with 6A80 and keep retry counter unchanged.
    ResponseAPDU verify = transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE, WRONG_PIN_FORMAT_INVALID);
    assertSw(0x6A80, verify, "VERIFY with malformed PIN encoding");

    int after = assert63cxAndGetRetries(transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE), "Retries after malformed VERIFY");
    assertEquals(before, after, "Malformed PIN should not decrement retries");
  }

  @Test
  void verifyWithWrongPinValueReturns63CxAndDecrementsRetries() {
    assertSw(0x9000, selectApplet(), "SELECT before VERIFY retry decrement test");
    int before = assert63cxAndGetRetries(transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE), "Initial retries");

    // Well-formed but incorrect PIN should return 63Cx and decrement retries.
    ResponseAPDU verify = transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE, WRONG_PIN_FORMAT_VALID);
    int immediateRetries = assert63cxAndGetRetries(verify, "VERIFY wrong value");

    int after = assert63cxAndGetRetries(transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE), "Retries after wrong VERIFY");
    assertEquals(before - 1, immediateRetries, "Immediate 63Cx should report one fewer retry");
    assertEquals(before - 1, after, "Status query should observe decremented retry counter");
  }

  @Test
  void verifyResetStatusDoesNotChangeRetryCounter() {
    assertSw(0x9000, selectApplet(), "SELECT before VERIFY reset-status test");

    // First consume one retry with a well-formed wrong PIN.
    transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE, WRONG_PIN_FORMAT_VALID);
    int retriesAfterFailure = assert63cxAndGetRetries(transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE), "Retries after wrong PIN");

    // P1=FF variant should reset verification state only.
    ResponseAPDU resetStatus = transmit(0x00, INS_VERIFY, 0xFF, LOCAL_PIN_REFERENCE);
    assertSw(0x9000, resetStatus, "VERIFY reset status variant");

    int retriesAfterReset = assert63cxAndGetRetries(transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE), "Retries after reset status");
    assertEquals(retriesAfterFailure, retriesAfterReset, "VERIFY reset-status must not modify retries");
  }

  @Test
  void verifyRejectsUnsupportedP1Value() {
    assertSw(0x9000, selectApplet(), "SELECT before VERIFY P1 validation");
    ResponseAPDU response = transmit(0x00, INS_VERIFY, 0x01, LOCAL_PIN_REFERENCE);
    assertSw(0x6A86, response, "VERIFY should reject unsupported P1 values");
  }

  @Test
  void verifyUnknownReferenceReturns6A88() {
    assertSw(0x9000, selectApplet(), "SELECT before VERIFY P2 validation");
    ResponseAPDU response = transmit(0x00, INS_VERIFY, 0x00, 0x7F);
    assertSw(0x6A88, response, "VERIFY should reject unknown key references");
  }

  @Test
  void changeReferenceDataRejectsWrongP1ForStandardPinReference() {
    assertSw(0x9000, selectApplet(), "SELECT before CHANGE REFERENCE DATA checks");
    byte[] payload = hex("313233343536FFFF393837363534FFFF");
    ResponseAPDU response = transmit(0x00, INS_CHANGE_REFERENCE_DATA, 0x01, LOCAL_PIN_REFERENCE, payload);
    assertSw(0x6A86, response, "CHANGE REFERENCE DATA for standard PIN must require P1=0x00");
  }

  @Test
  void changeReferenceDataRejectsWrongLength() {
    assertSw(0x9000, selectApplet(), "SELECT before CHANGE REFERENCE DATA checks");
    byte[] shortPayload = hex("313233343536FFFF393837363534FF"); // 15 bytes (should be 16)
    ResponseAPDU response =
        transmit(0x00, INS_CHANGE_REFERENCE_DATA, 0x00, LOCAL_PIN_REFERENCE, shortPayload);
    assertSw(0x6A80, response, "CHANGE REFERENCE DATA requires old/new PIN concatenation");
  }

  @Test
  void changeReferenceDataWithWrongOldPinReturns63Cx() {
    assertSw(0x9000, selectApplet(), "SELECT before CHANGE REFERENCE DATA checks");

    // Old value is wrong (but properly formatted), new value is properly formatted.
    byte[] payload = hex("313233343536FFFF393837363534FFFF");
    ResponseAPDU response =
        transmit(0x00, INS_CHANGE_REFERENCE_DATA, 0x00, LOCAL_PIN_REFERENCE, payload);
    int retries = assert63cxAndGetRetries(response, "CHANGE REFERENCE DATA wrong old PIN");
    assertTrue(retries > 0, "Card should still report retries remaining after first failure");
  }

  @Test
  void changeReferenceDataAdminVariantRequiresSecureChannel() {
    assertSw(0x9000, selectApplet(), "SELECT before CHANGE REFERENCE DATA checks");

    // P1=FF with standard reference routes to administrative handler, which requires SCP.
    byte[] payload = hex("313233343536FFFF393837363534FFFF");
    ResponseAPDU response =
        transmit(0x00, INS_CHANGE_REFERENCE_DATA, 0xFF, LOCAL_PIN_REFERENCE, payload);
    assertSw(0x6982, response, "Administrative CHANGE REFERENCE DATA must require SCP");
  }

  @Test
  void resetRetryCounterRejectsWrongP1() {
    assertSw(0x9000, selectApplet(), "SELECT before RESET RETRY COUNTER checks");
    byte[] payload = hex("3031323334353637393837363534FFFF");
    ResponseAPDU response = transmit(0x00, INS_RESET_RETRY_COUNTER, 0x01, LOCAL_PIN_REFERENCE, payload);
    assertSw(0x6A86, response, "RESET RETRY COUNTER requires P1=0x00");
  }

  @Test
  void resetRetryCounterRejectsWrongLc() {
    assertSw(0x9000, selectApplet(), "SELECT before RESET RETRY COUNTER checks");
    byte[] shortPayload = hex("3031323334353637393837363534FF"); // 15 bytes
    ResponseAPDU response =
        transmit(0x00, INS_RESET_RETRY_COUNTER, 0x00, LOCAL_PIN_REFERENCE, shortPayload);
    assertSw(0x6A80, response, "RESET RETRY COUNTER requires exactly 16 bytes of command data");
  }

  @Test
  void resetRetryCounterRejectsUnknownPinReference() {
    assertSw(0x9000, selectApplet(), "SELECT before RESET RETRY COUNTER checks");
    byte[] payload = hex("3031323334353637393837363534FFFF");
    ResponseAPDU response = transmit(0x00, INS_RESET_RETRY_COUNTER, 0x00, PUK_REFERENCE, payload);
    assertSw(0x6A88, response, "Only local PIN key reference 0x80 is valid for RESET RETRY COUNTER");
  }

  @Test
  void resetRetryCounterWrongPukReturns63Cx() {
    assertSw(0x9000, selectApplet(), "SELECT before RESET RETRY COUNTER checks");

    // PUK is random in default state, so this should reliably fail with 63Cx.
    byte[] payload = concat(WRONG_PUK, NEW_PIN_VALID);
    ResponseAPDU response = transmit(0x00, INS_RESET_RETRY_COUNTER, 0x00, LOCAL_PIN_REFERENCE, payload);
    int retries = assert63cxAndGetRetries(response, "RESET RETRY COUNTER wrong PUK");
    assertTrue(retries > 0, "PUK retry counter should still be above zero after one failure");
  }

  @Test
  void resetRetryCounterChecksPukBeforeValidatingNewPinFormat() {
    assertSw(0x9000, selectApplet(), "SELECT before RESET RETRY COUNTER checks");

    // First call uses a malformed new PIN, but this implementation verifies PUK first.
    ResponseAPDU first =
        transmit(
            0x00,
            INS_RESET_RETRY_COUNTER,
            0x00,
            LOCAL_PIN_REFERENCE,
            concat(WRONG_PUK, NEW_PIN_INVALID));
    int retriesAfterFirst = assert63cxAndGetRetries(first, "Wrong PUK with malformed new PIN");

    // Second call with a valid new PIN should decrement the PUK counter again.
    ResponseAPDU second =
        transmit(
            0x00,
            INS_RESET_RETRY_COUNTER,
            0x00,
            LOCAL_PIN_REFERENCE,
            concat(WRONG_PUK, NEW_PIN_VALID));
    int retriesAfterSecond = assert63cxAndGetRetries(second, "Wrong PUK with valid new PIN");

    assertEquals(9, retriesAfterFirst, "First wrong PUK should consume one retry");
    assertEquals(8, retriesAfterSecond, "Second wrong PUK should consume one additional retry");
  }

  private static byte[] concat(byte[] left, byte[] right) {
    byte[] out = new byte[left.length + right.length];
    System.arraycopy(left, 0, out, 0, left.length);
    System.arraycopy(right, 0, out, left.length, right.length);
    return out;
  }
}
