package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.util.concurrent.TimeUnit;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * SP 800-73-style tests for PIN and retry-counter command behavior.
 *
 * <p>The focus here is state transitions and status words: - Which failures decrement retries
 * (63Cx) - Which failures are format errors without decrement (6A80) - Which commands only reset
 * verification state but not retry counters
 */
@Timeout(value = 15, unit = TimeUnit.SECONDS)
class OpenFIPS201PinCommandTest extends OpenFIPS201TestSupport {

  private static final int INS_VERIFY = 0x20;
  private static final int INS_CHANGE_REFERENCE_DATA = 0x24;
  private static final int INS_RESET_RETRY_COUNTER = 0x2C;

  private static final int LOCAL_PIN_REFERENCE = 0x80;
  private static final int PUK_REFERENCE = 0x81;

  // Validly formatted PIN value (numeric + optional 0xFF padding), but intentionally wrong.
  private static final byte[] WRONG_PIN_FORMAT_VALID = hex("363534333231FFFF");

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
    int before =
        assert63cxAndGetRetries(
            transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE), "Initial retries");

    // Format-invalid PIN should fail with 6A80 and keep retry counter unchanged.
    ResponseAPDU verify =
        transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE, WRONG_PIN_FORMAT_INVALID);
    assertSw(0x6A80, verify, "VERIFY with malformed PIN encoding");

    int after =
        assert63cxAndGetRetries(
            transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE),
            "Retries after malformed VERIFY");
    assertEquals(before, after, "Malformed PIN should not decrement retries");
  }

  @Test
  void verifyWithWrongPinValueReturns63CxAndDecrementsRetries() {
    assertSw(0x9000, selectApplet(), "SELECT before VERIFY retry decrement test");
    int before =
        assert63cxAndGetRetries(
            transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE), "Initial retries");

    // Well-formed but incorrect PIN should return 63Cx and decrement retries.
    ResponseAPDU verify =
        transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE, WRONG_PIN_FORMAT_VALID);
    int immediateRetries = assert63cxAndGetRetries(verify, "VERIFY wrong value");

    int after =
        assert63cxAndGetRetries(
            transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE), "Retries after wrong VERIFY");
    assertEquals(before - 1, immediateRetries, "Immediate 63Cx should report one fewer retry");
    assertEquals(before - 1, after, "Status query should observe decremented retry counter");
  }

  @Test
  void finalWrongPinAttemptReturns63C0BeforeBlockedStatus() {
    assertSw(0x9000, selectApplet(), "SELECT before VERIFY exhaustion test");
    int retries =
        assert63cxAndGetRetries(
            transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE), "Initial retries");

    for (int remaining = retries - 1; remaining >= 0; remaining--) {
      assertSw(
          0x63C0 | remaining,
          transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE, WRONG_PIN_FORMAT_VALID),
          "Wrong VERIFY should report the post-attempt retry count");
    }

    assertSw(
        0x6983,
        transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE, WRONG_PIN_FORMAT_VALID),
        "A subsequent VERIFY should report the blocked reference");
    assertSw(
        0x6983,
        transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE),
        "VERIFY status should report the blocked reference");
  }

  @Test
  void verifyResetStatusDoesNotChangeRetryCounter() {
    assertSw(0x9000, selectApplet(), "SELECT before VERIFY reset-status test");

    // First consume one retry with a well-formed wrong PIN.
    transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE, WRONG_PIN_FORMAT_VALID);
    int retriesAfterFailure =
        assert63cxAndGetRetries(
            transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE), "Retries after wrong PIN");

    // P1=FF variant should reset verification state only.
    ResponseAPDU resetStatus = transmit(0x00, INS_VERIFY, 0xFF, LOCAL_PIN_REFERENCE);
    assertSw(0x9000, resetStatus, "VERIFY reset status variant");

    int retriesAfterReset =
        assert63cxAndGetRetries(
            transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE), "Retries after reset status");
    assertEquals(
        retriesAfterFailure, retriesAfterReset, "VERIFY reset-status must not modify retries");
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
    byte[] payload = concat(WRONG_PIN_FORMAT_VALID, NEW_PIN_VALID);
    ResponseAPDU response =
        transmit(0x00, INS_CHANGE_REFERENCE_DATA, 0xFF, LOCAL_PIN_REFERENCE, payload);
    assertSw(
        0x6A86,
        response,
        "SP 800-73-5 Part 2 Section 3.2.2 requires P1=0x00 for CHANGE REFERENCE DATA");
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
    byte[] payload = concat(WRONG_PIN_FORMAT_VALID, NEW_PIN_VALID);
    ResponseAPDU response =
        transmit(0x00, INS_CHANGE_REFERENCE_DATA, 0x00, LOCAL_PIN_REFERENCE, payload);
    int retries = assert63cxAndGetRetries(response, "CHANGE REFERENCE DATA wrong old PIN");
    assertTrue(retries > 0, "Card should still report retries remaining after first failure");
  }

  @Test
  void changeReferenceDataAdminVariantRequiresAdministrativeAuthorization() {
    assertSw(0x9000, selectApplet(), "SELECT before CHANGE REFERENCE DATA checks");

    byte[] payload = hex("313233343536FFFF393837363534FFFF");
    ResponseAPDU response =
        transmit(0x80, INS_CHANGE_REFERENCE_DATA, 0x01, LOCAL_PIN_REFERENCE, payload);
    assertSw(0x6982, response, "Administrative CHANGE REFERENCE DATA must require authorization");
  }

  @Test
  void resetRetryCounterRejectsWrongP1() {
    assertSw(0x9000, selectApplet(), "SELECT before RESET RETRY COUNTER checks");
    byte[] payload = hex("3031323334353637393837363534FFFF");
    ResponseAPDU response =
        transmit(0x00, INS_RESET_RETRY_COUNTER, 0x01, LOCAL_PIN_REFERENCE, payload);
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
    assertSw(
        0x6A88, response, "Only local PIN key reference 0x80 is valid for RESET RETRY COUNTER");
  }

  @Test
  void resetRetryCounterWrongPukReturns63Cx() {
    assertSw(0x9000, selectApplet(), "SELECT before RESET RETRY COUNTER checks");

    // The fixture provisions PUK 12345678; this distinct valid value must fail deterministically.
    byte[] payload = concat(WRONG_PUK, NEW_PIN_VALID);
    ResponseAPDU response =
        transmit(0x00, INS_RESET_RETRY_COUNTER, 0x00, LOCAL_PIN_REFERENCE, payload);
    int retries = assert63cxAndGetRetries(response, "RESET RETRY COUNTER wrong PUK");
    assertTrue(retries > 0, "PUK retry counter should still be above zero after one failure");
  }

  @Test
  void resetRetryCounterUsesFixedWireFieldsWithSixDigitPinLimit() {
    byte[] puk = hex("3837363534333231");
    setLocalPinOverScp(hex("313233343536FFFF"));
    setPukOverScp(puk);
    withMockedScp(
        () ->
            assertSw(
                0x9000,
                transmit(0x84, 0xDB, 0xFF, 0xFF, hex("6805A003850106")),
                "Set the significant PIN limit to six digits"));

    assertSw(0x9000, selectApplet(), "SELECT before fixed-width RESET RETRY COUNTER");
    byte[] newPin = hex("363534333231FFFF");
    assertSw(
        0x9000,
        transmit(0x00, INS_RESET_RETRY_COUNTER, 0x00, LOCAL_PIN_REFERENCE, concat(puk, newPin)),
        "Six-digit policy must still use two eight-byte command fields");
    assertSw(
        0x9000,
        transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE, newPin),
        "The replacement PIN should verify using the fixed-width encoding");
  }

  @Test
  void successfulResetRetryCounterPreservesValidatedPinStatus() {
    byte[] currentPin = hex("313233343536FFFF");
    byte[] puk = hex("3132333435363738");
    setLocalPinOverScp(currentPin);
    setPukOverScp(puk);

    assertSw(0x9000, selectApplet(), "SELECT before RESET RETRY COUNTER status test");
    assertSw(
        0x9000,
        transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE, currentPin),
        "Establish PIN security status");
    assertSw(
        0x9000,
        transmit(
            0x00, INS_RESET_RETRY_COUNTER, 0x00, LOCAL_PIN_REFERENCE, concat(puk, NEW_PIN_VALID)),
        "RESET RETRY COUNTER should succeed");
    assertSw(
        0x9000,
        transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE),
        "SP 800-73-5 Part 2 Section 3.2.3 preserves PIN security status");
  }

  @Test
  void resetRetryCounterValidatesNewPinFormatBeforePuk() {
    assertSw(0x9000, selectApplet(), "SELECT before RESET RETRY COUNTER checks");

    // SP 800-73-5 Part 2 Section 3.2.3 permits '6A 80' when the PUK is wrong and the new PIN is
    // malformed; '6A 80' requires that "the PUK's retry counter SHALL remain unchanged".
    assertSw(
        0x6A80,
        transmit(
            0x00,
            INS_RESET_RETRY_COUNTER,
            0x00,
            LOCAL_PIN_REFERENCE,
            concat(WRONG_PUK, NEW_PIN_INVALID)),
        "Wrong PUK with malformed new PIN");

    ResponseAPDU second =
        transmit(
            0x00,
            INS_RESET_RETRY_COUNTER,
            0x00,
            LOCAL_PIN_REFERENCE,
            concat(WRONG_PUK, NEW_PIN_VALID));
    assertEquals(
        9,
        assert63cxAndGetRetries(second, "Wrong PUK with valid new PIN"),
        "Only the well-formed attempt may consume a PUK retry");
  }

  @Test
  void resetRetryCounterMalformedPinAfterCorrectPukKeepsPukRetryCounter() {
    assertSw(0x9000, selectApplet(), "SELECT before RESET RETRY COUNTER checks");
    assertSw(
        0x63C9,
        transmit(
            0x00,
            INS_RESET_RETRY_COUNTER,
            0x00,
            LOCAL_PIN_REFERENCE,
            concat(WRONG_PUK, NEW_PIN_VALID)),
        "Consume one PUK retry");

    assertSw(
        0x6A80,
        transmit(
            0x00,
            INS_RESET_RETRY_COUNTER,
            0x00,
            LOCAL_PIN_REFERENCE,
            concat(StandardCardProfile.PUK, NEW_PIN_INVALID)),
        "Correct PUK with malformed new PIN");

    // A '6A 80' must leave the PUK retry counter unchanged, so the next failure reports eight.
    assertSw(
        0x63C8,
        transmit(
            0x00,
            INS_RESET_RETRY_COUNTER,
            0x00,
            LOCAL_PIN_REFERENCE,
            concat(WRONG_PUK, NEW_PIN_VALID)),
        "The malformed attempt must not reset the PUK retry counter");
    assertSw(
        0x9000,
        transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE, StandardCardProfile.PIN),
        "The PIN reference data must be unchanged");
  }

  @Test
  void changeReferenceDataWithMalformedOldPinReturns6A80WithoutDecrement() {
    assertSw(0x9000, selectApplet(), "SELECT before CHANGE REFERENCE DATA checks");
    int before =
        assert63cxAndGetRetries(
            transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE), "Initial retries");
    assertSw(
        0x6A80,
        transmit(
            0x00,
            INS_CHANGE_REFERENCE_DATA,
            0x00,
            LOCAL_PIN_REFERENCE,
            concat(WRONG_PIN_FORMAT_INVALID, NEW_PIN_VALID)),
        "Malformed current PIN");
    assertEquals(
        before,
        assert63cxAndGetRetries(
            transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE), "Retries after 6A80"),
        "A '6A 80' must leave the PIN retry counter unchanged");
  }

  @Test
  void changeReferenceDataOnBlockedPinReturns6983AndKeepsReference() {
    assertSw(0x9000, selectApplet(), "SELECT before blocked PIN checks");
    blockLocalPin();

    // SP 800-73-5 Part 2 Section 3.2.2: "If the current value of the retry counter associated with
    // the key reference is zero, then the reference data associated with the key reference SHALL
    // NOT be changed, and the PIV Card Application SHALL return the status word '69 83'."
    assertSw(
        0x6983,
        transmit(
            0x00,
            INS_CHANGE_REFERENCE_DATA,
            0x00,
            LOCAL_PIN_REFERENCE,
            concat(StandardCardProfile.PIN, NEW_PIN_VALID)),
        "CHANGE REFERENCE DATA on a blocked PIN");
    assertSw(0x6983, transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE), "PIN remains blocked");

    byte[] unblockedPin = hex("373839303132FFFF");
    assertSw(
        0x9000,
        transmit(
            0x00,
            INS_RESET_RETRY_COUNTER,
            0x00,
            LOCAL_PIN_REFERENCE,
            concat(StandardCardProfile.PUK, unblockedPin)),
        "Unblock with the PUK");
    assertSw(
        0x63C5,
        transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE, NEW_PIN_VALID),
        "The blocked CHANGE REFERENCE DATA must not have installed its new PIN");
    assertSw(
        0x9000,
        transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE, unblockedPin),
        "The PIN set by RESET RETRY COUNTER verifies");
  }

  @Test
  void blockedPukRejectsResetRetryCounterAndPukChangeWith6983() {
    assertSw(0x9000, selectApplet(), "SELECT before blocked PUK checks");
    for (int remaining = 9; remaining >= 0; remaining--) {
      assertSw(
          0x63C0 | remaining,
          transmit(
              0x00,
              INS_RESET_RETRY_COUNTER,
              0x00,
              LOCAL_PIN_REFERENCE,
              concat(WRONG_PUK, NEW_PIN_VALID)),
          "Wrong PUK reports the remaining PUK retries");
    }

    // SP 800-73-5 Part 2 Section 3.2.3: "If the current value of the PUK's retry counter is zero,
    // then the PIN's retry counter shall not be reset, the PIV Card Application shall return the
    // status word '69 83', and the reset operation shall be blocked."
    assertSw(
        0x6983,
        transmit(
            0x00,
            INS_RESET_RETRY_COUNTER,
            0x00,
            LOCAL_PIN_REFERENCE,
            concat(StandardCardProfile.PUK, NEW_PIN_VALID)),
        "RESET RETRY COUNTER with a blocked PUK");
    assertSw(
        0x6983,
        transmit(
            0x00,
            INS_CHANGE_REFERENCE_DATA,
            0x00,
            PUK_REFERENCE,
            concat(StandardCardProfile.PUK, StandardCardProfile.PUK)),
        "CHANGE REFERENCE DATA on a blocked PUK");
    assertSw(
        0x9000,
        transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE, StandardCardProfile.PIN),
        "The PIN reference data must be unchanged");
  }

  @Test
  void changeReferenceDataHistoryRejectionLeavesSecurityStatusUnchanged() {
    byte[] second = hex("363534333231FFFF");
    byte[] third = hex("373839303132FFFF");
    assertSw(0x9000, selectApplet(), "SELECT before PIN history checks");
    enablePinHistory();
    changePin(StandardCardProfile.PIN, second);
    changePin(second, third);
    assertSw(
        0x9000, transmit(0x00, INS_VERIFY, 0xFF, LOCAL_PIN_REFERENCE), "Clear PIN security status");

    assertSw(
        0x6984,
        transmit(0x00, INS_CHANGE_REFERENCE_DATA, 0x00, LOCAL_PIN_REFERENCE, concat(third, second)),
        "PIN history rejects a recent value");

    // The failed change must not leave the PIN verified as a side effect of the comparison.
    assert63cxAndGetRetries(
        transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE),
        "PIN security status after a history rejection");
    assertSw(
        0x9000,
        transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE, third),
        "The current PIN is unchanged");
  }

  @Test
  void resetRetryCounterHistoryRejectionKeepsPinAndItsSecurityStatus() {
    byte[] second = hex("363534333231FFFF");
    assertSw(0x9000, selectApplet(), "SELECT before PIN history checks");
    enablePinHistory();
    changePin(StandardCardProfile.PIN, second);
    assertSw(
        0x9000, transmit(0x00, INS_VERIFY, 0xFF, LOCAL_PIN_REFERENCE), "Clear PIN security status");

    assertSw(
        0x6984,
        transmit(
            0x00,
            INS_RESET_RETRY_COUNTER,
            0x00,
            LOCAL_PIN_REFERENCE,
            concat(StandardCardProfile.PUK, second)),
        "PIN history rejects a recent value after the PUK comparison");
    assert63cxAndGetRetries(
        transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE),
        "PIN security status after a history rejection");
    assertSw(
        0x9000,
        transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE, second),
        "The current PIN is unchanged");
  }

  /**
   * A history rejection must not turn the successful comparison into a retry-counter reset: the PIN
   * retry counter returns to its value before the command.
   */
  @Test
  void changeReferenceDataHistoryRejectionRestoresPinRetryCounter() {
    byte[] second = NEW_PIN_VALID;
    byte[] third = hex("373839303132FFFF");
    assertSw(0x9000, selectApplet(), "SELECT before PIN history checks");
    enablePinHistory();
    changePin(StandardCardProfile.PIN, second);
    changePin(second, third);
    int initial =
        assert63cxAndGetRetries(
            transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE, WRONG_PIN_FORMAT_VALID),
            "Wrong PIN decrements the retry counter");

    assertSw(
        0x6984,
        transmit(0x00, INS_CHANGE_REFERENCE_DATA, 0x00, LOCAL_PIN_REFERENCE, concat(third, second)),
        "PIN history rejects a recent value");

    assertEquals(
        initial,
        assert63cxAndGetRetries(
            transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE),
            "PIN retry counter after a history rejection"),
        "A history rejection must leave the PIN retry counter at its pre-command value");
    assertSw(
        0x9000,
        transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE, third),
        "The current PIN is unchanged");
  }

  /**
   * A history rejection in RESET RETRY COUNTER must not reset the PUK retry counter as a side
   * effect of the PUK comparison.
   */
  @Test
  void resetRetryCounterHistoryRejectionRestoresPukRetryCounter() {
    byte[] second = hex("363534333231FFFF");
    assertSw(0x9000, selectApplet(), "SELECT before PIN history checks");
    enablePinHistory();
    changePin(StandardCardProfile.PIN, second);
    int afterFirstFailure =
        assert63cxAndGetRetries(
            transmit(
                0x00,
                INS_RESET_RETRY_COUNTER,
                0x00,
                LOCAL_PIN_REFERENCE,
                concat(WRONG_PUK, second)),
            "Wrong PUK decrements the PUK retry counter");

    assertSw(
        0x6984,
        transmit(
            0x00,
            INS_RESET_RETRY_COUNTER,
            0x00,
            LOCAL_PIN_REFERENCE,
            concat(StandardCardProfile.PUK, second)),
        "PIN history rejects a recent value after the PUK comparison");

    assertEquals(
        afterFirstFailure - 1,
        assert63cxAndGetRetries(
            transmit(
                0x00,
                INS_RESET_RETRY_COUNTER,
                0x00,
                LOCAL_PIN_REFERENCE,
                concat(WRONG_PUK, second)),
            "PUK retry counter after a history rejection"),
        "A history rejection must leave the PUK retry counter at its pre-command value");
  }

  /** A disabled PUK is reference data that does not exist for both PUK-consuming commands. */
  @Test
  void disabledPukReportsReferenceNotFound() {
    byte[] second = hex("363534333231FFFF");
    assertSw(0x9000, selectApplet(), "SELECT before PUK configuration");
    withMockedScp(
        () ->
            assertSw(
                0x9000,
                transmit(0x84, 0xDB, 0xFF, 0xFF, hex("6805A103800100")),
                "Disable the PUK"));

    assertSw(
        0x6A88,
        transmit(
            0x00,
            INS_CHANGE_REFERENCE_DATA,
            0x00,
            PUK_REFERENCE,
            concat(StandardCardProfile.PUK, StandardCardProfile.PUK)),
        "CHANGE REFERENCE DATA 81 with the PUK disabled");
    assertSw(
        0x6A88,
        transmit(
            0x00,
            INS_RESET_RETRY_COUNTER,
            0x00,
            LOCAL_PIN_REFERENCE,
            concat(StandardCardProfile.PUK, second)),
        "RESET RETRY COUNTER with the PUK disabled");
  }

  private void enablePinHistory() {
    withMockedScp(
        () ->
            assertSw(
                0x9000,
                transmit(0x84, 0xDB, 0xFF, 0xFF, hex("6805A003890102")),
                "Configure two-entry PIN history"));
  }

  private void changePin(byte[] current, byte[] replacement) {
    assertSw(
        0x9000,
        transmit(
            0x00,
            INS_CHANGE_REFERENCE_DATA,
            0x00,
            LOCAL_PIN_REFERENCE,
            concat(current, replacement)),
        "CHANGE REFERENCE DATA");
  }

  private void blockLocalPin() {
    int retries =
        assert63cxAndGetRetries(
            transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE), "Initial retries");
    for (int i = 0; i < retries; i++) {
      transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE, WRONG_PIN_FORMAT_VALID);
    }
    assertSw(0x6983, transmit(0x00, INS_VERIFY, 0x00, LOCAL_PIN_REFERENCE), "PIN is blocked");
  }
}
