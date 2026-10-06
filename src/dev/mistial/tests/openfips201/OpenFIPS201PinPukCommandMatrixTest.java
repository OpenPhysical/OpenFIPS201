package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.makina.security.openfips201.OpenFIPS201;
import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javacard.framework.Applet;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;

/**
 * Status word, retry counter and security status matrix for the PIN and PUK commands of SP 800-73-5
 * Part 2: VERIFY (Section 3.2.1), CHANGE REFERENCE DATA (Section 3.2.2) and RESET RETRY COUNTER
 * (Section 3.2.3), each for a malformed command, a wrong value, a blocked reference, the
 * contactless intermediate retry reserve, an unprovisioned PUK, the contactless interface and
 * success.
 *
 * <p>Each row starts from a freshly installed card, drives the retry counters to the row's starting
 * values over the contact interface, sends one command and asserts its status word. It then reads
 * back the PIN security status (empty VERIFY '90 00') in the session of the command, where the
 * interface allows it, and over the contact interface the PIN retry counter (empty VERIFY '63 CX'
 * after VERIFY P1='FF'), the PUK retry counter (one further wrong RESET RETRY COUNTER, which
 * reports the counter less one) and, where the row names them, the PIN and PUK reference data.
 *
 * <p>The card uses the default configuration: PIN retries 6 contact and 5 contactless, PUK retries
 * 10 and 9, so each reference keeps an intermediate retry reserve of one. Rows sent over the VCI
 * enable contactless PIN use and hold the applet's VCI condition true (see {@link
 * #satisfyVciCondition()}); establishing the VCI itself is covered by the VCI end-to-end tests.
 */
@Timeout(value = 120, unit = TimeUnit.SECONDS)
class OpenFIPS201PinPukCommandMatrixTest extends OpenFIPS201TestSupport {

  private static final boolean FIPS_MODE = Boolean.getBoolean("fips.mode");

  private static final int PIN_TRIES = 6;
  private static final int PIN_RESERVE = 1;
  private static final int PUK_TRIES = 10;

  private static final byte[] PIN = StandardCardProfile.PIN;
  private static final byte[] PUK = StandardCardProfile.PUK;
  private static final byte[] WRONG_PIN = hex("363534333231FFFF");
  private static final byte[] NEW_PIN = hex("393837363534FFFF");
  private static final byte[] MALFORMED_PIN = hex("31323334353647FF");
  private static final byte[] WRONG_PUK = hex("3837363534333231");
  private static final byte[] NEW_PUK = hex("A1B2C3D4E5F60718");

  /** The interface a row's command is sent over. */
  private enum Interface {
    CONTACT,
    /** Contactless without the VCI. */
    CONTACTLESS,
    /** Contactless over the VCI, with contactless PIN use enabled. */
    VCI
  }

  /** One matrix row. */
  static final class Row {
    final String name;
    boolean provisioned = true;
    int pinTries = PIN_TRIES;
    int pukTries = PUK_TRIES;
    boolean pinVerified;
    Interface iface = Interface.CONTACT;
    int ins;
    int p1;
    int p2;
    byte[] data;
    int sw;
    int fipsSw = -1;
    int pinTriesAfter = -1;
    int pukTriesAfter = -1;
    boolean pinVerifiedAfter;
    byte[] pinAfter;
    byte[] pukAfter;

    Row(String name) {
      this.name = name;
    }

    Row unprovisioned() {
      provisioned = false;
      return this;
    }

    Row pinTries(int tries) {
      pinTries = tries;
      return this;
    }

    Row pukTries(int tries) {
      pukTries = tries;
      return this;
    }

    Row pinVerified() {
      pinVerified = true;
      return this;
    }

    Row over(Interface value) {
      iface = value;
      return this;
    }

    Row command(int ins, int p1, int p2, byte[] data) {
      this.ins = ins;
      this.p1 = p1;
      this.p2 = p2;
      this.data = data;
      return this;
    }

    /** Expects {@code value} in every variant. */
    Row sw(int value) {
      sw = value;
      return this;
    }

    /** Expects {@code value} in FIPS builds instead of the standard status word. */
    Row fipsSw(int value) {
      fipsSw = value;
      return this;
    }

    /**
     * Expects the PIN retry counter, PIN security status and PUK retry counter after the command.
     * Unset counters default to their starting values.
     */
    Row then(int pinTriesAfterValue, boolean pinVerifiedAfterValue, int pukTriesAfterValue) {
      pinTriesAfter = pinTriesAfterValue;
      pinVerifiedAfter = pinVerifiedAfterValue;
      pukTriesAfter = pukTriesAfterValue;
      return this;
    }

    /** Expects these values to be the reference data after the command. */
    Row referenceData(byte[] pin, byte[] puk) {
      pinAfter = pin;
      pukAfter = puk;
      return this;
    }

    @Override
    public String toString() {
      return name;
    }
  }

  private static Row row(String name) {
    return new Row(name);
  }

  static List<Row> rows() {
    List<Row> rows = new ArrayList<Row>();

    // VERIFY '80' (SP 800-73-5 Part 2 Section 3.2.1).
    rows.add(
        row("VERIFY 80 malformed length")
            .command(0x20, 0x00, 0x80, hex("31323334353637"))
            .sw(0x6A80)
            .then(PIN_TRIES, false, PUK_TRIES));
    rows.add(
        row("VERIFY 80 malformed value")
            .command(0x20, 0x00, 0x80, MALFORMED_PIN)
            .sw(0x6A80)
            .then(PIN_TRIES, false, PUK_TRIES));
    rows.add(
        row("VERIFY 80 wrong value")
            .pinVerified()
            .command(0x20, 0x00, 0x80, WRONG_PIN)
            .sw(0x63C5)
            .then(5, false, PUK_TRIES));
    rows.add(
        row("VERIFY 80 last wrong value")
            .pinTries(1)
            .command(0x20, 0x00, 0x80, WRONG_PIN)
            .sw(0x63C0)
            .then(0, false, PUK_TRIES));
    rows.add(
        row("VERIFY 80 blocked")
            .pinTries(0)
            .command(0x20, 0x00, 0x80, PIN)
            .sw(0x6983)
            .then(0, false, PUK_TRIES));
    rows.add(
        row("VERIFY 80 empty blocked")
            .pinTries(0)
            .command(0x20, 0x00, 0x80, null)
            .sw(0x6983)
            .then(0, false, PUK_TRIES));
    rows.add(
        row("VERIFY 80 success")
            .pinTries(2)
            .command(0x20, 0x00, 0x80, PIN)
            .sw(0x9000)
            .then(PIN_TRIES, true, PUK_TRIES));
    rows.add(
        row("VERIFY 80 empty unverified")
            .pinTries(4)
            .command(0x20, 0x00, 0x80, null)
            .sw(0x63C4)
            .then(4, false, PUK_TRIES));
    rows.add(
        row("VERIFY 80 empty verified")
            .pinVerified()
            .command(0x20, 0x00, 0x80, null)
            .sw(0x9000)
            .then(PIN_TRIES, true, PUK_TRIES));
    rows.add(
        row("VERIFY 80 reset status")
            .pinVerified()
            .command(0x20, 0xFF, 0x80, null)
            .sw(0x9000)
            .then(PIN_TRIES, false, PUK_TRIES));
    // Section 3.2.1: VERIFY '00' or '80' "SHALL fail if" the command "is not submitted over
    // either the contact interface or the VCI".
    rows.add(
        row("VERIFY 80 contactless without VCI")
            .over(Interface.CONTACTLESS)
            .command(0x20, 0x00, 0x80, PIN)
            .sw(0x6982)
            .then(PIN_TRIES, false, PUK_TRIES));
    rows.add(
        row("VERIFY 80 empty contactless without VCI")
            .over(Interface.CONTACTLESS)
            .command(0x20, 0x00, 0x80, null)
            .sw(0x6982)
            .then(PIN_TRIES, false, PUK_TRIES));
    // Section 3.2.1: over contactless, "return '69 83' if ... the current value of the retry
    // counter associated with the key reference is at or below the issuer-specified intermediate
    // retry value. If status word '69 83' is returned, then the comparison SHALL NOT be made".
    rows.add(
        row("VERIFY 80 contactless wrong value")
            .over(Interface.VCI)
            .command(0x20, 0x00, 0x80, WRONG_PIN)
            .sw(0x63C4)
            .then(5, false, PUK_TRIES));
    rows.add(
        row("VERIFY 80 contactless wrong value reaching reserve")
            .pinTries(2)
            .over(Interface.VCI)
            .command(0x20, 0x00, 0x80, WRONG_PIN)
            .sw(0x63C0)
            .then(1, false, PUK_TRIES));
    rows.add(
        row("VERIFY 80 contactless at reserve")
            .pinTries(1)
            .over(Interface.VCI)
            .command(0x20, 0x00, 0x80, PIN)
            .sw(0x6983)
            .then(1, false, PUK_TRIES));
    // Section 3.2.1: "If P1='00' and Lc and the command data field are absent, the command CAN be
    // used to retrieve the number of further retries allowed ('63 CX')". The '69 83' reserve rule
    // applies when "Lc and the command data field are present", so the empty form reports the
    // retries usable on this interface: none at the reserve, and '69 83' only at zero.
    rows.add(
        row("VERIFY 80 empty contactless above reserve")
            .pinTries(4)
            .over(Interface.VCI)
            .command(0x20, 0x00, 0x80, null)
            .sw(0x63C3)
            .then(4, false, PUK_TRIES));
    rows.add(
        row("VERIFY 80 empty contactless at reserve")
            .pinTries(1)
            .over(Interface.VCI)
            .command(0x20, 0x00, 0x80, null)
            .sw(0x63C0)
            .then(1, false, PUK_TRIES));
    rows.add(
        row("VERIFY 80 empty contactless blocked")
            .pinTries(0)
            .over(Interface.VCI)
            .command(0x20, 0x00, 0x80, null)
            .sw(0x6983)
            .then(0, false, PUK_TRIES));
    rows.add(
        row("VERIFY 80 contactless success")
            .pinTries(3)
            .over(Interface.VCI)
            .command(0x20, 0x00, 0x80, PIN)
            .sw(0x9000)
            .then(PIN_TRIES, true, PUK_TRIES));

    // VERIFY '81': the PUK is not a key reference VERIFY may verify (Section 3.2.1: "SHALL return
    // the status word '6A 88'").
    rows.add(
        row("VERIFY 81 not verifiable")
            .command(0x20, 0x00, 0x81, PUK)
            .sw(0x6A88)
            .then(PIN_TRIES, false, PUK_TRIES));
    rows.add(
        row("VERIFY 81 empty not verifiable")
            .command(0x20, 0x00, 0x81, null)
            .sw(0x6A88)
            .then(PIN_TRIES, false, PUK_TRIES));

    // CHANGE REFERENCE DATA '80' (Section 3.2.2).
    rows.add(
        row("CRD 80 malformed length")
            .command(0x24, 0x00, 0x80, hex("313233343536FFFF393837363534FF"))
            .sw(0x6A80)
            .then(PIN_TRIES, false, PUK_TRIES));
    rows.add(
        row("CRD 80 malformed new PIN")
            .command(0x24, 0x00, 0x80, concat(PIN, MALFORMED_PIN))
            .sw(0x6A80)
            .then(PIN_TRIES, false, PUK_TRIES));
    rows.add(
        row("CRD 80 wrong value")
            .pinVerified()
            .command(0x24, 0x00, 0x80, concat(WRONG_PIN, NEW_PIN))
            .sw(0x63C5)
            .then(5, false, PUK_TRIES)
            .referenceData(PIN, PUK));
    rows.add(
        row("CRD 80 blocked")
            .pinTries(0)
            .command(0x24, 0x00, 0x80, concat(PIN, NEW_PIN))
            .sw(0x6983)
            .then(0, false, PUK_TRIES));
    rows.add(
        row("CRD 80 success")
            .pinTries(3)
            .command(0x24, 0x00, 0x80, concat(PIN, NEW_PIN))
            .sw(0x9000)
            .then(PIN_TRIES, true, PUK_TRIES)
            .referenceData(NEW_PIN, PUK));
    rows.add(
        row("CRD 80 contactless without VCI")
            .over(Interface.CONTACTLESS)
            .command(0x24, 0x00, 0x80, concat(PIN, NEW_PIN))
            .sw(0x6982)
            .then(PIN_TRIES, false, PUK_TRIES)
            .referenceData(PIN, PUK));
    // Section 3.2.2: over the VCI "at or below the issuer-specified intermediate retry value ...
    // the PIV Card Application SHALL return the status word '69 83'."
    rows.add(
        row("CRD 80 contactless at reserve")
            .pinTries(1)
            .over(Interface.VCI)
            .command(0x24, 0x00, 0x80, concat(PIN, NEW_PIN))
            .sw(0x6983)
            .then(1, false, PUK_TRIES)
            .referenceData(PIN, PUK));
    rows.add(
        row("CRD 80 contactless wrong value")
            .pinTries(3)
            .over(Interface.VCI)
            .command(0x24, 0x00, 0x80, concat(WRONG_PIN, NEW_PIN))
            .sw(0x63C1)
            .then(2, false, PUK_TRIES));

    // CHANGE REFERENCE DATA '81' (Section 3.2.2).
    rows.add(
        row("CRD 81 malformed length")
            .command(0x24, 0x00, 0x81, hex("3132333435363738A1B2C3D4E5F607"))
            .sw(0x6A80)
            .then(PIN_TRIES, false, PUK_TRIES));
    rows.add(
        row("CRD 81 overlong")
            .command(0x24, 0x00, 0x81, concat(PUK, NEW_PUK, hex("00")))
            .sw(0x6A80)
            .then(PIN_TRIES, false, PUK_TRIES));
    rows.add(
        row("CRD 81 wrong value")
            .command(0x24, 0x00, 0x81, concat(WRONG_PUK, NEW_PUK))
            .sw(0x63C9)
            .then(PIN_TRIES, false, 9)
            .referenceData(PIN, PUK));
    rows.add(
        row("CRD 81 last wrong value")
            .pukTries(1)
            .command(0x24, 0x00, 0x81, concat(WRONG_PUK, NEW_PUK))
            .sw(0x63C0)
            .then(PIN_TRIES, false, 0));
    rows.add(
        row("CRD 81 blocked")
            .pukTries(0)
            .command(0x24, 0x00, 0x81, concat(PUK, NEW_PUK))
            .sw(0x6983)
            .then(PIN_TRIES, false, 0));
    rows.add(
        row("CRD 81 success")
            .pukTries(4)
            .pinVerified()
            .command(0x24, 0x00, 0x81, concat(PUK, NEW_PUK))
            .sw(0x9000)
            .then(PIN_TRIES, true, PUK_TRIES)
            .referenceData(PIN, NEW_PUK));
    // Section 3.2.2: "If key reference '81' is specified and the command is not submitted over the
    // contact interface, then the card command SHALL fail." The FIPS profile reports the command
    // as unsupported over contactless.
    rows.add(
        row("CRD 81 contactless")
            .over(Interface.CONTACTLESS)
            .command(0x24, 0x00, 0x81, concat(PUK, NEW_PUK))
            .sw(0x6982)
            .fipsSw(0x6A81)
            .then(PIN_TRIES, false, PUK_TRIES)
            .referenceData(PIN, PUK));
    rows.add(
        row("CRD 81 over VCI")
            .over(Interface.VCI)
            .command(0x24, 0x00, 0x81, concat(PUK, NEW_PUK))
            .sw(0x6982)
            .fipsSw(0x6A81)
            .then(PIN_TRIES, false, PUK_TRIES)
            .referenceData(PIN, PUK));
    // An unprovisioned PUK holds only the random install value: no presented value is accepted.
    rows.add(
        row("CRD 81 unprovisioned PUK")
            .unprovisioned()
            .command(0x24, 0x00, 0x81, concat(PUK, NEW_PUK))
            .sw(0x63C9)
            .then(PIN_TRIES, false, 9));

    // RESET RETRY COUNTER (Section 3.2.3).
    rows.add(
        row("RRC malformed length")
            .pinTries(0)
            .command(0x2C, 0x00, 0x80, hex("3132333435363738393837363534FF"))
            .sw(0x6A80)
            .then(0, false, PUK_TRIES));
    // "If the new reference data (PIN) ... does not satisfy the criteria in Sec. 2.4.3, then the
    // PIV Card Application SHALL return the status word '6A 80'", with the PUK retry counter
    // unchanged.
    rows.add(
        row("RRC malformed new PIN")
            .pinTries(0)
            .command(0x2C, 0x00, 0x80, concat(PUK, MALFORMED_PIN))
            .sw(0x6A80)
            .then(0, false, PUK_TRIES));
    // "If the PIV Card Application returns status word '63 CX', then the retry counter associated
    // with the PIN SHALL NOT be reset, the security status of the PIN's key reference SHALL be set
    // to FALSE, and the PUK's retry counter SHALL be decremented by one."
    rows.add(
        row("RRC wrong PUK")
            .pinVerified()
            .command(0x2C, 0x00, 0x80, concat(WRONG_PUK, NEW_PIN))
            .sw(0x63C9)
            .then(PIN_TRIES, false, 9)
            .referenceData(PIN, PUK));
    rows.add(
        row("RRC wrong PUK keeps PIN counter")
            .pinTries(2)
            .command(0x2C, 0x00, 0x80, concat(WRONG_PUK, NEW_PIN))
            .sw(0x63C9)
            .then(2, false, 9));
    rows.add(
        row("RRC last wrong PUK")
            .pukTries(1)
            .command(0x2C, 0x00, 0x80, concat(WRONG_PUK, NEW_PIN))
            .sw(0x63C0)
            .then(PIN_TRIES, false, 0));
    // "If the current value of the PUK's retry counter is zero, then the PIN's retry counter shall
    // not be reset, the PIV Card Application shall return the status word '69 83'".
    rows.add(
        row("RRC blocked PUK")
            .pinTries(0)
            .pukTries(0)
            .command(0x2C, 0x00, 0x80, concat(PUK, NEW_PIN))
            .sw(0x6983)
            .then(0, false, 0));
    // "If the card command succeeds, then the PIN's retry counter SHALL be set to its reset retry
    // value ... The security status of the PIN's key reference SHALL NOT be changed."
    rows.add(
        row("RRC success unblocks PIN")
            .pinTries(0)
            .pukTries(5)
            .command(0x2C, 0x00, 0x80, concat(PUK, NEW_PIN))
            .sw(0x9000)
            .then(PIN_TRIES, false, PUK_TRIES)
            .referenceData(NEW_PIN, PUK));
    rows.add(
        row("RRC success keeps PIN security status")
            .pinVerified()
            .command(0x2C, 0x00, 0x80, concat(PUK, NEW_PIN))
            .sw(0x9000)
            .then(PIN_TRIES, true, PUK_TRIES)
            .referenceData(NEW_PIN, PUK));
    // Table 2 marks RESET RETRY COUNTER "No" for contactless: "'6A 81' (Function not supported)".
    // The contactless reserve therefore never applies to it.
    rows.add(
        row("RRC contactless")
            .pinTries(0)
            .over(Interface.CONTACTLESS)
            .command(0x2C, 0x00, 0x80, concat(PUK, NEW_PIN))
            .sw(0x6A81)
            .then(0, false, PUK_TRIES)
            .referenceData(null, PUK));
    rows.add(
        row("RRC over VCI")
            .pinTries(0)
            .over(Interface.VCI)
            .command(0x2C, 0x00, 0x80, concat(PUK, NEW_PIN))
            .sw(0x6A81)
            .then(0, false, PUK_TRIES)
            .referenceData(null, PUK));
    rows.add(
        row("RRC P2 81")
            .command(0x2C, 0x00, 0x81, concat(PUK, NEW_PIN))
            .sw(0x6A88)
            .then(PIN_TRIES, false, PUK_TRIES));
    rows.add(
        row("RRC unprovisioned PUK")
            .unprovisioned()
            .command(0x2C, 0x00, 0x80, concat(PUK, NEW_PIN))
            .sw(0x63C9)
            .then(PIN_TRIES, false, 9));
    rows.add(
        row("RRC unprovisioned PUK with all-zero value")
            .unprovisioned()
            .command(0x2C, 0x00, 0x80, concat(new byte[8], NEW_PIN))
            .sw(0x63C9)
            .then(PIN_TRIES, false, 9));
    return rows;
  }

  @Override
  protected boolean provisionsStandardCard() {
    // Rows provision the standard PIN, PUK and 9B themselves unless they test the unprovisioned
    // PUK.
    return false;
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("rows")
  void pinPukCommandMatrix(Row row) throws Exception {
    if (row.provisioned) provisionStandardTestCard();
    if (row.iface == Interface.VCI) {
      assertSw(
          0x9000,
          withMockedScp(
              () -> {
                assertSw(0x9000, selectApplet(), "SELECT before configuration");
                return transmit(0x84, 0xDB, 0xFF, 0xFF, hex("6805A0038301FF"));
              }),
          row + ": enable contactless PIN use");
      satisfyVciCondition();
    }
    assertSw(0x9000, selectApplet(), row + ": SELECT");

    // Starting retry counters, then the starting PIN security status.
    for (int i = PUK_TRIES; i > row.pukTries; i--) {
      assertSw(
          0x63C0 | (i - 1),
          transmit(0x00, 0x2C, 0x00, 0x80, concat(WRONG_PUK, NEW_PIN)),
          row + ": drive the PUK retry counter");
    }
    for (int i = PIN_TRIES; i > row.pinTries; i--) {
      assertSw(
          0x63C0 | (i - 1),
          transmit(0x00, 0x20, 0x00, 0x80, WRONG_PIN),
          row + ": drive the PIN retry counter");
    }
    if (row.pinVerified) {
      assertEquals(PIN_TRIES, row.pinTries, row + ": a verified PIN has a full retry counter");
      assertSw(0x9000, transmit(0x00, 0x20, 0x00, 0x80, PIN), row + ": verify the PIN");
    }

    final ResponseAPDU[] response = new ResponseAPDU[1];
    Runnable command =
        () ->
            response[0] =
                row.data == null
                    ? transmit(0x00, row.ins, row.p1, row.p2)
                    : transmit(0x00, row.ins, row.p1, row.p2, row.data);
    int expectedSw = FIPS_MODE && row.fipsSw >= 0 ? row.fipsSw : row.sw;
    if (row.iface == Interface.CONTACT) {
      command.run();
      assertSw(expectedSw, response[0], row + ": command");
      assertSw(
          row.pinVerifiedAfter ? 0x9000 : pinTriesSw(row.pinTriesAfter),
          transmit(0x00, 0x20, 0x00, 0x80),
          row + ": PIN security status");
    } else {
      // The applet records the interface at SELECT. Over the VCI the PIN security status is read
      // in the same session: the empty VERIFY reports the retries usable over contactless.
      withContactless(
          () -> {
            assertSw(0x9000, selectApplet(), row + ": SELECT over contactless");
            command.run();
            assertSw(expectedSw, response[0], row + ": command");
            if (row.iface == Interface.VCI) {
              assertSw(
                  row.pinVerifiedAfter
                      ? 0x9000
                      : row.pinTriesAfter == 0
                          ? 0x6983
                          : 0x63C0 | Math.max(0, row.pinTriesAfter - PIN_RESERVE),
                  transmit(0x00, 0x20, 0x00, 0x80),
                  row + ": PIN security status over the VCI");
            }
          });
      assertSw(0x9000, selectApplet(), row + ": SELECT over contact");
    }

    // Read back over the contact interface: PIN and PUK retry counters and reference data.
    assertSw(0x9000, transmit(0x00, 0x20, 0xFF, 0x80), row + ": reset PIN security status");
    assertSw(
        pinTriesSw(row.pinTriesAfter),
        transmit(0x00, 0x20, 0x00, 0x80),
        row + ": PIN retry counter");

    if (row.pinAfter != null) {
      assertSw(
          0x9000,
          transmit(0x00, 0x20, 0x00, 0x80, row.pinAfter),
          row + ": PIN reference data after the command");
    }

    // A wrong PUK reports the PUK retry counter less one.
    assertSw(
        row.pukTriesAfter == 0 ? 0x6983 : 0x63C0 | (row.pukTriesAfter - 1),
        transmit(0x00, 0x2C, 0x00, 0x80, concat(WRONG_PUK, NEW_PIN)),
        row + ": PUK retry counter");
    if (row.pukAfter != null) {
      // CHANGE REFERENCE DATA '81' onto the same value proves the PUK reference data.
      assertSw(
          0x9000,
          transmit(0x00, 0x24, 0x00, 0x81, concat(row.pukAfter, row.pukAfter)),
          row + ": PUK reference data after the command");
    }
  }

  private static int pinTriesSw(int tries) {
    return tries == 0 ? 0x6983 : 0x63C0 | tries;
  }

  /**
   * Holds the applet's VCI condition (SP 800-73-5 Part 1 Section 5.5) true for the PIN command
   * handler, as after VCI establishment and pairing, by giving the handler a spy of the PIV
   * instance whose {@code isVciSatisfied()} returns true. Everything else, including the
   * contactless interface, the intermediate retry reserve and the retry counters, is the installed
   * applet's.
   */
  private void satisfyVciCondition() throws Exception {
    Object piv = field(unwrapApplet(engine.getApplet(OPENFIPS201_AID)), "piv");
    Object pinCommands = field(piv, "pinCommands");
    Object spy = Mockito.spy(piv);
    Method isVciSatisfied = piv.getClass().getDeclaredMethod("isVciSatisfied");
    isVciSatisfied.setAccessible(true);
    isVciSatisfied.invoke(Mockito.doReturn(true).when(spy));
    Field owner = pinCommands.getClass().getDeclaredField("owner");
    owner.setAccessible(true);
    owner.set(pinCommands, spy);
  }

  private static Object field(Object target, String name) throws Exception {
    Field field = target.getClass().getDeclaredField(name);
    field.setAccessible(true);
    return field.get(target);
  }

  private static Applet unwrapApplet(Applet appletProxy) throws Exception {
    if (appletProxy.getClass().getName().equals(OpenFIPS201.class.getName())) return appletProxy;
    for (Field proxyField : appletProxy.getClass().getDeclaredFields()) {
      if (!InvocationHandler.class.isAssignableFrom(proxyField.getType())) continue;
      proxyField.setAccessible(true);
      Object handler = proxyField.get(null);
      for (Field handlerField : handler.getClass().getDeclaredFields()) {
        handlerField.setAccessible(true);
        Object value = handlerField.get(handler);
        if (value instanceof Applet
            && value.getClass().getName().equals(OpenFIPS201.class.getName())) {
          return (Applet) value;
        }
      }
    }
    throw new IllegalStateException("Unable to unwrap simulator applet proxy");
  }
}
