package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.makina.security.openfips201.OpenFIPS201;
import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Test;

/**
 * Applet-level coverage of the FIPS power-up self-test error state.
 *
 * <p>{@code OpenFIPS201.ensureFipsOperational()} runs the CASTs on the first command after each
 * card reset, before any command processing. A failure latches the error state in CLEAR_ON_RESET
 * memory: every command, including SELECT, then returns 6F00 without touching keys or reference
 * data until the next reset re-runs the self-tests.
 */
class OpenFIPS201FipsSelfTestFailureTest extends OpenFIPS201TestSupport {
  private static final byte[] WRONG_PIN = {'9', '9', '9', '9', '9', '9', (byte) 0xFF, (byte) 0xFF};
  private static final byte[] GET_DATA_CHUID = {0x5C, 0x03, 0x5F, (byte) 0xC1, 0x02};
  private static final byte[] WITNESS_REQUEST = {0x7C, 0x02, (byte) 0x80, 0x00};

  @Test
  void failedPowerUpSelfTestLatchesErrorState() throws Exception {
    assumeTrue(Boolean.getBoolean("fips.mode"), "power-up self-tests run in the FIPS profile only");

    assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before the self-test failure");
    int retriesBefore = assert63cxAndGetRetries(verifyStatus(), "PIN status before failure");
    int getDataBefore = transmit(0x00, 0xCB, 0x3F, 0xFF, GET_DATA_CHUID, 256).getSW();

    byte[] knownAnswer = selfTestVector("AES_ENCRYPT_ZERO");
    byte original = knownAnswer[0];
    knownAnswer[0] ^= (byte) 1;
    try {
      reconnect();
      assertSw(ISO7816.SW_UNKNOWN, selectApplet(), "SELECT after a failed power-up self-test");
      assertSw(
          ISO7816.SW_UNKNOWN,
          transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN),
          "VERIFY in the self-test error state");
      assertSw(
          ISO7816.SW_UNKNOWN,
          transmit(0x00, 0x20, 0x00, 0x80, WRONG_PIN),
          "wrong-PIN VERIFY in the self-test error state");
      assertSw(
          ISO7816.SW_UNKNOWN,
          transmit(0x00, 0x87, StandardCardProfile.ADMIN_KEY_ALG, 0x9B, WITNESS_REQUEST, 256),
          "GENERAL AUTHENTICATE in the self-test error state");
      assertSw(
          ISO7816.SW_UNKNOWN,
          transmit(0x00, 0xCB, 0x3F, 0xFF, GET_DATA_CHUID, 256),
          "GET DATA in the self-test error state");

      // The error state is latched: a passing self-test is not re-attempted before a reset.
      knownAnswer[0] = original;
      assertSw(ISO7816.SW_UNKNOWN, selectApplet(), "SELECT stays latched until reset");
    } finally {
      knownAnswer[0] = original;
    }

    reconnect();
    assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT after reset re-runs the self-tests");
    assertEquals(
        retriesBefore,
        assert63cxAndGetRetries(verifyStatus(), "PIN status after recovery"),
        "commands rejected in the error state must not consume PIN retries");
    assertEquals(
        getDataBefore,
        transmit(0x00, 0xCB, 0x3F, 0xFF, GET_DATA_CHUID, 256).getSW(),
        "GET DATA after recovery");
    assertSw(
        ISO7816.SW_NO_ERROR,
        transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN),
        "the PIN is unchanged after recovery");
  }

  private ResponseAPDU verifyStatus() {
    return transmit(0x00, 0x20, 0x00, 0x80);
  }

  /** Card reset: a session opened with reset-on-close clears CLEAR_ON_RESET memory when closed. */
  private void reconnect() {
    if (session != null) {
      session.close();
    }
    engine.connect("*", true).close();
    session = engine.connect();
  }

  /**
   * Reads a known-answer vector from the isolated class loader that loaded the installed applet.
   */
  private byte[] selfTestVector(String name) throws Exception {
    ClassLoader appletLoader =
        unwrapApplet(engine.getApplet(OPENFIPS201_AID)).getClass().getClassLoader();
    Field field =
        Class.forName("com.makina.security.openfips201.FipsPowerUpSelfTests", true, appletLoader)
            .getDeclaredField(name);
    field.setAccessible(true);
    return (byte[]) field.get(null);
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
