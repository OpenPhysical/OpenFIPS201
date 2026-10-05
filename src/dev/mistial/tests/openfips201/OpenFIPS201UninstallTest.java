package dev.mistial.tests.openfips201;

import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.lang.reflect.Method;
import javacard.framework.AID;
import javacard.framework.AppletEvent;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Test;

/**
 * uninstall() releases the package-wide engines and codec singletons so the instance can be deleted
 * (JCRE 3.0.5 Section 11.3.4.2), but JC 3.0.5 API AppletEvent states "The Java Card runtime
 * environment will not rollback state automatically if applet deletion fails", and a second
 * instance of the package shares those statics. Every surviving instance must remain operational.
 */
class OpenFIPS201UninstallTest extends OpenFIPS201TestSupport {
  private static final byte[] SECOND_AID_BYTES = hex("A00000030800001000010002");

  @Test
  void instanceRemainsOperationalWhenDeletionFailsAfterUninstall() throws Exception {
    assertOperational("before uninstall");

    try (AutoCloseable ignored = enterEngineContext()) {
      ((AppletEvent) engine.getApplet(OPENFIPS201_AID)).uninstall();
    }

    assertOperational("after an uninstall whose deletion did not complete");
  }

  @Test
  void deletingAnotherInstanceLeavesThisInstanceOperational() {
    AID second = new AID(SECOND_AID_BYTES, (short) 0, (byte) SECOND_AID_BYTES.length);
    engine.installApplet(second, com.makina.security.openfips201.OpenFIPS201.class, new byte[0]);
    engine.deleteApplet(second);

    assertOperational("after deleting a second instance of the package");
  }

  /** Exercises the random-number engine, the TLV codecs and the AES engine. */
  private void assertOperational(String context) {
    ResponseAPDU response =
        authenticateCardManagementKeyResponse(
            StandardCardProfile.ADMIN_KEY_ALG, StandardCardProfile.ADMIN_KEY);
    assertSw(0x9000, response, "9B challenge-response authentication " + context);
  }

  private AutoCloseable enterEngineContext() throws Exception {
    Method asCurrent = engine.getClass().getMethod("asCurrent");
    asCurrent.setAccessible(true);
    return (AutoCloseable) asCurrent.invoke(engine);
  }
}
