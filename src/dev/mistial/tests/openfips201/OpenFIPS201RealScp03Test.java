package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.makina.security.openfips201.OpenFIPS201;
import java.util.EnumSet;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.engine.globalplatform.SCPConfig;
import pro.javacard.gp.GPRegistryEntry;
import pro.javacard.gp.GPSecureChannelVersion;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.keys.PlaintextKeys;

/**
 * Proves OpenFIPS201 can run against jCardEngine's real GlobalPlatform SCP03 stack.
 *
 * <p>The existing mocked-SCP tests keep narrow parser coverage. This class installs the applet
 * through the real GlobalPlatform card-content lifecycle (load file registration, SCP03 to the ISD,
 * INSTALL [for install and make selectable]) and then establishes SCP03 through GPPro, so emulator
 * transport work has a real secure-channel baseline that matches how a physical card is
 * provisioned.
 *
 * <p>NOTE: these tests require that the GlobalPlatform export jar (compile-time API stubs whose
 * {@code GPSystem.getSecureChannel()} returns null) is kept OFF the test runtime classpath, so the
 * applet resolves jCardEngine's functional {@code org.globalplatform} implementation. See the
 * {@code test.runtime.classpath} note in build/build.xml.
 */
@Timeout(value = 20, unit = TimeUnit.SECONDS)
class OpenFIPS201RealScp03Test extends OpenFIPS201TestSupport {
  private static final byte[] TEST_SCP03_KEY = PlaintextKeys.DEFAULT_KEY();
  private static final byte[] ISD_AID_BYTES = {
    (byte) 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00
  };

  @Override
  protected JavaCardEngine createEngine() {
    return new JavaCardEngine.Builder().withSCP(new SCPConfig.SCP03(TEST_SCP03_KEY, false)).build();
  }

  /** Exercises real SCP03 transport; the mocked-SCP standard test card must not be applied. */
  @Override
  protected boolean provisionsStandardCard() {
    return false;
  }

  /**
   * Installs OpenFIPS201 exactly like a real GP card is provisioned: register the load file (the
   * in-process analog of loading the CAP), open SCP03 against the ISD, and issue a real INSTALL
   * [for install and make selectable] APDU so the issuer security domain itself instantiates and
   * registers the applet.
   */
  @Override
  protected void installApplet() {
    engine.loadApplet(OPENFIPS201_PACKAGE_AID, OPENFIPS201_AID, OpenFIPS201.class);

    apdu4j.core.BIBO adminSession = engine.connect();
    try {
      GPSession gp = openIsdSecureChannel(adminSession);
      gp.installAndMakeSelectable(
          new pro.javacard.capfile.AID(OPENFIPS201_PACKAGE_AID_BYTES),
          new pro.javacard.capfile.AID(OPENFIPS201_AID_BYTES),
          new pro.javacard.capfile.AID(OPENFIPS201_AID_BYTES),
          EnumSet.noneOf(GPRegistryEntry.Privilege.class),
          null);
    } catch (Exception e) {
      throw new IllegalStateException("GlobalPlatform install of OpenFIPS201 failed", e);
    } finally {
      adminSession.close();
    }
  }

  @Test
  void gpProCanOpenRealScp03AgainstJCardEngineSecurityDomain() throws Exception {
    GPSession gp = openIsdSecureChannel(session);

    assertEquals(
        GPSecureChannelVersion.SCP.SCP03,
        gp.getSecureChannel().scp,
        "GPPro should negotiate SCP03 against the jCardEngine-backed ISD");
    assertFalse(
        gp.getKeyInfoTemplate().isEmpty(),
        "A protected ISD GET DATA should succeed after real SCP03 establishment");
  }

  /**
   * Opens SCP03 through the selected OpenFIPS201 applet, which forwards INITIALIZE UPDATE and
   * EXTERNAL AUTHENTICATE to its associated security domain via {@code
   * GPSystem.getSecureChannel().processSecurity()}, then drives a wrapped PIV command through
   * {@code SecureChannel.unwrap()}.
   *
   * <p>This test was previously disabled with a claim that jCardEngine's SCP03 key lookup cannot
   * resolve keys for a directly-installed applet. That was wrong: the actual failure was the GP
   * export stub jar shadowing jCardEngine's functional {@code GPSystem} on the test runtime
   * classpath, making {@code GPSystem.getSecureChannel()} return null inside the applet (a
   * NullPointerException surfacing as SW 0x6F00 on INITIALIZE UPDATE).
   */
  @Test
  void gpProCanOpenRealScp03ThroughOpenFips201SelectedApplet() throws Exception {
    GPSession gp = GPSession.connect(session, new pro.javacard.capfile.AID(OPENFIPS201_AID_BYTES));
    PlaintextKeys keys = PlaintextKeys.fromMasterKey(TEST_SCP03_KEY);
    keys.setVersion(0);
    gp.openSecureChannel(
        keys,
        new GPSecureChannelVersion(GPSecureChannelVersion.SCP.SCP03, 0),
        null,
        EnumSet.of(GPSession.APDUMode.MAC, GPSession.APDUMode.ENC));
    assertEquals(GPSecureChannelVersion.SCP.SCP03, gp.getSecureChannel().scp);

    // Drive a PIV command through the authenticated channel. GPPro wraps it (CLA 0x84, C-MAC +
    // C-ENC), and the applet must unwrap it via SecureChannel.unwrap() before dispatch - the code
    // path the mocked-SCP tests can only fake. GET DATA for the Discovery Object on a
    // pre-personalised card must return SW_FILE_NOT_FOUND: that status is only reachable when the
    // encrypted payload decrypted to a well-formed 5C tag list (a garbled payload fails TLV
    // parsing with a different status word).
    apdu4j.core.ResponseAPDU response =
        gp.transmit(
            new apdu4j.core.CommandAPDU(
                0x00, 0xCB, 0x3F, 0xFF, new byte[] {0x5C, 0x01, 0x7E}, 256));
    assertEquals(
        0x6A82,
        response.getSW(),
        "Wrapped PIV GET DATA should decrypt to a valid tag list and report the (undefined)"
            + " Discovery Object as not found");
  }

  private GPSession openIsdSecureChannel(apdu4j.core.BIBO bibo) throws Exception {
    GPSession gp = GPSession.connect(bibo, new pro.javacard.capfile.AID(ISD_AID_BYTES));
    PlaintextKeys keys = PlaintextKeys.fromMasterKey(TEST_SCP03_KEY);
    keys.setVersion(0);
    gp.openSecureChannel(
        keys,
        new GPSecureChannelVersion(GPSecureChannelVersion.SCP.SCP03, 0),
        null,
        EnumSet.of(GPSession.APDUMode.MAC, GPSession.APDUMode.ENC));
    return gp;
  }
}
