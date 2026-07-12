/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.common;

import apdu4j.core.BIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import java.util.EnumSet;
import pro.javacard.capfile.AID;
import pro.javacard.capfile.CAPFile;
import pro.javacard.gp.GPCardKeys;
import pro.javacard.gp.GPCommands;
import pro.javacard.gp.GPData;
import pro.javacard.gp.GPRegistryEntry;
import pro.javacard.gp.GPSecureChannelVersion;
import pro.javacard.gp.GPSession;

public final class GlobalPlatformSession implements CardSession {
  public static final byte[] PIV_AID = HexUtil.parse("A000000308000010000100");
  public static final byte[] ISD_AID = HexUtil.parse("A000000151000000");

  private final BIBO bibo;
  private final GPSession session;
  private final ScpConfig.Mode scpMode;

  private GlobalPlatformSession(BIBO bibo, GPSession session, ScpConfig.Mode scpMode) {
    this.bibo = bibo;
    this.session = session;
    this.scpMode = scpMode;
  }

  public static GlobalPlatformSession open(CardTarget target, byte[] aid, ScpConfig config)
      throws Exception {
    BIBO bibo = target.openBibo();
    try {
      GPSession gp = GPSession.connect(bibo, new AID(aid));
      gp.openSecureChannel(
          config.toPlaintextKeys(),
          toSecureChannelVersion(config.mode),
          null,
          EnumSet.of(GPSession.APDUMode.MAC, GPSession.APDUMode.ENC));
      return new GlobalPlatformSession(bibo, gp, fromSecureChannelVersion(gp.getSecureChannel()));
    } catch (Exception e) {
      bibo.close();
      throw e;
    }
  }

  public GPSession gp() {
    return session;
  }

  public ScpConfig.Mode scpMode() {
    return scpMode;
  }

  public void installCap(
      CAPFile cap, AID packageAid, AID appletAid, AID instanceAid, byte[] params, boolean loadCap)
      throws Exception {
    if (loadCap) {
      GPCommands.load(session, cap, null, null, GPData.LFDBH.SHA256);
    }
    session.installAndMakeSelectable(
        packageAid, appletAid, instanceAid, EnumSet.noneOf(GPRegistryEntry.Privilege.class), params);
  }

  public void putKeys(GPCardKeys keys, boolean replace) throws Exception {
    session.putKeys(keys, replace);
  }

  @Override
  public ResponseAPDU transmit(CommandAPDU command) {
    return session.transmit(command);
  }

  @Override
  public void close() {
    bibo.close();
  }

  private static GPSecureChannelVersion toSecureChannelVersion(ScpConfig.Mode mode) {
    if (mode == ScpConfig.Mode.AUTO) {
      return null;
    }
    return new GPSecureChannelVersion(
        mode == ScpConfig.Mode.SCP02
            ? GPSecureChannelVersion.SCP.SCP02
            : GPSecureChannelVersion.SCP.SCP03,
        0);
  }

  private static ScpConfig.Mode fromSecureChannelVersion(GPSecureChannelVersion version) {
    if (version.scp == GPSecureChannelVersion.SCP.SCP02) {
      return ScpConfig.Mode.SCP02;
    }
    if (version.scp == GPSecureChannelVersion.SCP.SCP03) {
      return ScpConfig.Mode.SCP03;
    }
    throw new IllegalStateException("Unsupported SCP version: " + version);
  }
}
