/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.applet;

import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.common.HexUtil;
import pro.javacard.capfile.AID;
import pro.javacard.capfile.CAPFile;

public final class AppletInstallService {
  public void install(GlobalPlatformSession session, AppletInstallRequest request)
      throws Exception {
    CAPFile cap = CAPFile.fromFile(request.capPath);
    AID packageAid = new AID(HexUtil.parse(request.packageAid));
    AID appletAid = new AID(HexUtil.parse(request.appletAid));
    AID instanceAid = new AID(HexUtil.parse(request.instanceAid));

    if (request.deleteExisting) {
      tryDelete(session, instanceAid);
      tryDelete(session, packageAid);
    }

    session.installCap(cap, packageAid, appletAid, instanceAid, new byte[0], request.loadCap);
  }

  private static void tryDelete(GlobalPlatformSession session, AID aid) {
    try {
      session.gp().deleteAID(aid, true);
    } catch (Exception ignored) {
      // Idempotent install profiles use this only as a best-effort cleanup of stock cards.
    }
  }
}
