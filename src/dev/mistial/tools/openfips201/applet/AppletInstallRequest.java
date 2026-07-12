/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.applet;

import java.nio.file.Path;

public final class AppletInstallRequest {
  public Path capPath;
  public String packageAid;
  public String appletAid;
  public String instanceAid;
  public boolean loadCap = true;
  public boolean deleteExisting;
}
