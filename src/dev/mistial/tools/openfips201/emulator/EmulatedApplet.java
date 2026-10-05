/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.emulator;

import com.makina.security.openfips201.OpenFIPS201;
import dev.mistial.openphysical.sam.IssuerSam;
import dev.mistial.tools.openfips201.common.HexUtil;
import javacard.framework.Applet;

/**
 * An applet package the emulator registers so a GlobalPlatform client can install it, as on a card
 * whose package is already loaded.
 */
public final class EmulatedApplet {
  /** The OpenFIPS201 PIV applet. */
  public static final EmulatedApplet PIV =
      new EmulatedApplet("A00000030800001000", "A000000308000010000100", OpenFIPS201.class);

  /** The OpenPhysical Issuer SAM applet. */
  public static final EmulatedApplet SAM =
      new EmulatedApplet(
          "F04F50454E50485953414D", "F04F50454E50485953414D0001000000", IssuerSam.class);

  private final byte[] packageAid;
  private final byte[] appletAid;
  public final Class<? extends Applet> appletClass;

  public EmulatedApplet(String packageAid, String appletAid, Class<? extends Applet> appletClass) {
    this.packageAid = HexUtil.parse(packageAid);
    this.appletAid = HexUtil.parse(appletAid);
    this.appletClass = appletClass;
  }

  public byte[] packageAid() {
    return packageAid.clone();
  }

  public byte[] appletAid() {
    return appletAid.clone();
  }

  /** {@code piv} or {@code sam}. */
  public static EmulatedApplet named(String name) {
    if ("piv".equalsIgnoreCase(name)) {
      return PIV;
    }
    if ("sam".equalsIgnoreCase(name)) {
      return SAM;
    }
    throw new IllegalArgumentException("--applet must be piv or sam");
  }
}
