package dev.mistial.tools.openfips201.nist;

import java.security.Provider;

public final class OpenFips201NistProvider extends Provider {
  static final String PROVIDER_NAME = "OpenFIPS201-NIST";
  static final String TERMINAL_TYPE = "OpenFIPS201Emulator";

  public OpenFips201NistProvider() {
    super(PROVIDER_NAME, "1.0", "OpenFIPS201 NIST Test Runner SmartcardIO adapter");
    put("TerminalFactory." + TERMINAL_TYPE, OpenFips201TerminalFactorySpi.class.getName());
  }
}
