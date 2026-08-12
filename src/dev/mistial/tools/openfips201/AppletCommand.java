package dev.mistial.tools.openfips201;

import dev.mistial.tools.openfips201.applet.AppletInstallRequest;
import dev.mistial.tools.openfips201.applet.AppletInstallService;
import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/** CAP installation commands. */
@Command(
    name = "applet",
    mixinStandardHelpOptions = true,
    subcommands = AppletCommand.Install.class)
final class AppletCommand implements Callable<Integer> {
  @Override
  public Integer call() {
    CommandLine.usage(this, System.err);
    return 2;
  }

  @Command(
      name = "install",
      mixinStandardHelpOptions = true,
      description = "Load and install the CAP.")
  static final class Install extends ScpOptions implements Callable<Integer> {
    @Option(names = "--cap", required = true)
    Path cap;

    @Option(names = "--package-aid", defaultValue = "A00000030800001000")
    String packageAid;

    @Option(names = "--applet-aid", defaultValue = "A000000308000010000100")
    String appletAid;

    @Option(names = "--instance-aid", defaultValue = "A000000308000010000100")
    String instanceAid;

    @Option(names = "--delete-existing")
    boolean deleteExisting;

    @Option(names = "--skip-load", description = "Install an already registered package.")
    boolean skipLoad;

    @Override
    public Integer call() throws Exception {
      AppletInstallRequest request = new AppletInstallRequest();
      request.capPath = cap;
      request.packageAid = packageAid;
      request.appletAid = appletAid;
      request.instanceAid = instanceAid;
      request.loadCap = !skipLoad;
      request.deleteExisting = deleteExisting;
      try (GlobalPlatformSession session =
          GlobalPlatformSession.open(
              CardTarget.parse(target), GlobalPlatformSession.ISD_AID, scp())) {
        new AppletInstallService().install(session, request);
      }
      System.out.println("Applet installed.");
      return 0;
    }
  }
}
