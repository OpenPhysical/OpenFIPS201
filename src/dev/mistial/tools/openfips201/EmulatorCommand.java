package dev.mistial.tools.openfips201;

import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.emulator.ZmqApduServer;
import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import pro.javacard.gp.keys.PlaintextKeys;

/** ZeroMQ-backed jCardEngine server commands. */
@Command(
    name = "emulator",
    mixinStandardHelpOptions = true,
    subcommands = EmulatorCommand.Serve.class)
final class EmulatorCommand implements Callable<Integer> {
  @Override
  public Integer call() {
    CommandLine.usage(this, System.err);
    return 2;
  }

  @Command(
      name = "serve",
      mixinStandardHelpOptions = true,
      description = "Serve an emulator over ZeroMQ.")
  static final class Serve implements Callable<Integer> {
    @Option(names = "--endpoint", defaultValue = ZmqApduServer.DEFAULT_ENDPOINT)
    String endpoint;

    @Option(names = "--scp03-key", description = "SCP03 master key hex; defaults to GP test key.")
    String scp03Key;

    @Override
    public Integer call() {
      byte[] key = scp03Key == null ? PlaintextKeys.DEFAULT_KEY() : HexUtil.parse(scp03Key);
      try (ZmqApduServer server = new ZmqApduServer(key)) {
        server.run(
            endpoint,
            bound -> {
              System.out.println("OpenFIPS201 emulator serving on " + bound);
              Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
            });
      }
      return 0;
    }
  }
}
