package dev.mistial.tools.openfips201;

import dev.mistial.tools.openfips201.common.CardTarget;
import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;

/** PC/SC reader discovery commands. */
@Command(
    name = "cards",
    mixinStandardHelpOptions = true,
    subcommands = CardsCommand.ListReaders.class)
final class CardsCommand implements Callable<Integer> {
  @Override
  public Integer call() {
    CommandLine.usage(this, System.err);
    return 2;
  }

  @Command(name = "list", mixinStandardHelpOptions = true, description = "List PC/SC reader names.")
  static final class ListReaders implements Callable<Integer> {
    @Override
    public Integer call() throws Exception {
      CardTarget.listPcscReaders();
      return 0;
    }
  }
}
