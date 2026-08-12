package dev.mistial.tools.openfips201;

import dev.mistial.tools.openfips201.crypto.SigningKey;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11SigningKey;
import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;

/** Cryptographic provider inspection commands. */
@Command(name = "crypto", mixinStandardHelpOptions = true, subcommands = CryptoCommand.Pkcs11.class)
final class CryptoCommand implements Callable<Integer> {
  @Override
  public Integer call() {
    CommandLine.usage(this, System.err);
    return 2;
  }

  @Command(name = "pkcs11", mixinStandardHelpOptions = true, subcommands = Pkcs11.List.class)
  static final class Pkcs11 implements Callable<Integer> {
    @Override
    public Integer call() {
      CommandLine.usage(this, System.err);
      return 2;
    }

    @Command(
        name = "list",
        mixinStandardHelpOptions = true,
        description = "Validate a token/key selection.")
    static final class List extends Pkcs11Options implements Callable<Integer> {
      @Override
      public Integer call() throws Exception {
        SigningKey key = new Pkcs11SigningKey(pkcs11());
        System.out.println("Selected " + key.description());
        System.out.println(key.publicKey().getAlgorithm() + " public key available");
        return 0;
      }
    }
  }
}
