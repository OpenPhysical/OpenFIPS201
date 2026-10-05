package dev.mistial.tools.openfips201;

import dev.mistial.tools.openfips201.crypto.CertifiedSigningKey;
import dev.mistial.tools.openfips201.crypto.SigningKey;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11Config;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11Session;
import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;

/** Cryptographic provider inspection commands. */
@Command(
    name = "crypto",
    mixinStandardHelpOptions = true,
    description = "Inspect issuer cryptographic providers and keys.",
    subcommands = CryptoCommand.Pkcs11.class)
final class CryptoCommand implements Callable<Integer> {
  @Override
  public Integer call() {
    CommandLine.usage(this, System.err);
    return 2;
  }

  @Command(
      name = "pkcs11",
      mixinStandardHelpOptions = true,
      description = "Inspect a PKCS#11 token and signing-key selection.",
      subcommands = Pkcs11.List.class)
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
        Pkcs11Config selection = pkcs11();
        try (Pkcs11Session session = Pkcs11Session.open(selection)) {
          // The selected key must carry a certificate for the same public key.
          SigningKey key = CertifiedSigningKey.of(session.signingKey(selection));
          System.out.println("Selected " + key.description());
          System.out.println(key.publicKey().getAlgorithm() + " public key available");
          System.out.println(
              "Certificate " + key.certificate().getSubjectX500Principal().getName());
        }
        return 0;
      }
    }
  }
}
