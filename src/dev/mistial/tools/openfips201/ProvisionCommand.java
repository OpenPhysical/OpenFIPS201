package dev.mistial.tools.openfips201;

import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.provisioning.CertificationProfileValidator;
import dev.mistial.tools.openfips201.provisioning.ConformancePackage;
import dev.mistial.tools.openfips201.provisioning.ConformanceProvisioner;
import dev.mistial.tools.openfips201.provisioning.IcamCardFolder;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/** Loads, validates, and applies a GSA ICAM card folder. */
@Command(
    name = "provision",
    mixinStandardHelpOptions = true,
    description = "Provision OpenFIPS201 from a GSA ICAM card folder over SCP03.")
final class ProvisionCommand extends ScpOptions implements Callable<Integer> {
  @Option(names = "--icam", required = true, description = "GSA ICAM card-builder folder.")
  Path icam;

  @Option(names = "--p12-password", description = "Password for ICAM PKCS#12 files.")
  String p12Password;

  @Option(names = "--certification-profile", description = "Validate, provision, and personalize.")
  boolean certificationProfile;

  @Option(names = "--government-email", description = "Require conditional 9C/9D material.")
  boolean governmentEmail;

  @Option(names = "--vci", description = "Require Discovery to advertise VCI.")
  boolean vci;

  @Option(names = "--pairing-required", description = "Require the VCI pairing-code policy.")
  boolean pairingRequired;

  @Override
  public Integer call() throws Exception {
    char[] password =
        p12Password == null ? IcamCardFolder.DEFAULT_P12_PASSWORD : p12Password.toCharArray();
    ConformancePackage pkg = IcamCardFolder.load(icam, password);
    System.out.println(
        "Loaded ICAM folder "
            + pkg.credentialId
            + ": "
            + pkg.dataObjects.size()
            + " objects, "
            + pkg.keys.size()
            + " keys");
    ConformanceProvisioner.ProvisionReport report;
    if (certificationProfile) {
      report =
          ConformanceProvisioner.provisionCertificationProfile(
              CardTarget.parse(target),
              scp(),
              pkg,
              new CertificationProfileValidator.Claims(governmentEmail, vci, pairingRequired),
              System.out);
      System.out.println("Personalized validated certification profile");
    } else {
      report = ConformanceProvisioner.provision(CardTarget.parse(target), scp(), pkg, System.out);
    }
    System.out.println(
        "Done: "
            + report.objectsCreated
            + " objects, "
            + report.keysImported
            + " keys ("
            + report.credentialId
            + ")");
    return 0;
  }
}
