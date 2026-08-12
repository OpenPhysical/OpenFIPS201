package dev.mistial.tools.openfips201.nist;

import com.tvec.smart_card.piv.apdu.tests.TestClassFactory;
import com.tvec.testrunner.gui.TestRunnerUtils;
import com.tvec.testrunner.gui.displays.testmanager.TestRunner;
import com.tvec.testrunner.gui.displays.testmanager.TestSpecification;
import com.tvec.testrunner.gui.displays.testmanager.testdata.Inputs;
import com.tvec.testrunner.gui.displays.testmanager.testdata.TestImpl;
import com.tvec.testrunner.gui.displays.testmanager.testdata.TestResult;
import com.tvec.testrunner.gui.displays.testmanager.testdata.TestVector;
import com.tvec.testrunner.gui.displays.testmanager.testdata.TestVectors;
import com.tvec.utility.Context;
import com.tvec.utility.configuration.Configuration;
import com.tvec.utility.configuration.ConfigurationEntry;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.provisioning.ConformancePackage;
import dev.mistial.tools.openfips201.provisioning.ConformanceProvisioner;
import dev.mistial.tools.openfips201.provisioning.IcamCardFolder;
import dev.mistial.tools.openfips201.vci.NativeVciProfile;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public final class NistHarnessMain {
  private static final String CONTACT = "CONTACT";
  private static final String CONTACTLESS = "CONTACTLESS";

  private NistHarnessMain() {}

  public static void main(String[] args) throws Exception {
    Options options = Options.parse(args);
    if (options.help) {
      Options.printUsage();
      return;
    }

    if (!"emulator".equals(options.target)) {
      throw new IllegalArgumentException("Only --target emulator is currently implemented");
    }

    File configFile = new File(options.config);
    if (!configFile.isFile()) {
      throw new IllegalArgumentException("Configuration does not exist: " + configFile);
    }

    new File(options.out).mkdirs();
    Configuration configuration = new Configuration(configFile);
    patchConfiguration(configuration, options);

    List<TestVector> vectors = loadVectors(configuration);
    if (options.listTests) {
      listTests(vectors);
      return;
    }

    List<TestVector> selected = select(vectors, options);
    if (selected.isEmpty()) {
      throw new IllegalArgumentException("No NIST test vectors matched the requested selection");
    }

    NativeVciProfile.Material nativeVci = null;
    ConformancePackage profile;
    if (options.vciSuite != null) {
      if (options.icam == null) {
        throw new IllegalArgumentException("--vci requires --icam identity material");
      }
      Path materialDirectory = Paths.get(options.out, "native-vci");
      Files.createDirectories(materialDirectory);
      byte suite =
          "cs7".equals(options.vciSuite)
              ? NativeVciProfile.SUITE_CS7
              : NativeVciProfile.SUITE_CS2;
      nativeVci =
          NativeVciProfile.build(
              Paths.get(options.icam),
              materialDirectory.resolve("content-signer").toString(),
              options.pairingCode,
              suite);
      profile = nativeVci.profile;
    } else {
      profile = options.icam == null ? null : IcamCardFolder.load(Paths.get(options.icam));
    }
    if (profile != null) {
      patchProfileConfiguration(configuration, profile, nativeVci);
    }
    List<HarnessResult> results = new ArrayList<HarnessResult>();
    int failures = 0;
    if (profile != null && selected.size() > 1 && !options.sharedCard) {
      for (TestVector vector : selected) {
        failures +=
            runOnCard(
                configuration,
                java.util.Collections.singletonList(vector),
                profile,
                nativeVci,
                results);
      }
    } else {
      failures = runOnCard(configuration, selected, profile, nativeVci, results);
    }
    writeJUnitSummary(Paths.get(options.out, "nist-results.xml"), results);
    if (failures != 0) {
      throw new IllegalStateException(failures + " NIST test vector(s) failed");
    }
  }

  private static int runOnCard(
      Configuration configuration,
      List<TestVector> selected,
      ConformancePackage profile,
      NativeVciProfile.Material nativeVci,
      List<HarnessResult> results)
      throws Exception {
    try (JCardEngineNistCardTransport.SharedCard card = JCardEngineNistCardTransport.createCard();
        NistCardTransport contact = new JCardEngineNistCardTransport(card, "T=1");
        NistCardTransport contactless = new JCardEngineNistCardTransport(card, "T=CL")) {
      if (profile != null) {
        ConformanceProvisioner.provision(
            card.openBibo("T=1"), ScpConfig.defaultTestScp03(), profile, System.out);
      }
      if (nativeVci != null) {
        NativeVciProfile.provisionSmCredential(card.openBibo("T=1"), nativeVci);
      }
      installProvider(contact, contactless);
      return runTests(configuration, selected, results);
    }
  }

  private static void installProvider(
      NistCardTransport contact, NistCardTransport contactless) {
    OpenFips201TerminalFactorySpi.install(contact, contactless);
    if (Security.getProvider(OpenFips201NistProvider.PROVIDER_NAME) == null) {
      Security.insertProviderAt(new OpenFips201NistProvider(), 1);
    }
    System.setProperty(
        "javax.smartcardio.TerminalFactory.DefaultType", OpenFips201NistProvider.TERMINAL_TYPE);
  }

  private static void patchConfiguration(Configuration configuration, Options options) {
    setEntry(
        configuration,
        "connectivity:CONTACT_READER_NAME",
        OpenFips201TerminalFactorySpi.CONTACT_READER);
    setEntry(
        configuration,
        "connectivity:CONTACTLESS_READER_NAME",
        OpenFips201TerminalFactorySpi.CONTACTLESS_READER);
    setEntry(configuration, "testing:PAIRING_CODE", options.pairingCode);
    setEntry(configuration, "testing:output:TestMainPath", options.out);
    setEntry(
        configuration, "testing:output:TestResultPath", options.out + File.separator + "results");
    setEntry(
        configuration,
        "testing:output:ContainerBufferPath",
        options.out + File.separator + "buffer");
    setEntry(configuration, "testing:output:TestLogPath", options.out + File.separator + "log");
  }

  private static void setEntry(Configuration configuration, String name, String value) {
    ConfigurationEntry entry = configuration.getEntry(name);
    if (entry == null) {
      throw new IllegalArgumentException("Configuration entry is missing: " + name);
    }
    entry.setValue(value);
  }

  private static void patchProfileConfiguration(
      Configuration configuration, ConformancePackage profile, NativeVciProfile.Material nativeVci)
      throws Exception {
    for (ConformancePackage.KeyMaterial key : profile.keys) {
      String algorithm = String.format("%02X", key.algorithm & 0xFF);
      if (key.slot == (byte) 0x9A) {
        setEntry(configuration, "testing:KEY_ALGORITHMS_AUTHENTICATION", algorithm);
        setEntry(configuration, "testing:GENERAL_AUTH_ALGORITHM_PIV_AUTHENTICATION_KEY", algorithm);
      } else if (key.slot == (byte) 0x9C) {
        setEntry(configuration, "testing:KEY_ALGORITHMS_DIGITAL_SIGNATURE", algorithm);
      } else if (key.slot == (byte) 0x9D) {
        setEntry(configuration, "testing:KEY_ALGORITHMS_KEY_MANAGEMENT", algorithm);
      } else if (key.slot == (byte) 0x9E) {
        setEntry(configuration, "testing:KEY_ALGORITHMS_CARD_AUTHENTICATION", algorithm);
      }
      if (key.certificate != null) {
        setEntry(
            configuration,
            "testing:keytypealgorithmkeys:KEY_"
                + String.format("%02X", key.slot & 0xFF)
                + "_"
                + algorithm,
            pemCertificate(key.certificate.getEncoded()));
      }
    }
    if (nativeVci != null) {
      setEntry(
          configuration,
          "testing:KEY_ALGORITHMS_SECURE_MESSAGING",
          String.format("%02X", nativeVci.suite & 0xFF));
    }
  }

  private static String pemCertificate(byte[] encoded) {
    String body = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(encoded);
    return "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----";
  }

  private static List<TestVector> loadVectors(Configuration configuration) {
    List<TestVector> vectors = new ArrayList<TestVector>();
    String[] subsystemNames = TestRunnerUtils.getSubsystemNames(configuration);
    for (String subsystemName : subsystemNames) {
      TestVectors subsystemVectors = TestRunnerUtils.getTestVectors(configuration, subsystemName);
      for (TestVector vector : subsystemVectors.getTestVectorArray()) {
        vectors.add(vector);
      }
    }
    return vectors;
  }

  private static void listTests(List<TestVector> vectors) {
    for (TestVector vector : vectors) {
      System.out.println(testName(vector) + " " + testInterface(vector));
    }
  }

  private static List<TestVector> select(List<TestVector> vectors, Options options) {
    List<TestVector> selected = new ArrayList<TestVector>();
    for (TestVector vector : vectors) {
      if (options.test != null && !options.test.equals(testName(vector))) {
        continue;
      }
      if (options.suite != null && !suiteMatches(options.suite, vector)) {
        continue;
      }
      selected.add(vector);
      if (options.limit > 0 && selected.size() >= options.limit) {
        break;
      }
    }
    return selected;
  }

  private static boolean suiteMatches(String suite, TestVector vector) {
    if ("all".equals(suite)) {
      return true;
    }
    String testInterface = testInterface(vector);
    if ("contact".equals(suite)) {
      return CONTACT.equalsIgnoreCase(testInterface);
    }
    if ("contactless".equals(suite)) {
      return CONTACTLESS.equalsIgnoreCase(testInterface);
    }
    if (suite.startsWith("card-")) {
      String requestedInterface = suite.substring("card-".length());
      return !vector.getSubsystemName().startsWith("piv")
          && requestedInterface.equalsIgnoreCase(testInterface);
    }
    if (suite.equalsIgnoreCase(testInterface)) {
      return true;
    }
    return vector.getSubsystemName().equalsIgnoreCase(suite);
  }

  private static int runTests(
      Configuration configuration, List<TestVector> selected, List<HarnessResult> results) {
    int failures = 0;
    TestClassFactory factory = new TestClassFactory();
    for (int index = 0; index < selected.size(); index++) {
      TestVector vector = selected.get(index);
      String name = testName(vector);
      TestSpecification specification =
          new TestSpecification(configuration, vector.getSubsystemName(), vector.getID());
      specification.setTestVectorInfo(selected.size(), vector);
      TestRunner runner = new TestRunner(null, specification);
      TestImpl test = factory.getTestClass(runner, vector, new Context());
      TestResult result = null;
      boolean passed = false;
      String failure = null;
      try {
        System.out.println("RUN " + (index + 1) + "/" + selected.size() + " " + name);
        OpenFips201TerminalFactorySpi.reset(testInterface(vector));
        test.setupTest();
        result = test.runTest();
        String resultText = result == null ? "error" : result.getResultCodeText();
        if (isPassingResult(resultText)) {
          passed = true;
          System.out.println(resultText.toUpperCase() + " " + name);
        } else {
          failure = resultText;
          System.out.println("FAIL " + name + " " + resultText);
          printResultDetails(result);
        }
      } catch (Exception | LinkageError e) {
        failure = e.toString();
        System.out.println("ERROR " + name + " " + e.getMessage());
        e.printStackTrace(System.out);
      } finally {
        try {
          test.cleanupTest();
        } catch (Exception e) {
          passed = false;
          failure = "cleanup failed: " + e;
          System.out.println("ERROR " + name + " cleanup failed: " + e.getMessage());
          e.printStackTrace(System.out);
        }
      }
      if (!passed) {
        failures++;
      }
      results.add(new HarnessResult(name, passed, failure));
    }
    return failures;
  }

  private static void writeJUnitSummary(Path output, List<HarnessResult> results) throws Exception {
    int failures = 0;
    StringBuilder xml = new StringBuilder();
    for (HarnessResult result : results) {
      if (!result.passed) failures++;
    }
    xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.append("<testsuite name=\"OpenFIPS201 NIST\" tests=\"")
        .append(results.size())
        .append("\" failures=\"")
        .append(failures)
        .append("\">\n");
    for (HarnessResult result : results) {
      xml.append("  <testcase classname=\"nist.card\" name=\"")
          .append(xmlEscape(result.name))
          .append("\">");
      if (!result.passed) {
        xml.append("<failure message=\"")
            .append(xmlEscape(result.failure == null ? "failed" : result.failure))
            .append("\"/>");
      }
      xml.append("</testcase>\n");
    }
    xml.append("</testsuite>\n");
    Files.write(output, xml.toString().getBytes(StandardCharsets.UTF_8));
    System.out.println("WROTE " + output);
  }

  private static String xmlEscape(String value) {
    return value.replace("&", "&amp;")
        .replace("\"", "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;");
  }

  private static final class HarnessResult {
    final String name;
    final boolean passed;
    final String failure;

    HarnessResult(String name, boolean passed, String failure) {
      this.name = name;
      this.passed = passed;
      this.failure = failure;
    }
  }

  private static void printResultDetails(TestResult result) {
    if (result == null) {
      return;
    }
    for (Object expected : result.getExpectedResults()) {
      System.out.println("  expected: " + expected);
    }
    for (Object actual : result.getActualResults()) {
      System.out.println("  actual: " + actual);
    }
    String userText = result.getUserDefinedText();
    if (userText != null && userText.length() != 0) {
      System.out.println("  detail: " + userText);
    }
  }

  private static boolean isPassingResult(String resultText) {
    return "pass".equalsIgnoreCase(resultText)
        || "true".equalsIgnoreCase(resultText);
  }

  private static String testName(TestVector vector) {
    return vector.getSubsystemName() + ":" + vector.getID();
  }

  private static String testInterface(TestVector vector) {
    Inputs inputs = vector.getInputs();
    if (inputs == null) {
      return "";
    }
    String value = inputs.getString("TestInterface");
    return value == null ? "" : value;
  }

  private static final class Options {
    String target = "emulator";
    String config = "tools/piv_test_runner/config/OpenFIPS201.xml";
    String out = "tools/piv_test_runner/piv_tests/harness";
    String suite;
    String test;
    String icam;
    String vciSuite;
    String pairingCode = "12345678";
    int limit;
    boolean listTests;
    boolean fips;
    boolean sharedCard;
    boolean help;

    static Options parse(String[] args) {
      Options options = new Options();
      for (int i = 0; i < args.length; i++) {
        String arg = args[i];
        if ("--help".equals(arg) || "-h".equals(arg)) {
          options.help = true;
        } else if ("--list-tests".equals(arg)) {
          options.listTests = true;
        } else if ("--fips".equals(arg)) {
          options.fips = true;
        } else if ("--shared-card".equals(arg)) {
          options.sharedCard = true;
        } else if ("--target".equals(arg)) {
          options.target = requireValue(args, ++i, arg);
        } else if ("--config".equals(arg)) {
          options.config = requireValue(args, ++i, arg);
        } else if ("--out".equals(arg)) {
          options.out = requireValue(args, ++i, arg);
        } else if ("--suite".equals(arg)) {
          options.suite = requireValue(args, ++i, arg);
        } else if ("--test".equals(arg)) {
          options.test = requireValue(args, ++i, arg);
        } else if ("--icam".equals(arg)) {
          options.icam = requireValue(args, ++i, arg);
        } else if ("--vci".equals(arg)) {
          options.vciSuite = requireValue(args, ++i, arg).toLowerCase();
          if (!"cs2".equals(options.vciSuite) && !"cs7".equals(options.vciSuite)) {
            throw new IllegalArgumentException("--vci must be cs2 or cs7");
          }
        } else if ("--pairing-code".equals(arg)) {
          options.pairingCode = requireValue(args, ++i, arg);
        } else if ("--limit".equals(arg)) {
          options.limit = Integer.parseInt(requireValue(args, ++i, arg));
        } else {
          throw new IllegalArgumentException("Unknown option: " + arg);
        }
      }
      if (!options.listTests && options.suite == null && options.test == null) {
        throw new IllegalArgumentException("Select tests with --suite, --test, or --list-tests");
      }
      return options;
    }

    private static String requireValue(String[] args, int index, String option) {
      if (index >= args.length) {
        throw new IllegalArgumentException(option + " requires a value");
      }
      return args[index];
    }

    static void printUsage() {
      System.out.println("Usage: run-nist-harness.sh [options]");
      System.out.println(
          "  --target emulator        Use the in-process OpenFIPS201 JCardEngine target");
      System.out.println("  --config FILE            NIST Test Runner configuration XML");
      System.out.println("  --out DIR                Local output directory");
      System.out.println("  --fips                   Compile and test the FIPS_MODE applet profile");
      System.out.println("  --list-tests             List available NIST vectors");
      System.out.println(
          "  --suite contact          Run an interface, card-<interface>, all, or subsystem");
      System.out.println("  --test Subsystem:Id      Run one vector, for example SelectCommand:1");
      System.out.println("  --icam DIR               Provision a GSA ICAM card folder before testing");
      System.out.println("  --vci cs2|cs7           Build a signed native Part 1 VCI profile");
      System.out.println("  --pairing-code 12345678 Eight-digit test-card pairing code");
      System.out.println("  --shared-card            Preserve one ICAM image across multiple vectors");
      System.out.println("  --limit N                Stop after N selected vectors");
    }
  }
}
