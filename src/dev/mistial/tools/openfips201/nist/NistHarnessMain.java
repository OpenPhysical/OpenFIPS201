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
import java.io.File;
import java.security.Security;
import java.util.ArrayList;
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

    try (NistCardTransport transport = new JCardEngineNistCardTransport()) {
      installProvider(transport);
      int failures = runTests(configuration, selected);
      if (failures != 0) {
        throw new IllegalStateException(failures + " NIST test vector(s) failed");
      }
    }
  }

  private static void installProvider(NistCardTransport transport) {
    OpenFips201TerminalFactorySpi.install(transport);
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
    return vector.getSubsystemName().equalsIgnoreCase(suite);
  }

  private static int runTests(Configuration configuration, List<TestVector> selected) {
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
      try {
        System.out.println("RUN " + (index + 1) + "/" + selected.size() + " " + name);
        test.setupTest();
        result = test.runTest();
        String resultText = result == null ? "error" : result.getResultCodeText();
        if (isPassingResult(resultText)) {
          System.out.println(resultText.toUpperCase() + " " + name);
        } else {
          failures++;
          System.out.println("FAIL " + name + " " + resultText);
          printResultDetails(result);
        }
      } catch (Exception e) {
        failures++;
        System.out.println("ERROR " + name + " " + e.getMessage());
        e.printStackTrace(System.out);
      } finally {
        try {
          test.cleanupTest();
        } catch (Exception e) {
          failures++;
          System.out.println("ERROR " + name + " cleanup failed: " + e.getMessage());
          e.printStackTrace(System.out);
        }
      }
    }
    return failures;
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
        || "true".equalsIgnoreCase(resultText)
        || "skip".equalsIgnoreCase(resultText);
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
    int limit;
    boolean listTests;
    boolean help;

    static Options parse(String[] args) {
      Options options = new Options();
      for (int i = 0; i < args.length; i++) {
        String arg = args[i];
        if ("--help".equals(arg) || "-h".equals(arg)) {
          options.help = true;
        } else if ("--list-tests".equals(arg)) {
          options.listTests = true;
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
      System.out.println("  --list-tests             List available NIST vectors");
      System.out.println(
          "  --suite contact          Run contact, contactless, all, or a subsystem name");
      System.out.println("  --test Subsystem:Id      Run one vector, for example SelectCommand:1");
      System.out.println("  --limit N                Stop after N selected vectors");
    }
  }
}
