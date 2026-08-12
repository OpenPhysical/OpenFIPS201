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
import dev.mistial.tools.openfips201.applet.AppletInstallRequest;
import dev.mistial.tools.openfips201.applet.AppletInstallService;
import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.common.SecureMessagingAdvertisement;
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
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

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

    if (!"emulator".equals(options.target) && !"pcsc".equals(options.target)) {
      throw new IllegalArgumentException("--target must be emulator or pcsc");
    }
    if ("pcsc".equals(options.target) && options.reader == null) {
      throw new IllegalArgumentException("--target pcsc requires --reader NAME");
    }
    if (options.provision && options.icam == null) {
      throw new IllegalArgumentException("--provision requires --icam");
    }
    if (options.vciSuite != null && !options.provision) {
      throw new IllegalArgumentException("--vci requires --provision");
    }
    if ("pcsc".equals(options.target) && options.provision && !options.yes) {
      throw new IllegalArgumentException("Physical provisioning requires --yes");
    }
    if (options.reinstallCap != null && (!"pcsc".equals(options.target) || !options.provision)) {
      throw new IllegalArgumentException("--reinstall-cap requires physical --provision");
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
          "cs7".equals(options.vciSuite) ? NativeVciProfile.SUITE_CS7 : NativeVciProfile.SUITE_CS2;
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
    boolean secureMessagingAdvertised =
        nativeVci != null
            || ("pcsc".equals(options.target) && readSecureMessagingAdvertisement(options.reader));
    selected = filterApplicableVectors(selected, secureMessagingAdvertised, results);
    if (selected.isEmpty()) {
      writeJUnitSummary(Paths.get(options.out, "nist-results.xml"), results);
      return;
    }
    int failures = 0;
    if ("pcsc".equals(options.target)
        && selected.size() > 1
        && !options.sharedCard
        && options.reinstallCap == null) {
      throw new IllegalArgumentException(
          "Multiple physical vectors require --shared-card or --reinstall-cap for isolation");
    }
    if (selected.size() > 1 && !options.sharedCard) {
      for (TestVector vector : selected) {
        failures +=
            runOnCard(
                configuration,
                java.util.Collections.singletonList(vector),
                profile,
                nativeVci,
                results,
                options);
      }
    } else {
      failures = runOnCard(configuration, selected, profile, nativeVci, results, options);
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
      List<HarnessResult> results,
      Options options)
      throws Exception {
    if ("pcsc".equals(options.target)) {
      CardTarget target = CardTarget.parse("pcsc:" + options.reader);
      if (profile != null) {
        if (options.provision) {
          if (options.reinstallCap != null) {
            installPhysicalApplet(target, options);
          }
          ConformanceProvisioner.provision(target, options.scp(), profile, System.out);
        } else {
          ConformanceProvisioner.verifyPublicProfile(target, profile);
          System.out.println("Verified physical card matches profile " + profile.credentialId);
        }
      }
      return runTests(configuration, selected, results, false);
    }
    try (JCardEngineNistCardTransport.SharedCard card = JCardEngineNistCardTransport.createCard();
        NistCardTransport contact = new JCardEngineNistCardTransport(card, "T=1");
        NistCardTransport contactless = new JCardEngineNistCardTransport(card, "T=CL")) {
      if (profile != null && options.provision) {
        ConformanceProvisioner.provision(
            () -> card.openBibo("T=1"), ScpConfig.defaultTestScp03(), profile, System.out);
      }
      if (nativeVci != null) {
        NativeVciProfile.provisionSmCredential(card.openBibo("T=1"), nativeVci);
      }
      installProvider(contact, contactless);
      return runTests(configuration, selected, results, true);
    }
  }

  private static void installPhysicalApplet(CardTarget target, Options options) throws Exception {
    AppletInstallRequest request = new AppletInstallRequest();
    request.capPath = Paths.get(options.reinstallCap);
    request.packageAid = "A00000030800001000";
    request.appletAid = "A000000308000010000100";
    request.instanceAid = "A000000308000010000100";
    request.deleteExisting = true;
    try (GlobalPlatformSession session =
        GlobalPlatformSession.open(target, GlobalPlatformSession.ISD_AID, options.scp())) {
      new AppletInstallService().install(session, request);
    }
  }

  private static void installProvider(NistCardTransport contact, NistCardTransport contactless) {
    OpenFips201TerminalFactorySpi.install(contact, contactless);
    if (Security.getProvider(OpenFips201NistProvider.PROVIDER_NAME) == null) {
      Security.insertProviderAt(new OpenFips201NistProvider(), 1);
    }
    System.setProperty(
        "javax.smartcardio.TerminalFactory.DefaultType", OpenFips201NistProvider.TERMINAL_TYPE);
  }

  private static void patchConfiguration(Configuration configuration, Options options) {
    String contactReader =
        "pcsc".equals(options.target)
            ? options.reader
            : OpenFips201TerminalFactorySpi.CONTACT_READER;
    String contactlessReader =
        "pcsc".equals(options.target)
            ? options.reader
            : OpenFips201TerminalFactorySpi.CONTACTLESS_READER;
    setEntry(configuration, "connectivity:CONTACT_READER_NAME", contactReader);
    setEntry(configuration, "connectivity:CONTACTLESS_READER_NAME", contactlessReader);
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

  private static void setEntryIfPresent(Configuration configuration, String name, String value) {
    ConfigurationEntry entry = configuration.getEntry(name);
    if (entry != null) {
      entry.setValue(value);
    }
  }

  private static void patchProfileConfiguration(
      Configuration configuration, ConformancePackage profile, NativeVciProfile.Material nativeVci)
      throws Exception {
    // Baseline files contain broad development fixtures. A selected personalization profile is
    // authoritative, so absent mechanisms must be cleared rather than inherited accidentally.
    setEntry(configuration, "testing:KEY_ALGORITHMS_AUTHENTICATION", "");
    setEntry(configuration, "testing:GENERAL_AUTH_ALGORITHM_PIV_AUTHENTICATION_KEY", "");
    setEntry(configuration, "testing:KEY_ALGORITHMS_DIGITAL_SIGNATURE", "");
    setEntry(configuration, "testing:KEY_ALGORITHMS_KEY_MANAGEMENT", "");
    setEntry(configuration, "testing:KEY_ALGORITHMS_CARD_AUTHENTICATION", "");
    setEntry(configuration, "testing:KEY_ALGORITHMS_CARD_AUTHENTICATION_SYMMETRIC", "");
    setEntry(configuration, "testing:KEY_ALGORITHMS_CARD_MANAGEMENT", "");
    setEntry(configuration, "testing:KEY_ALGORITHMS_SECURE_MESSAGING", "");
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
        // NIST 5.0.1 has certificate fields for the primary PIV slots, but not
        // for every retired key-management slot present in GSA card 37.
        setEntryIfPresent(
            configuration,
            "testing:keytypealgorithmkeys:KEY_"
                + String.format("%02X", key.slot & 0xFF)
                + "_"
                + algorithm,
            pemCertificate(key.certificate.getEncoded()));
      }
    }
    if (profile.managementKey != null) {
      String algorithm = String.format("%02X", profile.managementKey.algorithm & 0xFF);
      setEntry(configuration, "testing:KEY_ALGORITHMS_CARD_MANAGEMENT", algorithm);
      setEntry(
          configuration,
          "testing:keytypealgorithmkeys:KEY_9B_" + algorithm,
          HexUtil.format(profile.managementKey.key));
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

  private static List<TestVector> filterApplicableVectors(
      List<TestVector> vectors, boolean secureMessagingAdvertised, List<HarnessResult> results) {
    List<TestVector> applicable = new ArrayList<TestVector>();
    for (TestVector vector : vectors) {
      if (requiresSecureMessaging(vector) && !secureMessagingAdvertised) {
        String name = testName(vector);
        // NIST SP 800-73-5 Part 2, Section 3.1.1 ties 0x27/0x2E advertisement to possession of the
        // corresponding SM key. Running an SM-only vector without that advertisement tests a
        // feature the personalized card does not claim, so report N/A rather than a product pass
        // or failure. This is especially important for legacy GSA images such as card 46, which
        // contain PIV authentication keys and objects but no PIV Secure Messaging credential.
        String reason = "card does not advertise secure messaging in the SELECT APT";
        System.out.println("SKIP " + name + " " + reason);
        results.add(HarnessResult.skipped(name, reason));
      } else {
        applicable.add(vector);
      }
    }
    return applicable;
  }

  private static boolean requiresSecureMessaging(TestVector vector) {
    // SecureMessagingErrorHandling is labeled CONTACT/CONTACTLESS by the NIST corpus because that
    // is its transport, even though the test establishes and exercises PIV secure messaging.
    // Interface-only filtering would therefore incorrectly run it on a non-SM personalization.
    String testInterface = testInterface(vector);
    return "SECURE_MESSAGING".equalsIgnoreCase(testInterface)
        || "VIRTUAL_CONTACT".equalsIgnoreCase(testInterface)
        || "SecureMessagingErrorHandling".equalsIgnoreCase(vector.getSubsystemName());
  }

  private static boolean readSecureMessagingAdvertisement(String readerName) throws Exception {
    CardTerminal selected = null;
    for (CardTerminal terminal : TerminalFactory.getDefault().terminals().list()) {
      if (terminal.getName().equals(readerName)) {
        selected = terminal;
        break;
      }
    }
    if (selected == null) {
      throw new IllegalArgumentException("PC/SC reader not found: " + readerName);
    }
    Card card = selected.connect("*");
    try {
      CardChannel channel = card.getBasicChannel();
      ResponseAPDU response =
          channel.transmit(new CommandAPDU(hex("00A404000BA00000030800001000010000")));
      if (response.getSW() != 0x9000) {
        throw new IllegalStateException(
            String.format("PIV SELECT preflight failed with SW %04X", response.getSW()));
      }
      // Use the card's live APT as the authority for physical-card applicability. A build profile
      // name such as "CS2" expresses capability, while Section 3.1.1 permits advertisement only
      // after the matching per-card SM key exists.
      return SecureMessagingAdvertisement.isPresent(response.getData());
    } finally {
      card.disconnect(false);
    }
  }

  private static byte[] hex(String value) {
    return HexUtil.parse(value);
  }

  private static int runTests(
      Configuration configuration,
      List<TestVector> selected,
      List<HarnessResult> results,
      boolean resetEmulator) {
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
        if (resetEmulator) {
          OpenFips201TerminalFactorySpi.reset(testInterface(vector));
        }
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
      if (!result.passed && !result.skipped) failures++;
    }
    xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    int skipped = 0;
    for (HarnessResult result : results) {
      if (result.skipped) skipped++;
    }
    xml.append("<testsuite name=\"OpenFIPS201 NIST\" tests=\"")
        .append(results.size())
        .append("\" failures=\"")
        .append(failures)
        .append("\" skipped=\"")
        .append(skipped)
        .append("\">\n");
    for (HarnessResult result : results) {
      xml.append("  <testcase classname=\"nist.card\" name=\"")
          .append(xmlEscape(result.name))
          .append("\">");
      if (result.skipped) {
        xml.append("<skipped message=\"").append(xmlEscape(result.failure)).append("\"/>");
      } else if (!result.passed) {
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
    return value
        .replace("&", "&amp;")
        .replace("\"", "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;");
  }

  private static final class HarnessResult {
    final String name;
    final boolean passed;
    final boolean skipped;
    final String failure;

    HarnessResult(String name, boolean passed, String failure) {
      this(name, passed, false, failure);
    }

    HarnessResult(String name, boolean passed, boolean skipped, String failure) {
      this.name = name;
      this.passed = passed;
      this.skipped = skipped;
      this.failure = failure;
    }

    static HarnessResult skipped(String name, String reason) {
      return new HarnessResult(name, false, true, reason);
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
    return "pass".equalsIgnoreCase(resultText) || "true".equalsIgnoreCase(resultText);
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
    String reader;
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
    boolean provision;
    boolean yes;
    String reinstallCap;
    String scpMode = "03";
    int scpKeyVersion;
    String scpKey;
    String scpEncKey;
    String scpMacKey;
    String scpDekKey;
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
        } else if ("--provision".equals(arg)) {
          options.provision = true;
        } else if ("--yes".equals(arg)) {
          options.yes = true;
        } else if ("--reinstall-cap".equals(arg)) {
          options.reinstallCap = requireValue(args, ++i, arg);
        } else if ("--scp".equals(arg)) {
          options.scpMode = requireValue(args, ++i, arg);
        } else if ("--scp-key-version".equals(arg)) {
          options.scpKeyVersion = Integer.decode(requireValue(args, ++i, arg));
        } else if ("--scp-key".equals(arg)) {
          options.scpKey = requireValue(args, ++i, arg);
        } else if ("--scp-enc-key".equals(arg)) {
          options.scpEncKey = requireValue(args, ++i, arg);
        } else if ("--scp-mac-key".equals(arg)) {
          options.scpMacKey = requireValue(args, ++i, arg);
        } else if ("--scp-dek-key".equals(arg)) {
          options.scpDekKey = requireValue(args, ++i, arg);
        } else if ("--target".equals(arg)) {
          options.target = requireValue(args, ++i, arg);
        } else if ("--reader".equals(arg)) {
          options.reader = requireValue(args, ++i, arg);
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
      if (!options.help && !options.listTests && options.suite == null && options.test == null) {
        throw new IllegalArgumentException("Select tests with --suite, --test, or --list-tests");
      }
      return options;
    }

    ScpConfig scp() {
      if ("emulator".equals(target)
          && scpKey == null
          && scpEncKey == null
          && scpMacKey == null
          && scpDekKey == null) {
        return ScpConfig.defaultTestScp03();
      }
      return ScpConfig.fromCliKeys(
          ScpConfig.parseMode(scpMode), scpKeyVersion, scpKey, scpEncKey, scpMacKey, scpDekKey);
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
          "  --target emulator|pcsc   Use the in-process emulator or a physical PC/SC card");
      System.out.println("  --reader NAME            PC/SC reader name for --target pcsc");
      System.out.println("  --config FILE            NIST Test Runner configuration XML");
      System.out.println("  --out DIR                Local output directory");
      System.out.println(
          "  --fips                   Compile and test the FIPS_MODE applet profile");
      System.out.println("  --list-tests             List available NIST vectors");
      System.out.println(
          "  --suite contact          Run an interface, card-<interface>, all, or subsystem");
      System.out.println("  --test Subsystem:Id      Run one vector, for example SelectCommand:1");
      System.out.println(
          "  --icam DIR               Load expected GSA ICAM personalization metadata");
      System.out.println("  --provision              Apply --icam before testing");
      System.out.println("  --yes                    Confirm physical-card mutation");
      System.out.println("  --reinstall-cap FILE     Reinstall a fresh physical applet per vector");
      System.out.println("  --scp-key HEX            Shared SCP key for physical provisioning");
      System.out.println("  --scp-enc-key HEX        Split SCP ENC key");
      System.out.println("  --scp-mac-key HEX        Split SCP MAC key");
      System.out.println("  --scp-dek-key HEX        Split SCP DEK key");
      System.out.println("  --vci cs2|cs7           Build a signed native Part 1 VCI profile");
      System.out.println("  --pairing-code 12345678 Eight-digit test-card pairing code");
      System.out.println(
          "  --shared-card            Preserve one ICAM image across multiple vectors");
      System.out.println("  --limit N                Stop after N selected vectors");
    }
  }
}
