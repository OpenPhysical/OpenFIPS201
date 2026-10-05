package dev.mistial.tools.openfips201.provisioning;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.crypto.CryptoProviders;
import java.math.BigInteger;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

class CertificationProfileValidatorTest {
  private static final KeyPurposeId ID_PIV_CONTENT_SIGNING =
      KeyPurposeId.getInstance(new ASN1ObjectIdentifier("2.16.840.1.101.3.6.7"));
  private static final KeyPurposeId ID_PIVI_CONTENT_SIGNING =
      KeyPurposeId.getInstance(new ASN1ObjectIdentifier("2.16.840.1.101.3.8.7"));

  @Test
  void secureMessagingSignerMustAssertContentSigningUsage() throws Exception {
    // SP 800-73-5 Part 1 Section 3.3.7: "The X.509 Certificate for Content Signing SHALL also
    // include an extended key usage (extKeyUsage) extension asserting id-PIV-content-signing."
    // GSA ICAM card 01 (agency 4700) and card 02 (PIV-I, 9999 9999 999999) FASC-Ns.
    byte[] federal = hex("3019D13810D828AB6C10C339E5A1685A08C92ADE0A6184E739C3E7");
    byte[] pivICard = hex("3019D4E739DA739CED39CE739DA16858210842108515CCE739B7FA");
    String piv = smSigner(ID_PIV_CONTENT_SIGNING);
    String pivI = smSigner(ID_PIVI_CONTENT_SIGNING);
    assertDoesNotThrow(
        () -> CertificationProfileValidator.validateSmSignerUsage(hex(piv), federal));
    assertDoesNotThrow(
        () -> CertificationProfileValidator.validateSmSignerUsage(hex(pivI), pivICard));
    // FPKI PIV-I Profiles v1.3 Worksheet 8: a PIV-I card's signer asserts the PIV-I purpose.
    assertThrows(
        IllegalArgumentException.class,
        () -> CertificationProfileValidator.validateSmSignerUsage(hex(piv), pivICard));
    for (String payload :
        new String[] {
          smSigner(null), smSigner(KeyPurposeId.id_kp_codeSigning), "700101710100FE00"
        }) {
      assertThrows(
          IllegalArgumentException.class,
          () -> CertificationProfileValidator.validateSmSignerUsage(hex(payload), federal));
    }
  }

  /** Returns a 5FC122 value carrying an uncompressed certificate with the given extKeyUsage. */
  private static String smSigner(KeyPurposeId usage) throws Exception {
    CryptoProviders.ensureBouncyCastle();
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair keyPair = generator.generateKeyPair();
    X500Name subject = new X500Name("CN=Test Content Signer");
    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            subject,
            BigInteger.ONE,
            new Date(),
            new Date(System.currentTimeMillis() + 86_400_000L),
            subject,
            keyPair.getPublic());
    if (usage != null) {
      builder.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(usage));
    }
    byte[] certificate =
        builder
            .build(new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate()))
            .getEncoded();
    return String.format("7082%04X", certificate.length)
        + HexUtil.format(certificate)
        + "710100FE00";
  }

  @Test
  void acceptsAppendixAContainerSchemasAndRejectsWrongLeadingTags() {
    String[][] containers = {
      {"5FC107", "F000F100F200F300F400F50110F600F700FA00FB00FC00FD00FE00"},
      {
        "5FC102",
        "3019"
            + "0000000000"
            + "0000000000"
            + "0000000000"
            + "0000000000"
            + "0000000000"
            + "341000000000000000000000000000000000"
            + "35083230323631323331"
            + "3E0101FE00"
      },
      {"5FC105", "700101710100FE00"},
      {"5FC10D", "700101710100720101FE00"},
      {"5FC103", "BC0101FE00"},
      {"5FC106", "BA03013000BB0101FE00"},
      {"5FC109", "0101410201420409323032364A414E3031050143060F414141414141414141414141414141FE00"},
      {"5FC10C", "C10100C20100FE00"},
      {"7F61", "020100"},
      {"5FC122", "700101710100FE00"},
      {"5FC123", "99083132333435363738FE00"}
    };

    for (String[] container : containers) {
      byte[] payload = hex(container[1]);
      assertDoesNotThrow(
          () -> CertificationProfileValidator.validateContainer(container[0], payload),
          container[0]);
      payload[0] = 0x31;
      assertThrows(
          IllegalArgumentException.class,
          () -> CertificationProfileValidator.validateContainer(container[0], payload),
          container[0] + " must reject a wrong leading tag");
    }
  }

  @Test
  void rejectsInvalidFixedValuesTypesAndMandatoryElements() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            CertificationProfileValidator.validateContainer(
                "5FC107", hex("F000F100F200F300F400F50111F600F700FA00FB00FC00FD00FE00")),
        "CCC data model number must be 0x10");
    assertThrows(
        IllegalArgumentException.class,
        () -> CertificationProfileValidator.validateContainer("5FC106", hex("BA03013000BB0101")),
        "Security Object requires the Appendix A error-detection element");
    assertThrows(
        IllegalArgumentException.class,
        () -> CertificationProfileValidator.validateContainer("5FC10C", hex("C10115C20100FE00")),
        "Key History cannot name more than 20 retired keys");
    assertThrows(
        IllegalArgumentException.class,
        () ->
            CertificationProfileValidator.validateContainer(
                "5FC109",
                hex(
                    "0101410201420409323032363031313031050143060F414141414141414141414141414141FE00")),
        "Printed Information expiration must use YYYYMMMDD");
    assertThrows(
        IllegalArgumentException.class,
        () ->
            CertificationProfileValidator.validateContainer(
                "5FC109",
                hex(
                    "0101FF0201420409323032364A414E3031050143060F414141414141414141414141414141FE00")),
        "Printed Information text must be ASCII");
    assertThrows(
        IllegalArgumentException.class,
        () ->
            CertificationProfileValidator.validateContainer(
                "5FC102",
                hex(
                    "3019"
                        + "00000000000000000000000000000000000000000000000000"
                        + "341000000000000000000000000000000000"
                        + "35083939393939393939"
                        + "3E0101FE00")),
        "CHUID expiration must be a calendar date");
    assertThrows(
        IllegalArgumentException.class,
        () ->
            CertificationProfileValidator.validateContainer(
                "5FC109",
                hex(
                    "0101410201420409323032364645423330050143060F414141414141414141414141414141FE00")),
        "Printed Information expiration must be a calendar date");
  }

  @Test
  void securityObjectCoverageIncludesEverySuppliedUnsignedContainer() {
    Map<String, ConformancePackage.DataObject> objects =
        new HashMap<String, ConformancePackage.DataObject>();
    ConformancePackage.DataObject ccc = object(hex("5FC107"), hex("F500"));
    ConformancePackage.DataObject printed = object(hex("5FC109"), hex("FE00"));
    ConformancePackage.DataObject certificate = object(hex("5FC105"), hex("700101710100FE00"));
    objects.put("5FC107", ccc);
    objects.put("5FC109", printed);
    objects.put("5FC105", certificate);

    Map<Integer, ConformancePackage.DataObject> mapped =
        new HashMap<Integer, ConformancePackage.DataObject>();
    mapped.put(1, ccc);
    IllegalArgumentException missing =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                CertificationProfileValidator.validateRequiredSecurityObjectCoverage(
                    objects, mapped));
    assertTrue(missing.getMessage().contains("5FC109"));

    mapped.put(2, printed);
    assertDoesNotThrow(
        () -> CertificationProfileValidator.validateRequiredSecurityObjectCoverage(objects, mapped),
        "PIV certificates are excluded from required Security Object coverage");
  }

  @Test
  void securityObjectMappingsUseUniqueDataGroupsAndContainers() {
    ConformancePackage.DataObject first = object(hex("5FC107"), hex("F500"));
    ConformancePackage.DataObject second = object(hex("5FC109"), hex("FE00"));
    Map<Integer, ConformancePackage.DataObject> mappings =
        new HashMap<Integer, ConformancePackage.DataObject>();
    Set<ConformancePackage.DataObject> objects = new HashSet<ConformancePackage.DataObject>();

    CertificationProfileValidator.addSecurityObjectMapping(mappings, objects, 1, first);
    assertThrows(
        IllegalArgumentException.class,
        () -> CertificationProfileValidator.addSecurityObjectMapping(mappings, objects, 0, second));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            CertificationProfileValidator.addSecurityObjectMapping(mappings, objects, 17, second));
    assertThrows(
        IllegalArgumentException.class,
        () -> CertificationProfileValidator.addSecurityObjectMapping(mappings, objects, 1, second));
    assertThrows(
        IllegalArgumentException.class,
        () -> CertificationProfileValidator.addSecurityObjectMapping(mappings, objects, 2, first));
  }

  @Test
  void capacitiesCoverEveryPart1Table8ContainerFamily() {
    assertEquals(245, CertificationProfileValidator.requiredCapacity(hex("5FC109"), 1));
    assertEquals(128, CertificationProfileValidator.requiredCapacity(hex("5FC10C"), 1));
    assertEquals(1895, CertificationProfileValidator.requiredCapacity(hex("5FC10D"), 1));
    assertEquals(1895, CertificationProfileValidator.requiredCapacity(hex("5FC120"), 1));
    assertEquals(7106, CertificationProfileValidator.requiredCapacity(hex("5FC121"), 1));
    assertEquals(65, CertificationProfileValidator.requiredCapacity(hex("7F61"), 1));
    assertEquals(2471, CertificationProfileValidator.requiredCapacity(hex("5FC122"), 1));
    assertEquals(12, CertificationProfileValidator.requiredCapacity(hex("5FC123"), 1));
    assertEquals(14, CertificationProfileValidator.requiredCapacity(hex("5FC123"), 12));
    assertEquals(3004, CertificationProfileValidator.requiredCapacity(hex("5FC122"), 3000));
  }

  @Test
  void rejectsIncompleteMandatoryPart1DataModelBeforeCardMutation() {
    ConformancePackage pkg = packageWith(new ArrayList<ConformancePackage.DataObject>());
    IllegalArgumentException failure =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                CertificationProfileValidator.validate(
                    pkg, new CertificationProfileValidator.Claims(false, false, false)));
    assertTrue(failure.getMessage().contains("missing mandatory object"));
  }

  @Test
  void rejectsVciClaimWithoutDiscovery() {
    ArrayList<ConformancePackage.DataObject> objects = mandatoryPlaceholders();
    IllegalArgumentException failure =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                CertificationProfileValidator.validate(
                    packageWith(objects),
                    new CertificationProfileValidator.Claims(false, true, true)));
    assertTrue(failure.getMessage().contains("requires Discovery"));
  }

  @Test
  void rejectsDiscoveryThatContradictsFrozenPairingClaim() {
    ArrayList<ConformancePackage.DataObject> objects = mandatoryPlaceholders();
    objects.add(object(new byte[] {(byte) 0x7E}, hex("7E124F0BA0000003080000100001005F2F024C00")));
    IllegalArgumentException failure =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                CertificationProfileValidator.validate(
                    packageWith(objects),
                    new CertificationProfileValidator.Claims(false, true, true)));
    assertTrue(failure.getMessage().contains("contradict frozen claims"));
  }

  @Test
  void pinUsagePolicyAcceptsOnlyPart1Table1Values() {
    List<Integer> table1 =
        Arrays.asList(0x40, 0x48, 0x4C, 0x50, 0x58, 0x5C, 0x60, 0x68, 0x6C, 0x70, 0x78, 0x7C);
    for (int first = 0; first < 0x100; first++) {
      boolean listed = table1.contains(first);
      boolean global = (first & 0x20) != 0;
      for (int second : new int[] {0x00, 0x10, 0x20, 0x30}) {
        boolean expected = listed && (global ? second == 0x10 || second == 0x20 : second == 0x00);
        assertEquals(
            expected,
            CertificationProfileValidator.isTable1PinUsagePolicy(first, second),
            String.format("%02X%02X", first, second));
      }
    }
  }

  @Test
  void rejectsDiscoveryPolicyOutsideTable1() {
    // 0x44 sets "VCI established without a pairing code" without the VCI bit.
    assertDiscoveryRejected("4400", new CertificationProfileValidator.Claims(false, false, false));
    // With bit 6 set the second byte is 0x10 or 0x20.
    assertDiscoveryRejected(
        "6030", new CertificationProfileValidator.Claims(false, false, false, true));
  }

  @Test
  void rejectsDiscoveryAdvertisingFeaturesTheCardLacks() {
    assertDiscoveryRejected("5000", new CertificationProfileValidator.Claims(false, false, false));
    assertDiscoveryRejected("6010", new CertificationProfileValidator.Claims(false, false, false));

    ArrayList<ConformancePackage.DataObject> objects = mandatoryPlaceholders();
    objects.add(discovery("6010"));
    IllegalArgumentException later =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                CertificationProfileValidator.validate(
                    packageWith(objects),
                    new CertificationProfileValidator.Claims(false, false, false, true)));
    assertFalse(later.getMessage().contains("Discovery"), later.getMessage());
    assertFalse(later.getMessage().contains("PIN Usage Policy"), later.getMessage());
  }

  private static ConformancePackage.DataObject discovery(String policy) {
    return object(new byte[] {(byte) 0x7E}, hex("7E124F0BA0000003080000100001005F2F02" + policy));
  }

  private static void assertDiscoveryRejected(
      String policy, CertificationProfileValidator.Claims claims) {
    ArrayList<ConformancePackage.DataObject> objects = mandatoryPlaceholders();
    objects.add(discovery(policy));
    IllegalArgumentException failure =
        assertThrows(
            IllegalArgumentException.class,
            () -> CertificationProfileValidator.validate(packageWith(objects), claims));
    assertTrue(
        failure.getMessage().contains("PIN Usage Policy")
            || failure.getMessage().contains("Discovery advertises"),
        failure.getMessage());
  }

  @Test
  void vciClaimsRequireSignerAndPairingContainers() {
    ArrayList<ConformancePackage.DataObject> withoutSigner = mandatoryPlaceholders();
    withoutSigner.add(
        object(new byte[] {(byte) 0x7E}, hex("7E124F0BA0000003080000100001005F2F024800")));
    IllegalArgumentException signerFailure =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                CertificationProfileValidator.validate(
                    packageWith(withoutSigner),
                    new CertificationProfileValidator.Claims(false, true, true)));
    assertTrue(signerFailure.getMessage().contains("5FC122"));

    withoutSigner.add(object(hex("5FC122"), hex("700171710100FE00")));
    IllegalArgumentException pairingFailure =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                CertificationProfileValidator.validate(
                    packageWith(withoutSigner),
                    new CertificationProfileValidator.Claims(false, true, true)));
    assertTrue(pairingFailure.getMessage().contains("5FC123"));
  }

  @Test
  void rejectsObjectAndKeyAccessModesOutsidePart1Tables2And5() {
    ArrayList<ConformancePackage.DataObject> objects =
        new ArrayList<ConformancePackage.DataObject>();
    objects.add(object(hex("5FC103"), hex("BC0101FE00")));
    ConformancePackage wrongBiometric = packageWith(objects);
    assertThrows(
        IllegalArgumentException.class,
        () -> CertificationProfileValidator.validateAccessModes(wrongBiometric));

    objects.clear();
    objects.add(
        new ConformancePackage.DataObject(
            hex("5FC103"),
            "fingerprints",
            (byte) 0x01,
            (byte) 0x09,
            ConformancePackage.PutForm.TAG_LIST,
            hex("BC0101FE00")));
    assertDoesNotThrow(
        () -> CertificationProfileValidator.validateAccessModes(packageWith(objects)));

    ConformancePackage.KeyMaterial badCardAuth =
        new ConformancePackage.KeyMaterial(
            (byte) 0x9E,
            "card auth",
            (byte) 0x11,
            (byte) 0x04,
            (byte) 0x10,
            (byte) 0x7F,
            (byte) 0x08,
            null,
            null);
    ConformancePackage badKeyPackage =
        new ConformancePackage(
            "test",
            Paths.get("."),
            StandardCardProfile.PIN,
            StandardCardProfile.PUK,
            null,
            Collections.<ConformancePackage.DataObject>emptyList(),
            Collections.singletonList(badCardAuth));
    assertThrows(
        IllegalArgumentException.class,
        () -> CertificationProfileValidator.validateAccessModes(badKeyPackage));
  }

  private static ArrayList<ConformancePackage.DataObject> mandatoryPlaceholders() {
    ArrayList<ConformancePackage.DataObject> result =
        new ArrayList<ConformancePackage.DataObject>();
    for (String id :
        new String[] {"5FC107", "5FC102", "5FC105", "5FC101", "5FC103", "5FC108", "5FC106"}) {
      result.add(object(hex(id), new byte[] {0x30, 0x00}));
    }
    return result;
  }

  private static ConformancePackage.DataObject object(byte[] id, byte[] payload) {
    return new ConformancePackage.DataObject(
        id,
        "test",
        (byte) 0x7F,
        (byte) 0x7F,
        id.length == 1 ? ConformancePackage.PutForm.DISCOVERY : ConformancePackage.PutForm.TAG_LIST,
        payload);
  }

  private static ConformancePackage packageWith(ArrayList<ConformancePackage.DataObject> objects) {
    return new ConformancePackage(
        "test",
        Paths.get("."),
        StandardCardProfile.PIN,
        StandardCardProfile.PUK,
        null,
        objects,
        Collections.<ConformancePackage.KeyMaterial>emptyList());
  }

  private static byte[] hex(String value) {
    byte[] result = new byte[value.length() / 2];
    for (int i = 0; i < value.length(); i += 2) {
      result[i / 2] = (byte) Integer.parseInt(value.substring(i, i + 2), 16);
    }
    return result;
  }
}
