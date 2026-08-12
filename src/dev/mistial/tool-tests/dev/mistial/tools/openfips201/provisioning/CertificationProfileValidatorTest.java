package dev.mistial.tools.openfips201.provisioning;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class CertificationProfileValidatorTest {
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
        StandardCardProfile.ADMIN_KEY_ALG,
        StandardCardProfile.ADMIN_KEY,
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
