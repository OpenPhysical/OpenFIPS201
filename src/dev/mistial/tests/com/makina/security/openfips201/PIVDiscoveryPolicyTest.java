package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import javacard.framework.ISOException;
import org.junit.jupiter.api.Test;

class PIVDiscoveryPolicyTest {

  @Test
  void dataObjectAllocationInitializesAndClearsReusableStorage() {
    PIVDataObject object =
        new PIVDataObject(
            (byte) 0x01, PIVObject.ACCESS_MODE_ALWAYS, PIVObject.ACCESS_MODE_ALWAYS, (byte) 0x9B);

    object.allocate((short) 8);
    object.content[0] = (byte) 0x7F;
    object.allocate((short) 4);

    assertTrue(object.isInitialised());
    assertEquals(4, object.getLength());
    assertEquals(0, object.content[0]);
  }

  @Test
  void dataObjectAllocationRejectsNonPositiveLengths() {
    PIVDataObject object =
        new PIVDataObject(
            (byte) 0x01, PIVObject.ACCESS_MODE_ALWAYS, PIVObject.ACCESS_MODE_ALWAYS, (byte) 0x9B);

    assertThrows(ISOException.class, () -> object.allocate((short) 0));
    assertThrows(ISOException.class, () -> object.allocate((short) -1));
    assertThrows(ISOException.class, () -> object.beginUpdate((short) 0));
  }

  @Test
  void multiByteDataObjectUsesDefaultAdministrativeKey() {
    PIVDataObject object =
        new PIVDataObject(
            new byte[] {(byte) 0x5F, (byte) 0xC1, (byte) 0x07},
            (short) 0,
            (short) 3,
            PIVObject.ACCESS_MODE_ALWAYS,
            PIVObject.ACCESS_MODE_ALWAYS,
            (byte) 0);

    assertEquals(PIVObject.DEFAULT_ADMIN_KEY, object.getAdminKey());
  }

  @Test
  void personalizationRequiresPart1ContainerStructure() {
    // SP 800-73-5 Part 1 Sections 3 and 4 define complete BER-TLV containers for the mandatory
    // objects; populated storage alone is not sufficient for the irreversible transition.
    assertFalse(PIVDataCommandHandler.isStructurallyValidMandatoryObject(null, (byte) 0x07));
    assertFalse(mandatoryObjectIsValid((byte) 0x07, hex("00")));
    assertTrue(mandatoryObjectIsValid((byte) 0x07, hex("F00100")));
    assertTrue(mandatoryObjectIsValid((byte) 0x07, hex("01810100")));
    assertTrue(mandatoryObjectIsValid((byte) 0x07, hex("0182000100")));
    assertTrue(mandatoryObjectIsValid((byte) 0x07, hex("5F2F0100")));
    assertFalse(mandatoryObjectIsValid((byte) 0x07, hex("1F80")));
    assertFalse(mandatoryObjectIsValid((byte) 0x07, hex("1F8000")));
    assertFalse(mandatoryObjectIsValid((byte) 0x07, hex("0180")));
    assertFalse(mandatoryObjectIsValid((byte) 0x07, hex("018201")));
    assertFalse(mandatoryObjectIsValid((byte) 0x07, hex("018300000100")));
    assertFalse(mandatoryObjectIsValid((byte) 0x07, hex("010200")));

    assertTrue(mandatoryObjectIsValid((byte) 0x05, hex("700100710100FE00")));
    assertTrue(mandatoryObjectIsValid((byte) 0x05, hex("70010071810100FE00")));
    assertFalse(mandatoryObjectIsValid((byte) 0x05, hex("700100710100")));
    assertFalse(mandatoryObjectIsValid((byte) 0x05, hex("710100700100FE00")));
    assertFalse(mandatoryObjectIsValid((byte) 0x05, hex("70010071020000FE00")));

    assertTrue(mandatoryObjectIsValid((byte) 0x06, hex("BA03010101BB0100")));
    assertTrue(mandatoryObjectIsValid((byte) 0x06, hex("BA03010101BB0100FE00")));
    assertFalse(mandatoryObjectIsValid((byte) 0x06, hex("BA00BB0100")));
    assertFalse(mandatoryObjectIsValid((byte) 0x06, hex("BA020101BB0100")));
    assertFalse(mandatoryObjectIsValid((byte) 0x06, hex("BA03010101BC0100")));
    assertFalse(mandatoryObjectIsValid((byte) 0x06, hex("BA03010101BB0200")));
    assertFalse(mandatoryObjectIsValid((byte) 0x06, hex("BA03010101BB010000")));
  }

  @Test
  void globalPinRequiresInitialisedDiscoveryPolicyBit() {
    PIVDataStore store = mock(PIVDataStore.class);
    PIVDataObject discovery = mock(PIVDataObject.class);
    PIVDataCommandHandler handler =
        new PIVDataCommandHandler(
            mock(Config.class),
            mock(PIVSecurityProvider.class),
            store,
            mock(ChainBuffer.class),
            new byte[32]);

    assertFalse(handler.isGlobalPinAdvertised(), "Missing Discovery must disable Global PIN");

    when(store.findSingleByte(PIV.ID_DATA_DISCOVERY)).thenReturn(discovery);
    when(discovery.isInitialised()).thenReturn(true);
    discovery.content = hex("7E124F0BA0000003080000100001005F2F024000");
    when(discovery.getLength()).thenReturn((short) discovery.content.length);
    assertFalse(
        handler.isGlobalPinAdvertised(), "Discovery without the Global PIN bit must disable it");

    discovery.content = hex("7E124F0BA0000003080000100001005F2F026010");
    when(discovery.getLength()).thenReturn((short) discovery.content.length);
    assertTrue(
        handler.isGlobalPinAdvertised(), "Stored Discovery Global PIN policy must enable it");
  }

  @Test
  void acceptsEveryDefinedGlobalPinDiscoveryCombination() {
    PIVDataStore store = mock(PIVDataStore.class);
    PIVDataObject discovery = mock(PIVDataObject.class);
    PIVDataCommandHandler handler =
        new PIVDataCommandHandler(
            mock(Config.class),
            mock(PIVSecurityProvider.class),
            store,
            mock(ChainBuffer.class),
            new byte[32]);
    when(store.findSingleByte(PIV.ID_DATA_DISCOVERY)).thenReturn(discovery);
    when(discovery.isInitialised()).thenReturn(true);

    int[] localOnlyPolicies = {0x40, 0x44, 0x48, 0x4C, 0x50, 0x54, 0x58, 0x5C};
    for (int first : localOnlyPolicies) {
      setPolicy(discovery, first, 0x00);
      assertEquals((first << 8), handler.getDiscoveryPolicy());
      assertFalse(handler.isGlobalPinAdvertised());
    }

    int[] globalPolicies = {0x60, 0x64, 0x68, 0x6C, 0x70, 0x74, 0x78, 0x7C};
    for (int first : globalPolicies) {
      for (int preference : new int[] {0x10, 0x20}) {
        setPolicy(discovery, first, preference);
        assertEquals((first << 8) | preference, handler.getDiscoveryPolicy());
        assertTrue(handler.isGlobalPinAdvertised());
      }
    }

    setPolicy(discovery, 0x40, 0x10);
    assertEquals(-1, handler.getDiscoveryPolicy(), "Local-only policy cannot prefer Global PIN");
    setPolicy(discovery, 0x60, 0x00);
    assertEquals(-1, handler.getDiscoveryPolicy(), "Global PIN policy must state its preference");
  }

  @Test
  void validatesPart1DiscoveryShapeAndPairingPolicy() {
    PIVDataStore store = mock(PIVDataStore.class);
    PIVDataObject discovery = mock(PIVDataObject.class);
    PIVDataCommandHandler handler =
        new PIVDataCommandHandler(
            mock(Config.class),
            mock(PIVSecurityProvider.class),
            store,
            mock(ChainBuffer.class),
            new byte[32]);
    when(store.findSingleByte(PIV.ID_DATA_DISCOVERY)).thenReturn(discovery);
    when(discovery.isInitialised()).thenReturn(true);

    // SP 800-73-5 Part 1 Section 3.3.2: VCI with pairing is 0x48; without pairing is 0x4C.
    discovery.content = hex("7E124F0BA0000003080000100001005F2F024800");
    when(discovery.getLength()).thenReturn((short) discovery.content.length);
    assertEquals(0x4800, handler.getDiscoveryPolicy());

    discovery.content = hex("7E124F0BA0000003080000100001005F2F024C00");
    when(discovery.getLength()).thenReturn((short) discovery.content.length);
    assertEquals(0x4C00, handler.getDiscoveryPolicy());

    discovery.content = hex("7E124F0BA0000003080000100001015F2F024C00");
    when(discovery.getLength()).thenReturn((short) discovery.content.length);
    assertEquals(-1, handler.getDiscoveryPolicy(), "The Discovery AID is fixed by Section 3.3.2");

    discovery.content = hex("7E124F0BA0000003080000100001005F2F022000");
    when(discovery.getLength()).thenReturn((short) discovery.content.length);
    assertEquals(
        -1, handler.getDiscoveryPolicy(), "The mandatory local-PIN policy bit must be set");
  }

  @Test
  void pairingReferenceRequiresStoredVciPairingPolicy() {
    assertFalse(
        PIV.isPairingCodeReferenceEnabled(Config.VCI_MODE_PAIRING_CODE, (short) -1),
        "Missing Discovery must disable pairing reference 98");
    assertFalse(
        PIV.isPairingCodeReferenceEnabled(Config.VCI_MODE_PAIRING_CODE, (short) 0x4000),
        "Discovery without VCI must disable pairing reference 98");
    assertFalse(
        PIV.isPairingCodeReferenceEnabled(Config.VCI_MODE_PAIRING_CODE, (short) 0x4C00),
        "No-pairing Discovery policy must disable pairing reference 98");
    assertTrue(
        PIV.isPairingCodeReferenceEnabled(Config.VCI_MODE_PAIRING_CODE, (short) 0x4800),
        "VCI pairing-required Discovery policy enables reference 98");
  }

  private static byte[] hex(String value) {
    byte[] result = new byte[value.length() / 2];
    for (int i = 0; i < value.length(); i += 2) {
      result[i / 2] = (byte) Integer.parseInt(value.substring(i, i + 2), 16);
    }
    return result;
  }

  private static void setPolicy(PIVDataObject discovery, int first, int second) {
    discovery.content = hex("7E124F0BA0000003080000100001005F2F020000");
    discovery.content[discovery.content.length - 2] = (byte) first;
    discovery.content[discovery.content.length - 1] = (byte) second;
    when(discovery.getLength()).thenReturn((short) discovery.content.length);
  }

  private static boolean mandatoryObjectIsValid(byte suffix, byte[] content) {
    PIVDataObject object = mock(PIVDataObject.class);
    object.content = content;
    when(object.isInitialised()).thenReturn(true);
    when(object.getLength()).thenReturn((short) content.length);
    return PIVDataCommandHandler.isStructurallyValidMandatoryObject(object, suffix);
  }
}
