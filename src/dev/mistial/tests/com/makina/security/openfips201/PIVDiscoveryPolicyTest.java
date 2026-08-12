package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

class PIVDiscoveryPolicyTest {

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
    assertEquals(-1, handler.getDiscoveryPolicy(), "The mandatory local-PIN policy bit must be set");
  }

  private static byte[] hex(String value) {
    byte[] result = new byte[value.length() / 2];
    for (int i = 0; i < value.length(); i += 2) {
      result[i / 2] = (byte) Integer.parseInt(value.substring(i, i + 2), 16);
    }
    return result;
  }
}
