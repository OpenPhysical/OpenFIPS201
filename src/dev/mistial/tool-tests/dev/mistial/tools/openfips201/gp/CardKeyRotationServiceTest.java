package dev.mistial.tools.openfips201.gp;

import static org.junit.jupiter.api.Assertions.*;

import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.CardTransport;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.emulator.ZmqEmulatorFixture;
import javacard.framework.ISO7816;
import org.junit.jupiter.api.Test;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.keys.PlaintextKeys;

/** Real SCP03 transitions, not a mocked secure channel or a physical-card retirement claim. */
class CardKeyRotationServiceTest {
  private static final int FIRST_ISSUER_VERSION = ScpConfig.KEY_VERSION_MIN;
  private static final int SECOND_ISSUER_VERSION = FIRST_ISSUER_VERSION + 1;
  private static final int AES_128_KEY_BYTES = 128 / Byte.SIZE;
  private static final byte FIRST_KEY_FILL = (byte) 0x11;
  private static final byte SECOND_KEY_FILL = (byte) 0x22;
  private static final byte REPLACEMENT_KEY_FILL = (byte) 0x33;

  @Test
  void forwardAndReverseRollAddAbsentTargetsAndRetireSources() throws Exception {
    try (ZmqEmulatorFixture fixture = ZmqEmulatorFixture.start(PlaintextKeys.DEFAULT_KEY());
        CardTransport transport = CardTarget.parse("zmq:" + fixture.endpoint()).openTransport()) {
      CardKeyRotationService service = new CardKeyRotationService();
      ScpConfig first = syntheticKeys(FIRST_ISSUER_VERSION, FIRST_KEY_FILL);
      ScpConfig second = syntheticKeys(SECOND_ISSUER_VERSION, SECOND_KEY_FILL);
      service.rotate(
          transport, ScpConfig.defaultTestScp03(), DerivedScpKeys.fromConfig(first), true);
      service.rotate(transport, first, DerivedScpKeys.fromConfig(second), true);
      assertInventory(transport, second, SECOND_ISSUER_VERSION, FIRST_ISSUER_VERSION);
      // Version 1 was retired. Reverse roll must ADD it, not PUT KEY replace version 1.
      service.rotate(transport, second, DerivedScpKeys.fromConfig(first), true);
      assertInventory(transport, first, FIRST_ISSUER_VERSION, SECOND_ISSUER_VERSION);
    }
  }

  @Test
  void existingTargetRequiresPermissionAndUsesItsVersionForReplacement() throws Exception {
    try (ZmqEmulatorFixture fixture = ZmqEmulatorFixture.start(PlaintextKeys.DEFAULT_KEY());
        CardTransport raw = CardTarget.parse("zmq:" + fixture.endpoint()).openTransport()) {
      java.util.List<Integer> versions = new java.util.ArrayList<>();
      apdu4j.core.BIBO delegate = raw.bibo();
      try (CardTransport transport =
          CardTransport.borrow(
              command -> {
                if (command[ISO7816.OFFSET_INS] == (byte) GPSession.INS_PUT_KEY)
                  versions.add(command[ISO7816.OFFSET_P1] & ScpConfig.KEY_VERSION_MAX);
                return delegate.transceive(command);
              })) {
        ScpConfig first = syntheticKeys(FIRST_ISSUER_VERSION, FIRST_KEY_FILL);
        ScpConfig existing = syntheticKeys(SECOND_ISSUER_VERSION, SECOND_KEY_FILL);
        ScpConfig replacement = syntheticKeys(SECOND_ISSUER_VERSION, REPLACEMENT_KEY_FILL);
        CardKeyRotationService service = new CardKeyRotationService();
        service.rotate(
            transport, ScpConfig.defaultTestScp03(), DerivedScpKeys.fromConfig(first), true);
        try (GlobalPlatformSession session =
            transport.openGlobalPlatformSession(GlobalPlatformSession.ISD_AID, first)) {
          session.putKeys(existing.toPlaintextKeys(), false);
        }
        assertThrows(
            IllegalArgumentException.class,
            () -> service.rotate(transport, first, DerivedScpKeys.fromConfig(replacement), false));
        assertEquals(
            java.util.Arrays.asList(ScpConfig.KEY_VERSION_AUTO, ScpConfig.KEY_VERSION_AUTO),
            versions,
            "refusal must not PUT KEY");
        service.rotate(transport, first, DerivedScpKeys.fromConfig(replacement), true);
        assertEquals(
            java.util.Arrays.asList(
                ScpConfig.KEY_VERSION_AUTO, ScpConfig.KEY_VERSION_AUTO, SECOND_ISSUER_VERSION),
            versions,
            "P1 identifies the replaced target");
        assertInventory(transport, replacement, SECOND_ISSUER_VERSION, FIRST_ISSUER_VERSION);
      }
    }
  }

  @Test
  void retirementFailureReportsStageWithoutRetryingOrDeletingTheNewKeys() throws Exception {
    try (ZmqEmulatorFixture fixture = ZmqEmulatorFixture.start(PlaintextKeys.DEFAULT_KEY());
        CardTransport raw = CardTarget.parse("zmq:" + fixture.endpoint()).openTransport()) {
      ScpConfig first = syntheticKeys(FIRST_ISSUER_VERSION, FIRST_KEY_FILL);
      ScpConfig second = syntheticKeys(SECOND_ISSUER_VERSION, SECOND_KEY_FILL);
      CardKeyRotationService service = new CardKeyRotationService();
      service.rotate(raw, ScpConfig.defaultTestScp03(), DerivedScpKeys.fromConfig(first), true);
      apdu4j.core.BIBO delegate = raw.bibo();
      int[] deletes = {0};
      try (CardTransport faulty =
          CardTransport.borrow(
              command -> {
                if (command[ISO7816.OFFSET_INS] == (byte) GPSession.INS_DELETE) {
                  deletes[0]++;
                  return new byte[] {
                    (byte) (ISO7816.SW_CONDITIONS_NOT_SATISFIED >>> Byte.SIZE),
                    (byte) ISO7816.SW_CONDITIONS_NOT_SATISFIED
                  };
                }
                return delegate.transceive(command);
              })) {
        CardKeyRotationService.RotationFailure failure =
            assertThrows(
                CardKeyRotationService.RotationFailure.class,
                () -> service.rotate(faulty, first, DerivedScpKeys.fromConfig(second), true));
        assertEquals(CardKeyRotationService.Stage.RETIRE_SOURCE, failure.stage);
        assertEquals(FIRST_ISSUER_VERSION, failure.sourceVersion);
        assertEquals(SECOND_ISSUER_VERSION, failure.targetVersion);
        assertEquals(1, deletes[0], "no automatic retry or compensating mutation");
      }
      try (GlobalPlatformSession session =
          raw.openGlobalPlatformSession(GlobalPlatformSession.ISD_AID, second)) {
        assertTrue(session.hasKeyVersion(FIRST_ISSUER_VERSION));
        assertTrue(session.hasKeyVersion(SECOND_ISSUER_VERSION));
      }
    }
  }

  @Test
  void wildcardDestinationIsRejectedBeforeOpeningAnyChannel() throws Exception {
    CardTransport transport = org.mockito.Mockito.mock(CardTransport.class);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new CardKeyRotationService()
                .rotate(
                    transport,
                    syntheticKeys(FIRST_ISSUER_VERSION, FIRST_KEY_FILL),
                    DerivedScpKeys.fromConfig(ScpConfig.defaultTestScp03()),
                    true));
    org.mockito.Mockito.verifyNoInteractions(transport);
  }

  private static ScpConfig syntheticKeys(int version, byte value) {
    byte[] key = new byte[AES_128_KEY_BYTES];
    java.util.Arrays.fill(key, value);
    return ScpConfig.fromMaster(ScpConfig.Mode.SCP03, version, key);
  }

  private static void assertInventory(
      CardTransport transport, ScpConfig keys, int present, int absent) throws Exception {
    try (GlobalPlatformSession session =
        transport.openGlobalPlatformSession(GlobalPlatformSession.ISD_AID, keys)) {
      assertTrue(session.hasKeyVersion(present));
      assertFalse(session.hasKeyVersion(absent));
    }
  }
}
