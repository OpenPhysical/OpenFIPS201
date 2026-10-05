package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.util.Arrays;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import org.globalplatform.CVM;
import org.globalplatform.GPSystem;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import pro.javacard.engine.JavaCardEngine;

/**
 * White-box tests of {@link PIVSecurityProvider#updatePIN}: PIN history confidentiality, the
 * atomicity of the reference data and history writes, and platform refusal of a Global PIN change.
 */
class PIVSecurityProviderPinUpdateTest {
  private static final byte[] PIN_A = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, (byte) 0xFF, (byte) 0xFF
  };
  private static final byte[] PIN_B = {
    0x36, 0x35, 0x34, 0x33, 0x32, 0x31, (byte) 0xFF, (byte) 0xFF
  };
  private static final byte HISTORY = (byte) 2;

  private JavaCardEngine engine;
  private AutoCloseable engineContext;
  private MockedStatic<GPSystem> gp;
  private CVM cvm;

  @BeforeEach
  void enterCardContext() throws Exception {
    engine = JavaCardEngine.create();
    Method asCurrent = engine.getClass().getMethod("asCurrent");
    asCurrent.setAccessible(true);
    engineContext = (AutoCloseable) asCurrent.invoke(engine);
    cvm = Mockito.mock(CVM.class);
    gp = Mockito.mockStatic(GPSystem.class);
    gp.when(() -> GPSystem.getCVM(GPSystem.CVM_GLOBAL_PIN)).thenReturn(cvm);
    PIVCrypto.terminate();
    PIVCrypto.init();
  }

  @AfterEach
  void leaveCardContext() throws Exception {
    gp.close();
    engineContext.close();
  }

  @Test
  void pinHistoryHoldsKeyedEntriesRatherThanPlainDigests() throws Exception {
    PIVSecurityProvider provider = new PIVSecurityProvider(null);
    provider.updatePIN(PIV.ID_CVM_LOCAL_PIN, PIN_A, (short) 0, (byte) PIN_A.length, HISTORY);

    byte[] entry = Arrays.copyOfRange(pinHistory(provider), 0, 32);
    byte[] plainDigest = MessageDigest.getInstance("SHA-256").digest(PIN_A);
    assertFalse(
        Arrays.equals(plainDigest, entry),
        "The stored entry must not be an unkeyed SHA-256 of the current PIN");
    assertFalse(Arrays.equals(new byte[32], entry), "The current PIN must be recorded");

    // A second card keys its history with a different install-time secret.
    PIVSecurityProvider other = new PIVSecurityProvider(null);
    other.updatePIN(PIV.ID_CVM_LOCAL_PIN, PIN_A, (short) 0, (byte) PIN_A.length, HISTORY);
    assertFalse(
        Arrays.equals(entry, Arrays.copyOfRange(pinHistory(other), 0, 32)),
        "History entries must depend on a per-card secret");

    // The keyed entries still detect reuse.
    ISOException reuse =
        assertThrows(
            ISOException.class,
            () ->
                provider.updatePIN(
                    PIV.ID_CVM_LOCAL_PIN, PIN_A, (short) 0, (byte) PIN_A.length, HISTORY));
    assertEquals(ISO7816.SW_DATA_INVALID, reuse.getReason());
  }

  @Test
  void historyRejectionLeavesTheReferenceDataUnchanged() throws Exception {
    PIVSecurityProvider provider = new PIVSecurityProvider(null);
    provider.updatePIN(PIV.ID_CVM_LOCAL_PIN, PIN_A, (short) 0, (byte) PIN_A.length, HISTORY);
    provider.updatePIN(PIV.ID_CVM_LOCAL_PIN, PIN_B, (short) 0, (byte) PIN_B.length, HISTORY);
    byte[] historyBefore = pinHistory(provider).clone();

    ISOException reuse =
        assertThrows(
            ISOException.class,
            () ->
                provider.updatePIN(
                    PIV.ID_CVM_LOCAL_PIN, PIN_A, (short) 0, (byte) PIN_A.length, HISTORY));
    assertEquals(ISO7816.SW_DATA_INVALID, reuse.getReason());
    assertArrayEquals(historyBefore, pinHistory(provider));
    assertTrue(
        provider.getPIN(PIV.ID_CVM_LOCAL_PIN).check(PIN_B, (short) 0, (byte) PIN_B.length),
        "The current PIN must survive a history rejection");
  }

  @Test
  void referenceDataAndHistoryAreWrittenInOneTransaction() throws Exception {
    // JC 3.0.5 API OwnerPIN.update: "If a transaction is in progress, the new pin and try counter
    // update must be conditional i.e the copy operation must use the transaction facility."
    final byte[] depthAtUpdate = {(byte) -1};
    Mockito.when(
            cvm.update(
                Mockito.any(byte[].class),
                Mockito.anyShort(),
                Mockito.anyByte(),
                Mockito.eq(CVM.FORMAT_HEX)))
        .thenAnswer(
            ignored -> {
              depthAtUpdate[0] = JCSystem.getTransactionDepth();
              return true;
            });
    PIVSecurityProvider provider = new PIVSecurityProvider(null);

    provider.updatePIN(PIV.ID_CVM_GLOBAL_PIN, PIN_A, (short) 0, (byte) PIN_A.length, HISTORY);

    assertEquals(1, depthAtUpdate[0], "The PIN value must be written inside the transaction");
    assertEquals(0, JCSystem.getTransactionDepth(), "The transaction must be committed");
    assertEquals((byte) 0xFF, pinHistoryOccupied(provider)[0], "History must be recorded");
  }

  @Test
  void refusedGlobalPinUpdateReturns6A81AndRecordsNoHistory() throws Exception {
    // GP Card Specification v2.3.1 Section 8.2.1: setting a new CVM value "depends on the
    // requesting Application having the CVM Management privilege".
    Mockito.when(
            cvm.update(
                Mockito.any(byte[].class),
                Mockito.anyShort(),
                Mockito.anyByte(),
                Mockito.eq(CVM.FORMAT_HEX)))
        .thenReturn(false);
    PIVSecurityProvider provider = new PIVSecurityProvider(null);

    ISOException refused =
        assertThrows(
            ISOException.class,
            () ->
                provider.updatePIN(
                    PIV.ID_CVM_GLOBAL_PIN, PIN_A, (short) 0, (byte) PIN_A.length, HISTORY));

    assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, refused.getReason());
    assertEquals(0, JCSystem.getTransactionDepth(), "The transaction must be aborted");
    assertArrayEquals(
        new byte[pinHistoryOccupied(provider).length],
        pinHistoryOccupied(provider),
        "A refused update must not be recorded in PIN history");
  }

  private static byte[] pinHistory(PIVSecurityProvider provider) throws Exception {
    return (byte[]) field("pinHistory").get(provider);
  }

  private static byte[] pinHistoryOccupied(PIVSecurityProvider provider) throws Exception {
    return (byte[]) field("pinHistoryOccupied").get(provider);
  }

  private static Field field(String name) throws Exception {
    Field field = PIVSecurityProvider.class.getDeclaredField(name);
    field.setAccessible(true);
    return field;
  }
}
