package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javacard.framework.PINException;
import org.globalplatform.CVM;
import org.globalplatform.GPSystem;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class PIVCVMPINTest {
  @Test
  void delegatesGlobalPinOperationsToThePlatformCvm() {
    // SP 800-73-5 Part 2, Section 3.2.1 assigns key reference 00 to the
    // platform Global PIN; this adapter must preserve the platform CVM state.
    CVM cvm = Mockito.mock(CVM.class);
    Mockito.when(cvm.getTriesRemaining()).thenReturn((byte) 5);
    Mockito.when(
            cvm.verify(
                Mockito.any(byte[].class),
                Mockito.anyShort(),
                Mockito.anyByte(),
                Mockito.eq(CVM.FORMAT_HEX)))
        .thenReturn(CVM.CVM_SUCCESS);
    Mockito.when(cvm.isVerified()).thenReturn(true);

    try (MockedStatic<GPSystem> gp = Mockito.mockStatic(GPSystem.class)) {
      gp.when(() -> GPSystem.getCVM(GPSystem.CVM_GLOBAL_PIN)).thenReturn(cvm);
      PIVCVMPIN pin = new PIVCVMPIN();
      byte[] value = {0x12, 0x34, 0x56};

      assertEquals(5, pin.getTriesRemaining());
      assertTrue(pin.check(value, (short) 0, (byte) value.length));
      assertTrue(pin.isValidated());
      pin.reset();
      pin.update(value, (short) 0, (byte) value.length);
      assertEquals(0, pin.getTryLimit());
      assertFalse(pin.supportsSetTryLimit());
      assertThrows(PINException.class, () -> pin.setTryLimit((byte) 3));

      Mockito.verify(cvm).resetState();
      Mockito.verify(cvm).update(value, (short) 0, (byte) value.length, CVM.FORMAT_HEX);
    }
  }

  @Test
  void globalPinStatusRequiresDiscoveryAuthorization() {
    // SP 800-73-5 Part 1 Section 3.3.2 binds Global PIN use to the stored Discovery policy.
    PIVPIN applicationPin = Mockito.mock(PIVPIN.class);
    PIVPIN globalPin = Mockito.mock(PIVPIN.class);
    Mockito.when(globalPin.isValidated()).thenReturn(true);

    assertFalse(PIVSecurityProvider.pinIsValidated(applicationPin, globalPin, false));
    assertTrue(PIVSecurityProvider.pinIsValidated(applicationPin, globalPin, true));

    Mockito.when(applicationPin.isValidated()).thenReturn(true);
    assertTrue(PIVSecurityProvider.pinIsValidated(applicationPin, globalPin, false));
  }
}
