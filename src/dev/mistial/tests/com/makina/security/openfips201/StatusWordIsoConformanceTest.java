package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Guards the applet's named status words against proprietary values.
 *
 * <p>ISO/IEC 7816-4:2020 Section 5.6: "the values '67XX', '6BXX', '6DXX', '6EXX', '6FXX' and '9XXX'
 * are proprietary, except the values '6700', '6701', '6702', '6B00', '6D00', '6E00', '6F00' and
 * '9000'". Every error status the applet names must be interindustry.
 */
class StatusWordIsoConformanceTest {

  static boolean isInterindustry(int sw) {
    int sw1 = (sw >> 8) & 0xFF;
    switch (sw1) {
      case 0x67:
        return sw == 0x6700 || sw == 0x6701 || sw == 0x6702;
      case 0x6B:
      case 0x6D:
      case 0x6E:
      case 0x6F:
        return (sw & 0xFF) == 0x00;
      case 0x61:
      case 0x62:
      case 0x63:
      case 0x64:
      case 0x65:
      case 0x66:
      case 0x68:
      case 0x69:
      case 0x6A:
      case 0x6C:
        return true;
      default:
        return sw == 0x9000;
    }
  }

  @Test
  void namedStatusWordsAreInterindustry() throws Exception {
    List<String> checked = new ArrayList<>();
    for (Class<?> type : new Class<?>[] {PIV.class, PIVSecureMessaging.class, Config.class}) {
      for (Field field : type.getDeclaredFields()) {
        if (!field.getName().startsWith("SW_")
            || field.getType() != short.class
            || !Modifier.isStatic(field.getModifiers())) {
          continue;
        }
        field.setAccessible(true);
        int sw = field.getShort(null) & 0xFFFF;
        assertTrue(
            isInterindustry(sw),
            String.format(
                "%s.%s = %04X is proprietary", type.getSimpleName(), field.getName(), sw));
        checked.add(field.getName());
      }
    }
    assertTrue(checked.contains("SW_OBJECT_EXISTS"), "the guard must see the PIV constants");
  }

  @Test
  void objectExistsIsIsoFileAlreadyExists() {
    assertEquals((short) 0x6A89, PIV.SW_OBJECT_EXISTS);
  }

  @Test
  void classifierFollowsIso78164Section56() {
    assertTrue(isInterindustry(0x6E00));
    assertTrue(isInterindustry(0x6A89));
    assertFalse(isInterindustry(0x6E27));
    assertFalse(isInterindustry(0x6D01));
    assertFalse(isInterindustry(0x6703));
  }
}
