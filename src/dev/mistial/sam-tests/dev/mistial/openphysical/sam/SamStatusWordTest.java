package dev.mistial.openphysical.sam;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import org.junit.jupiter.api.Test;

/**
 * Guards the SAM's named status words against proprietary values (ISO/IEC 7816-4:2020 Section 5.6:
 * '67XX', '6BXX', '6DXX', '6EXX' and '6FXX' are proprietary except '6700', '6701', '6702', '6B00',
 * '6D00', '6E00' and '6F00').
 */
class SamStatusWordTest {

  @Test
  void namedStatusWordsAreInterindustry() throws Exception {
    int checked = 0;
    for (Field field : SamConst.class.getDeclaredFields()) {
      if (!field.getName().startsWith("SW_")
          || field.getType() != short.class
          || !Modifier.isStatic(field.getModifiers())) {
        continue;
      }
      field.setAccessible(true);
      int sw = field.getShort(null) & 0xFFFF;
      int sw1 = sw >> 8;
      boolean proprietary =
          (sw1 == 0x67 && sw > 0x6702)
              || ((sw1 == 0x6B || sw1 == 0x6D || sw1 == 0x6E || sw1 == 0x6F) && (sw & 0xFF) != 0);
      assertTrue(!proprietary, String.format("SamConst.%s = %04X", field.getName(), sw));
      checked++;
    }
    assertTrue(checked > 0, "the guard must see the SamConst status words");
  }

  @Test
  void personalizationAfterLockIsConditionsOfUseNotSatisfied() {
    assertEquals((short) 0x6985, SamConst.SW_LOCKED);
  }
}
