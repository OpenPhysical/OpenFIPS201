/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.gp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11AesCmacService;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11Config;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class Scp03Kdf3DerivationServiceTest {
  @Test
  void roundInputMatchesGpProKdf3Template() {
    byte[] kdd = HexUtil.parse("00002345496554204839");

    assertEquals(
        "01000000010000002345496554204839",
        HexUtil.format(Scp03Kdf3DerivationService.roundInput(1, (byte) 0x01, kdd)));
    assertEquals(
        "02000000030000002345496554204839",
        HexUtil.format(Scp03Kdf3DerivationService.roundInput(2, (byte) 0x03, kdd)));
  }

  @Test
  void derivesKnownGpProAes256VectorFromCmacRounds() {
    Pkcs11Config config = new Pkcs11Config();
    config.keyAlias = "scp03-master-known";
    byte[] kdd = HexUtil.parse("00002345496554204839");
    Scp03Kdf3DerivationService service =
        new Scp03Kdf3DerivationService(new FixtureCmacService());

    DerivedScpKeys keys = service.derive(config, kdd, 1);

    assertArrayEquals(
        HexUtil.parse("B622ECDF65A3B1304A6279100936B5FA757F387CB59A621A207C5C80F23DB683"),
        keys.config.encKey);
    assertArrayEquals(
        HexUtil.parse("004442D5B39EE449DE126616AE9D13F0CFE83E1037AD91F2AA317536BB8F19CA"),
        keys.config.macKey);
    assertArrayEquals(
        HexUtil.parse("49D2D0F5601CF238C4CAF3A2E611A357CA175CC3407B24ED1634556B143655FC"),
        keys.config.dekKey);
    assertEquals(1, keys.config.keyVersion);
  }

  private static final class FixtureCmacService extends Pkcs11AesCmacService {
    private final Map<String, byte[]> rounds = new HashMap<String, byte[]>();

    FixtureCmacService() {
      put("01000000010000002345496554204839", "B622ECDF65A3B1304A6279100936B5FA");
      put("02000000010000002345496554204839", "757F387CB59A621A207C5C80F23DB683");
      put("01000000020000002345496554204839", "004442D5B39EE449DE126616AE9D13F0");
      put("02000000020000002345496554204839", "CFE83E1037AD91F2AA317536BB8F19CA");
      put("01000000030000002345496554204839", "49D2D0F5601CF238C4CAF3A2E611A357");
      put("02000000030000002345496554204839", "CA175CC3407B24ED1634556B143655FC");
    }

    @Override
    public byte[] sign(Pkcs11Config config, byte[] message) {
      byte[] value = rounds.get(HexUtil.format(message));
      if (value == null) {
        throw new AssertionError("Unexpected CMAC input " + HexUtil.format(message));
      }
      return value;
    }

    private void put(String input, String output) {
      rounds.put(input, HexUtil.parse(output));
    }
  }
}
