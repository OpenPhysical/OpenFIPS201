/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.opid;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.SecureFiles;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11AdminService;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11AesBlock;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11Config;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11Session;
import dev.mistial.tools.openfips201.pkcs11.SoftHsmFixture;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Every {@code fpe.json} vector through FF1 on a SoftHSM2 token key ({@link Pkcs11AesBlock}). */
@Tag("softhsm")
class OpidCipherSoftHsmTest {
  @TempDir Path temp;

  @Test
  void everyFpeVectorMatchesThroughTheToken() throws Exception {
    SoftHsmFixture.requireSoftHsm();
    String label = SoftHsmFixture.uniqueLabel("ff1-");
    Pkcs11Config config = SoftHsmFixture.config(label);
    byte[] userPin = "ff1-user-pin".getBytes(StandardCharsets.US_ASCII);
    Pkcs11AdminService.initializeToken(
        config, "ff1-so-pin-0000".getBytes(StandardCharsets.US_ASCII), userPin.clone());
    config.pinFile = SecureFiles.writeNew(temp.resolve("pin"), userPin).toString();

    Pkcs11AdminService admin = new Pkcs11AdminService();
    try (Pkcs11Session session = Pkcs11Session.open(config)) {
      Map<String, String> labels = new HashMap<String, String>();
      int checks =
          FpeVectorChecks.runAll(
              key -> {
                String hex = HexUtil.format(key);
                String keyLabel = labels.get(hex);
                if (keyLabel == null) {
                  String prefix = "k" + labels.size();
                  keyLabel =
                      admin.importIinFpeKey(session, prefix, 0, key, OpidCipher.of(key).kcv())
                          .label;
                  labels.put(hex, keyLabel);
                }
                return OpidCipher.of(session.aesBlock(keyLabel));
              });
      assertEquals(FpeVectorChecks.runAll(OpidCipher::of), checks);
      assertTrue(labels.size() >= 2, labels.size() + " distinct keys");
    }
  }
}
