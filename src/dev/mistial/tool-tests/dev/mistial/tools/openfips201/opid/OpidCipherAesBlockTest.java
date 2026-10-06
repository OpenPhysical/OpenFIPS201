/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.opid;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.crypto.AesBlock;
import dev.mistial.tools.openfips201.crypto.BcAesBlock;
import org.junit.jupiter.api.Test;

/** {@link OpidCipher} through the pluggable {@link AesBlock}, in memory. */
class OpidCipherAesBlockTest {
  @Test
  void everyFpeVectorMatchesThroughAnInMemoryAesBlock() throws Exception {
    int viaKey = FpeVectorChecks.runAll(OpidCipher::of);
    int viaBlock = FpeVectorChecks.runAll(key -> OpidCipher.of(new BcAesBlock(key)));
    assertEquals(viaKey, viaBlock);
    assertTrue(viaBlock >= 60, viaBlock + " checks");
  }

  @Test
  void destroyingTheCipherDestroysTheBlock() {
    BcAesBlock block = new BcAesBlock(new byte[32]);
    OpidCipher cipher = OpidCipher.of(block);
    cipher.destroy();
    assertThrows(IllegalStateException.class, cipher::kcv);
    assertThrows(
        IllegalStateException.class, () -> block.encryptBlock(new byte[16], 0, new byte[16], 0));
    assertThrows(IllegalArgumentException.class, () -> OpidCipher.of((AesBlock) null));
  }
}
