/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.gp;

import dev.mistial.tools.openfips201.common.ScpConfig;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class CardKeyDerivationService {
  public DerivedScpKeys derive(byte[] master, String context, int keyVersion) throws Exception {
    byte[] enc = deriveOne(master, context, "ENC");
    byte[] mac = deriveOne(master, context, "MAC");
    byte[] dek = deriveOne(master, context, "DEK");
    ScpConfig config = new ScpConfig(ScpConfig.Mode.SCP03, keyVersion, enc, mac, dek);
    return DerivedScpKeys.fromConfig(config);
  }

  private static byte[] deriveOne(byte[] master, String context, String label) throws Exception {
    Mac hmac = Mac.getInstance("HmacSHA256");
    hmac.init(new SecretKeySpec(master, "HmacSHA256"));
    hmac.update(label.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    hmac.update((byte) 0x00);
    hmac.update(context.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    byte[] full = hmac.doFinal();
    return slice(full, 0, 16);
  }

  private static byte[] slice(byte[] value, int offset, int length) {
    byte[] result = new byte[length];
    System.arraycopy(value, offset, result, 0, length);
    return result;
  }
}
