/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.crypto;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** Central registration point for host-side cryptographic providers. */
public final class CryptoProviders {
  private CryptoProviders() {}

  public static void ensureBouncyCastle() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }
}
