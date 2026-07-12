/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.gp;

import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11AesCmacService;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11Config;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import pro.javacard.gp.GPCardKeys;

public final class Scp03Kdf3DerivationService {
  private static final int KDD_LENGTH = 10;
  private static final int DEFAULT_KEY_LENGTH = 32;
  private static final byte PURPOSE_ENC = 0x01;
  private static final byte PURPOSE_MAC = 0x02;
  private static final byte PURPOSE_DEK = 0x03;

  private final Pkcs11AesCmacService cmac;

  public Scp03Kdf3DerivationService() {
    this(new Pkcs11AesCmacService());
  }

  Scp03Kdf3DerivationService(Pkcs11AesCmacService cmac) {
    this.cmac = cmac;
  }

  public DerivedScpKeys derive(Pkcs11Config masterKey, byte[] kdd, int keyVersion) {
    return derive(masterKey, kdd, keyVersion, DEFAULT_KEY_LENGTH);
  }

  public DerivedScpKeys derive(Pkcs11Config masterKey, byte[] kdd, int keyVersion, int keyLength) {
    if (kdd == null || kdd.length != KDD_LENGTH) {
      throw new IllegalArgumentException("SCP03 KDF3 KDD must be 10 bytes");
    }
    if (keyLength != 16 && keyLength != 24 && keyLength != 32) {
      throw new IllegalArgumentException("SCP03 card key length must be 16, 24, or 32 bytes");
    }
    byte[] enc = deriveOne(masterKey, PURPOSE_ENC, kdd);
    byte[] mac = deriveOne(masterKey, PURPOSE_MAC, kdd);
    byte[] dek = deriveOne(masterKey, PURPOSE_DEK, kdd);
    enc = slice(enc, 0, keyLength);
    mac = slice(mac, 0, keyLength);
    dek = slice(dek, 0, keyLength);
    ScpConfig config = new ScpConfig(ScpConfig.Mode.SCP03, keyVersion, enc, mac, dek);
    return new DerivedScpKeys(
        config,
        HexUtil.format(slice(config.toPlaintextKeys().kcv(GPCardKeys.KeyPurpose.ENC), 0, 3)),
        HexUtil.format(slice(config.toPlaintextKeys().kcv(GPCardKeys.KeyPurpose.MAC), 0, 3)),
        HexUtil.format(slice(config.toPlaintextKeys().kcv(GPCardKeys.KeyPurpose.DEK), 0, 3)));
  }

  private byte[] deriveOne(Pkcs11Config masterKey, byte purpose, byte[] kdd) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (int counter = 1; out.size() < DEFAULT_KEY_LENGTH; counter++) {
      byte[] round = cmac.sign(masterKey, roundInput(counter, purpose, kdd));
      out.write(round, 0, round.length);
    }
    return slice(out.toByteArray(), 0, DEFAULT_KEY_LENGTH);
  }

  static byte[] roundInput(int counter, byte purpose, byte[] kdd) {
    if (counter < 1 || counter > 255) {
      throw new IllegalArgumentException("SCP03 KDF3 counter must fit in one byte");
    }
    byte[] input = new byte[16];
    input[0] = (byte) counter;
    input[4] = purpose;
    System.arraycopy(kdd, 0, input, 6, kdd.length);
    return input;
  }

  private static byte[] slice(byte[] value, int offset, int length) {
    return Arrays.copyOfRange(value, offset, offset + length);
  }
}
