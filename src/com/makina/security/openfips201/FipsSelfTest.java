package com.makina.security.openfips201;

import javacard.framework.Util;
import javacard.security.AESKey;

/** Known-answer tests for applet-owned approved cryptographic constructions. */
final class FipsSelfTest {
  private static final byte[] AES_ZERO_BLOCK = {
    (byte) 0x66, (byte) 0xE9, (byte) 0x4B, (byte) 0xD4,
    (byte) 0xEF, (byte) 0x8A, (byte) 0x2C, (byte) 0x3B,
    (byte) 0x88, (byte) 0x4C, (byte) 0xFA, (byte) 0x59,
    (byte) 0xCA, (byte) 0x34, (byte) 0x2B, (byte) 0x2E
  };
  private static final byte[] CMAC_EMPTY = {
    (byte) 0x43, (byte) 0x87, (byte) 0xC1, (byte) 0x4B,
    (byte) 0x46, (byte) 0xEF, (byte) 0x7E, (byte) 0x17,
    (byte) 0x6D, (byte) 0xCE, (byte) 0xEF, (byte) 0xA8,
    (byte) 0x62, (byte) 0xD7, (byte) 0x2F, (byte) 0xF9
  };
  private static final byte[] SHA256_ABC = {
    (byte) 0xBA, (byte) 0x78, (byte) 0x16, (byte) 0xBF,
    (byte) 0x8F, (byte) 0x01, (byte) 0xCF, (byte) 0xEA,
    (byte) 0x41, (byte) 0x41, (byte) 0x40, (byte) 0xDE,
    (byte) 0x5D, (byte) 0xAE, (byte) 0x22, (byte) 0x23,
    (byte) 0xB0, (byte) 0x03, (byte) 0x61, (byte) 0xA3,
    (byte) 0x96, (byte) 0x17, (byte) 0x7A, (byte) 0x9C,
    (byte) 0xB4, (byte) 0x10, (byte) 0xFF, (byte) 0x61,
    (byte) 0xF2, (byte) 0x00, (byte) 0x15, (byte) 0xAD
  };

  private final AESKey aesKey = PIVCrypto.buildTransientAes128Key();

  boolean run(byte[] scratch) {
    Util.arrayFillNonAtomic(scratch, (short) 0, (short) 64, (byte) 0);
    aesKey.setKey(scratch, (short) 0);
    PIVCrypto.doAesEcbEncrypt(aesKey, scratch, (short) 0, (short) 16, scratch, (short) 16);
    if (!PIVSecurityProvider.arrayEqualsConstantTime(
        scratch, (short) 16, AES_ZERO_BLOCK, (short) 0, (short) AES_ZERO_BLOCK.length))
      return false;

    PIVCrypto.doAesCmac(aesKey, scratch, (short) 0, (short) 0, scratch, (short) 16);
    if (!PIVSecurityProvider.arrayEqualsConstantTime(
        scratch, (short) 16, CMAC_EMPTY, (short) 0, (short) CMAC_EMPTY.length)) return false;

    scratch[0] = (byte) 'a';
    scratch[1] = (byte) 'b';
    scratch[2] = (byte) 'c';
    PIVCrypto.doSha256(scratch, (short) 0, (short) 3, scratch, (short) 16);
    return PIVSecurityProvider.arrayEqualsConstantTime(
        scratch, (short) 16, SHA256_ABC, (short) 0, (short) SHA256_ABC.length);
  }
}
