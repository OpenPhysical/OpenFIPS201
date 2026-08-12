package com.makina.security.openfips201;

import javacard.framework.Util;
import javacard.security.AESKey;

/** Known-answer tests for applet-owned approved cryptographic constructions. */
final class FipsPowerUpSelfTests {
  private static final byte[] AES_ENCRYPT_ZERO = {
    (byte) 0x66, (byte) 0xE9, (byte) 0x4B, (byte) 0xD4,
    (byte) 0xEF, (byte) 0x8A, (byte) 0x2C, (byte) 0x3B,
    (byte) 0x88, (byte) 0x4C, (byte) 0xFA, (byte) 0x59,
    (byte) 0xCA, (byte) 0x34, (byte) 0x2B, (byte) 0x2E
  };
  private static final byte[] AES_DECRYPT_ZERO_CIPHERTEXT = {
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
  // #if VCI_CS7
  private static final byte[] SHA384_ABC = {
    (byte) 0xCB, (byte) 0x00, (byte) 0x75, (byte) 0x3F,
    (byte) 0x45, (byte) 0xA3, (byte) 0x5E, (byte) 0x8B,
    (byte) 0xB5, (byte) 0xA0, (byte) 0x3D, (byte) 0x69,
    (byte) 0x9A, (byte) 0xC6, (byte) 0x50, (byte) 0x07,
    (byte) 0x27, (byte) 0x2C, (byte) 0x32, (byte) 0xAB,
    (byte) 0x0E, (byte) 0xDE, (byte) 0xD1, (byte) 0x63,
    (byte) 0x1A, (byte) 0x8B, (byte) 0x60, (byte) 0x5A,
    (byte) 0x43, (byte) 0xFF, (byte) 0x5B, (byte) 0xED,
    (byte) 0x80, (byte) 0x86, (byte) 0x07, (byte) 0x2B,
    (byte) 0xA1, (byte) 0xE7, (byte) 0xCC, (byte) 0x23,
    (byte) 0x58, (byte) 0xBA, (byte) 0xEC, (byte) 0xA1,
    (byte) 0x34, (byte) 0xC8, (byte) 0x25, (byte) 0xA7
  };
  // #endif

  private final AESKey aesKey = PIVCrypto.buildTransientAes128Key();

  boolean run(byte[] scratch) {
    Util.arrayFillNonAtomic(scratch, (short) 0, (short) 64, (byte) 0);
    aesKey.setKey(scratch, (short) 0);
    short length =
        PIVCrypto.doAesEcbEncrypt(
            aesKey, scratch, (short) 0, (short) 16, scratch, (short) 16);
    if (length != PIVCrypto.LENGTH_BLOCK_AES
        || !PIVSecurityProvider.arrayEqualsConstantTime(
            scratch,
            (short) 16,
            AES_ENCRYPT_ZERO,
            (short) 0,
            (short) AES_ENCRYPT_ZERO.length))
      return false;

    // FIPS 140-3 IG 10.3.A Resolution 1 requires separate encryption and decryption CASTs.
    // CBC with an all-zero IV is used here so the test exercises the inverse cipher used by PIV SM.
    length =
        PIVCrypto.doAesCbcDecrypt(
            aesKey,
            scratch,
            (short) 48,
            PIVCrypto.LENGTH_BLOCK_AES,
            AES_DECRYPT_ZERO_CIPHERTEXT,
            (short) 0,
            PIVCrypto.LENGTH_BLOCK_AES,
            scratch,
            (short) 32);
    if (length != PIVCrypto.LENGTH_BLOCK_AES
        || !PIVSecurityProvider.arrayEqualsConstantTime(
            scratch, (short) 32, scratch, (short) 0, PIVCrypto.LENGTH_BLOCK_AES)) return false;

    length = PIVCrypto.doAesCmac(aesKey, scratch, (short) 0, (short) 0, scratch, (short) 16);
    if (length != PIVCrypto.LENGTH_BLOCK_AES
        || !PIVSecurityProvider.arrayEqualsConstantTime(
            scratch, (short) 16, CMAC_EMPTY, (short) 0, (short) CMAC_EMPTY.length)) return false;

    scratch[0] = (byte) 'a';
    scratch[1] = (byte) 'b';
    scratch[2] = (byte) 'c';
    length = PIVCrypto.doSha256(scratch, (short) 0, (short) 3, scratch, (short) 16);
    if (length != (short) SHA256_ABC.length
        || !PIVSecurityProvider.arrayEqualsConstantTime(
            scratch, (short) 16, SHA256_ABC, (short) 0, (short) SHA256_ABC.length)) return false;

    // #if VCI_CS7
    // IG 10.3.A Resolution 2 requires SHA-384's own CAST when SHA-512 is not implemented.
    scratch[0] = (byte) 'a';
    scratch[1] = (byte) 'b';
    scratch[2] = (byte) 'c';
    length = PIVCrypto.doSha384(scratch, (short) 0, (short) 3, scratch, (short) 16);
    if (length != (short) SHA384_ABC.length
        || !PIVSecurityProvider.arrayEqualsConstantTime(
            scratch, (short) 16, SHA384_ABC, (short) 0, (short) SHA384_ABC.length)) return false;
    // #endif

    return true;
  }
}
