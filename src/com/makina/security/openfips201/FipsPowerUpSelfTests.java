package com.makina.security.openfips201;

import javacard.framework.Util;
import javacard.security.AESKey;
// #if FIPS_MODE
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
// #endif

/**
 * Power-up cryptographic algorithm self-tests (CASTs) of the FIPS profile.
 *
 * <p>Module boundary: the applet together with the Java Card platform services it invokes. A CAST
 * runs before first use for every approved algorithm that the FIPS profile exposes ({@link
 * FipsPolicy#allowsMechanism}) and that the platform offers ({@link PIVCrypto#supportsMechanism}):
 * AES encryption and decryption, AES-CMAC, SHA-256, SHA-384 (CS7), ECDSA signature generation and
 * verification, ECC CDH shared-secret computation and the RSA private- and public-key primitives.
 * The applet-owned OPACITY KDA CAST is {@link PIVOpacity#runCryptographicAlgorithmSelfTest}. Per
 * module policy, one key size or curve per algorithm is tested: P-256 for ECDSA and ECC CDH and
 * 2048-bit RSA. A mechanism the platform does not offer cannot be used and is not tested; an
 * offered mechanism whose test keys cannot be built fails the self-test.
 *
 * <p>The test keys hold public test vectors. They are allocated and loaded at install time, so a
 * power-up run writes no persistent memory.
 */
final class FipsPowerUpSelfTests {
  /** Minimum scratch length required by {@link #run}. */
  static final short LENGTH_SCRATCH = (short) 768;

  private static final byte[] AES_ENCRYPT_ZERO = {
    (byte) 0x66, (byte) 0xE9, (byte) 0x4B, (byte) 0xD4,
    (byte) 0xEF, (byte) 0x8A, (byte) 0x2C, (byte) 0x3B,
    (byte) 0x88, (byte) 0x4C, (byte) 0xFA, (byte) 0x59,
    (byte) 0xCA, (byte) 0x34, (byte) 0x2B, (byte) 0x2E
  };
  private static final byte[] AES_DECRYPT_CIPHERTEXT = {
    (byte) 0xC8, (byte) 0xA3, (byte) 0x31, (byte) 0xFF,
    (byte) 0x8E, (byte) 0xDD, (byte) 0x3D, (byte) 0xB1,
    (byte) 0x75, (byte) 0xE1, (byte) 0x54, (byte) 0x5D,
    (byte) 0xBE, (byte) 0xFB, (byte) 0x76, (byte) 0x0B
  };
  private static final byte[] AES_DECRYPT_PLAINTEXT = {
    (byte) 0x00, (byte) 0x11, (byte) 0x22, (byte) 0x33,
    (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77,
    (byte) 0x88, (byte) 0x99, (byte) 0xAA, (byte) 0xBB,
    (byte) 0xCC, (byte) 0xDD, (byte) 0xEE, (byte) 0xFF
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
  // #if FIPS_MODE
  // ECC CDH P-256: NIST CAVS KAS ECC CDH primitive vector, COUNT = 0 (dIUT, QIUT, QCAVS, ZIUT).
  // The same key pair is the ECDSA P-256 test key.
  private static final byte[] ECC_P256_PRIVATE = {
    (byte) 0x7D, (byte) 0x7D, (byte) 0xC5, (byte) 0xF7,
    (byte) 0x1E, (byte) 0xB2, (byte) 0x9D, (byte) 0xDA,
    (byte) 0xF8, (byte) 0x0D, (byte) 0x62, (byte) 0x14,
    (byte) 0x63, (byte) 0x2E, (byte) 0xEA, (byte) 0xE0,
    (byte) 0x3D, (byte) 0x90, (byte) 0x58, (byte) 0xAF,
    (byte) 0x1F, (byte) 0xB6, (byte) 0xD2, (byte) 0x2E,
    (byte) 0xD8, (byte) 0x0B, (byte) 0xAD, (byte) 0xB6,
    (byte) 0x2B, (byte) 0xC1, (byte) 0xA5, (byte) 0x34
  };
  private static final byte[] ECC_P256_PUBLIC = {
    (byte) 0x04, (byte) 0xEA, (byte) 0xD2, (byte) 0x18,
    (byte) 0x59, (byte) 0x01, (byte) 0x19, (byte) 0xE8,
    (byte) 0x87, (byte) 0x6B, (byte) 0x29, (byte) 0x14,
    (byte) 0x6F, (byte) 0xF8, (byte) 0x9C, (byte) 0xA6,
    (byte) 0x17, (byte) 0x70, (byte) 0xC4, (byte) 0xED,
    (byte) 0xBB, (byte) 0xF9, (byte) 0x7D, (byte) 0x38,
    (byte) 0xCE, (byte) 0x38, (byte) 0x5E, (byte) 0xD2,
    (byte) 0x81, (byte) 0xD8, (byte) 0xA6, (byte) 0xB2,
    (byte) 0x30, (byte) 0x28, (byte) 0xAF, (byte) 0x61,
    (byte) 0x28, (byte) 0x1F, (byte) 0xD3, (byte) 0x5E,
    (byte) 0x2F, (byte) 0xA7, (byte) 0x00, (byte) 0x25,
    (byte) 0x23, (byte) 0xAC, (byte) 0xC8, (byte) 0x5A,
    (byte) 0x42, (byte) 0x9C, (byte) 0xB0, (byte) 0x6E,
    (byte) 0xE6, (byte) 0x64, (byte) 0x83, (byte) 0x25,
    (byte) 0x38, (byte) 0x9F, (byte) 0x59, (byte) 0xED,
    (byte) 0xFC, (byte) 0xE1, (byte) 0x40, (byte) 0x51,
    (byte) 0x41
  };
  private static final byte[] ECC_CDH_PEER = {
    (byte) 0x04, (byte) 0x70, (byte) 0x0C, (byte) 0x48,
    (byte) 0xF7, (byte) 0x7F, (byte) 0x56, (byte) 0x58,
    (byte) 0x4C, (byte) 0x5C, (byte) 0xC6, (byte) 0x32,
    (byte) 0xCA, (byte) 0x65, (byte) 0x64, (byte) 0x0D,
    (byte) 0xB9, (byte) 0x1B, (byte) 0x6B, (byte) 0xAC,
    (byte) 0xCE, (byte) 0x3A, (byte) 0x4D, (byte) 0xF6,
    (byte) 0xB4, (byte) 0x2C, (byte) 0xE7, (byte) 0xCC,
    (byte) 0x83, (byte) 0x88, (byte) 0x33, (byte) 0xD2,
    (byte) 0x87, (byte) 0xDB, (byte) 0x71, (byte) 0xE5,
    (byte) 0x09, (byte) 0xE3, (byte) 0xFD, (byte) 0x9B,
    (byte) 0x06, (byte) 0x0D, (byte) 0xDB, (byte) 0x20,
    (byte) 0xBA, (byte) 0x5C, (byte) 0x51, (byte) 0xDC,
    (byte) 0xC5, (byte) 0x94, (byte) 0x8D, (byte) 0x46,
    (byte) 0xFB, (byte) 0xF6, (byte) 0x40, (byte) 0xDF,
    (byte) 0xE0, (byte) 0x44, (byte) 0x17, (byte) 0x82,
    (byte) 0xCA, (byte) 0xB8, (byte) 0x5F, (byte) 0xA4,
    (byte) 0xAC
  };
  private static final byte[] ECC_CDH_Z = {
    (byte) 0x46, (byte) 0xFC, (byte) 0x62, (byte) 0x10,
    (byte) 0x64, (byte) 0x20, (byte) 0xFF, (byte) 0x01,
    (byte) 0x2E, (byte) 0x54, (byte) 0xA4, (byte) 0x34,
    (byte) 0xFB, (byte) 0xDD, (byte) 0x2D, (byte) 0x25,
    (byte) 0xCC, (byte) 0xC5, (byte) 0x85, (byte) 0x20,
    (byte) 0x60, (byte) 0x56, (byte) 0x1E, (byte) 0x68,
    (byte) 0x04, (byte) 0x0D, (byte) 0xD7, (byte) 0x77,
    (byte) 0x89, (byte) 0x97, (byte) 0xBD, (byte) 0x7B
  };
  // ECDSA P-256 signature (DER) by ECC_P256_PRIVATE over the precomputed hash SHA256_ABC.
  private static final byte[] ECDSA_SIGNATURE = {
    (byte) 0x30, (byte) 0x46, (byte) 0x02, (byte) 0x21,
    (byte) 0x00, (byte) 0x94, (byte) 0x45, (byte) 0xDF,
    (byte) 0x56, (byte) 0xE9, (byte) 0xC1, (byte) 0xB6,
    (byte) 0xB8, (byte) 0x18, (byte) 0xB0, (byte) 0xDC,
    (byte) 0xA4, (byte) 0xA9, (byte) 0xDD, (byte) 0x1D,
    (byte) 0x5C, (byte) 0x41, (byte) 0x9E, (byte) 0xB5,
    (byte) 0x2B, (byte) 0xF4, (byte) 0xAC, (byte) 0x40,
    (byte) 0x4B, (byte) 0x7F, (byte) 0x71, (byte) 0x37,
    (byte) 0x9C, (byte) 0x02, (byte) 0x63, (byte) 0xBB,
    (byte) 0x61, (byte) 0x02, (byte) 0x21, (byte) 0x00,
    (byte) 0xE8, (byte) 0xDF, (byte) 0x3F, (byte) 0x81,
    (byte) 0x17, (byte) 0xB1, (byte) 0xB5, (byte) 0x15,
    (byte) 0x6D, (byte) 0xBF, (byte) 0x9B, (byte) 0x5C,
    (byte) 0x40, (byte) 0xB5, (byte) 0x5A, (byte) 0x64,
    (byte) 0xCA, (byte) 0x55, (byte) 0x80, (byte) 0x24,
    (byte) 0xFD, (byte) 0x6E, (byte) 0x37, (byte) 0xA4,
    (byte) 0x83, (byte) 0x30, (byte) 0x4E, (byte) 0x63,
    (byte) 0x02, (byte) 0x27, (byte) 0xFC, (byte) 0xB6
  };
  // RSA-2048 test key (public exponent 65537) and RSA_SIGNATURE = M^d mod n for the message
  // representative M = 00 01 02 .. FF built by rsaKnownAnswer().
  private static final byte[] RSA_MODULUS = {
    (byte) 0xB8, (byte) 0xFD, (byte) 0x74, (byte) 0xC1,
    (byte) 0xFA, (byte) 0xEC, (byte) 0x13, (byte) 0x59,
    (byte) 0x61, (byte) 0x01, (byte) 0x0D, (byte) 0xC9,
    (byte) 0xCA, (byte) 0x30, (byte) 0xFB, (byte) 0x72,
    (byte) 0x08, (byte) 0xC2, (byte) 0x7A, (byte) 0xF2,
    (byte) 0xFD, (byte) 0x64, (byte) 0xEC, (byte) 0x35,
    (byte) 0x4C, (byte) 0xE4, (byte) 0xC1, (byte) 0x93,
    (byte) 0x10, (byte) 0x8E, (byte) 0x18, (byte) 0xFF,
    (byte) 0x18, (byte) 0xE9, (byte) 0x92, (byte) 0x21,
    (byte) 0xEE, (byte) 0x05, (byte) 0x1D, (byte) 0xE5,
    (byte) 0x1D, (byte) 0xB1, (byte) 0x69, (byte) 0xE0,
    (byte) 0x63, (byte) 0xCB, (byte) 0xAE, (byte) 0x65,
    (byte) 0xD2, (byte) 0x1A, (byte) 0xA7, (byte) 0x7F,
    (byte) 0xB4, (byte) 0xD7, (byte) 0xD5, (byte) 0x43,
    (byte) 0xB0, (byte) 0x37, (byte) 0x7F, (byte) 0x92,
    (byte) 0xE3, (byte) 0x79, (byte) 0x62, (byte) 0x75,
    (byte) 0x2C, (byte) 0x3F, (byte) 0xF3, (byte) 0xD2,
    (byte) 0x7E, (byte) 0xBC, (byte) 0xC3, (byte) 0x00,
    (byte) 0xA9, (byte) 0x80, (byte) 0x1C, (byte) 0x48,
    (byte) 0x9A, (byte) 0x79, (byte) 0x64, (byte) 0x98,
    (byte) 0xAF, (byte) 0xCC, (byte) 0xFD, (byte) 0x46,
    (byte) 0x26, (byte) 0xC9, (byte) 0x6D, (byte) 0x4A,
    (byte) 0x36, (byte) 0xD6, (byte) 0x5B, (byte) 0x3D,
    (byte) 0x4F, (byte) 0x80, (byte) 0x24, (byte) 0x2B,
    (byte) 0x43, (byte) 0x1C, (byte) 0x82, (byte) 0xAA,
    (byte) 0x71, (byte) 0xE2, (byte) 0xD8, (byte) 0x44,
    (byte) 0x76, (byte) 0x31, (byte) 0x8C, (byte) 0x89,
    (byte) 0xF6, (byte) 0xE1, (byte) 0xAB, (byte) 0x67,
    (byte) 0xB2, (byte) 0x6A, (byte) 0x42, (byte) 0x01,
    (byte) 0x11, (byte) 0x7B, (byte) 0xF5, (byte) 0xC8,
    (byte) 0xC8, (byte) 0x31, (byte) 0x68, (byte) 0xBF,
    (byte) 0xC6, (byte) 0x1B, (byte) 0x55, (byte) 0x81,
    (byte) 0xF9, (byte) 0x2F, (byte) 0xFC, (byte) 0xB3,
    (byte) 0xE4, (byte) 0xD8, (byte) 0xA8, (byte) 0xC6,
    (byte) 0xAD, (byte) 0xAA, (byte) 0x1F, (byte) 0xC2,
    (byte) 0x02, (byte) 0xDB, (byte) 0xF6, (byte) 0x95,
    (byte) 0xD5, (byte) 0x5B, (byte) 0x53, (byte) 0xFF,
    (byte) 0xF3, (byte) 0x0D, (byte) 0x87, (byte) 0xC8,
    (byte) 0x3F, (byte) 0xD8, (byte) 0x11, (byte) 0xB8,
    (byte) 0x15, (byte) 0x79, (byte) 0x28, (byte) 0x0F,
    (byte) 0x6A, (byte) 0x7B, (byte) 0xE1, (byte) 0xD8,
    (byte) 0xE4, (byte) 0xA5, (byte) 0x35, (byte) 0xC8,
    (byte) 0x8B, (byte) 0x35, (byte) 0xAE, (byte) 0x18,
    (byte) 0xBC, (byte) 0x3D, (byte) 0x56, (byte) 0x04,
    (byte) 0xC5, (byte) 0xC6, (byte) 0x26, (byte) 0x79,
    (byte) 0x1D, (byte) 0xD2, (byte) 0xED, (byte) 0xBE,
    (byte) 0xB8, (byte) 0x20, (byte) 0xA4, (byte) 0xBC,
    (byte) 0x24, (byte) 0x90, (byte) 0x91, (byte) 0x9A,
    (byte) 0x1D, (byte) 0xB8, (byte) 0x4A, (byte) 0x35,
    (byte) 0x18, (byte) 0x88, (byte) 0x53, (byte) 0x8E,
    (byte) 0xEC, (byte) 0xDB, (byte) 0x07, (byte) 0x69,
    (byte) 0xA2, (byte) 0xA2, (byte) 0xD4, (byte) 0x13,
    (byte) 0x69, (byte) 0xC3, (byte) 0x6C, (byte) 0x95,
    (byte) 0x91, (byte) 0x0D, (byte) 0x35, (byte) 0xEF,
    (byte) 0x08, (byte) 0xC6, (byte) 0xCF, (byte) 0xA5,
    (byte) 0xC3, (byte) 0x2D, (byte) 0x52, (byte) 0xF6,
    (byte) 0xB1, (byte) 0x5C, (byte) 0x5E, (byte) 0x2B,
    (byte) 0xA2, (byte) 0x83, (byte) 0x6F, (byte) 0xDA,
    (byte) 0xB2, (byte) 0x65, (byte) 0x9D, (byte) 0x04,
    (byte) 0x09, (byte) 0xA9, (byte) 0x83, (byte) 0x96,
    (byte) 0x35, (byte) 0x74, (byte) 0x28, (byte) 0xFE,
    (byte) 0x02, (byte) 0xF8, (byte) 0x63, (byte) 0xF4,
    (byte) 0x9D, (byte) 0x6D, (byte) 0xD0, (byte) 0x32,
    (byte) 0x1C, (byte) 0x57, (byte) 0x0E, (byte) 0x1F
  };
  private static final byte[] RSA_PRIVATE_EXPONENT = {
    (byte) 0x21, (byte) 0x7A, (byte) 0x79, (byte) 0x29,
    (byte) 0x6B, (byte) 0xF4, (byte) 0x52, (byte) 0x72,
    (byte) 0x1F, (byte) 0xFC, (byte) 0x95, (byte) 0x56,
    (byte) 0xBA, (byte) 0x19, (byte) 0x50, (byte) 0x40,
    (byte) 0x2C, (byte) 0x76, (byte) 0xA9, (byte) 0xD2,
    (byte) 0x94, (byte) 0xEA, (byte) 0x31, (byte) 0x57,
    (byte) 0x5A, (byte) 0x11, (byte) 0xA2, (byte) 0x38,
    (byte) 0xAF, (byte) 0xCB, (byte) 0xCF, (byte) 0x99,
    (byte) 0x47, (byte) 0x14, (byte) 0x6A, (byte) 0x46,
    (byte) 0x6A, (byte) 0xB1, (byte) 0x91, (byte) 0x5D,
    (byte) 0xF8, (byte) 0x18, (byte) 0x35, (byte) 0xFD,
    (byte) 0x8E, (byte) 0x81, (byte) 0xFB, (byte) 0x8F,
    (byte) 0x60, (byte) 0xCD, (byte) 0x43, (byte) 0x17,
    (byte) 0xF9, (byte) 0x0E, (byte) 0x00, (byte) 0x82,
    (byte) 0x0D, (byte) 0xFF, (byte) 0x95, (byte) 0x3E,
    (byte) 0x6B, (byte) 0x9D, (byte) 0x79, (byte) 0xA4,
    (byte) 0x93, (byte) 0xFC, (byte) 0x04, (byte) 0xEF,
    (byte) 0xC8, (byte) 0xD0, (byte) 0xF7, (byte) 0x87,
    (byte) 0x84, (byte) 0xA5, (byte) 0x73, (byte) 0x38,
    (byte) 0xEE, (byte) 0x7F, (byte) 0xDE, (byte) 0xA5,
    (byte) 0x45, (byte) 0x57, (byte) 0x97, (byte) 0x54,
    (byte) 0x9D, (byte) 0x4B, (byte) 0x61, (byte) 0xD4,
    (byte) 0x87, (byte) 0x05, (byte) 0x17, (byte) 0x21,
    (byte) 0x0A, (byte) 0xE4, (byte) 0xB9, (byte) 0x66,
    (byte) 0xFC, (byte) 0xEF, (byte) 0xC9, (byte) 0x73,
    (byte) 0xF8, (byte) 0x45, (byte) 0x61, (byte) 0xF7,
    (byte) 0x4D, (byte) 0xDE, (byte) 0x9C, (byte) 0xBD,
    (byte) 0x11, (byte) 0x29, (byte) 0x79, (byte) 0x20,
    (byte) 0x3C, (byte) 0xA9, (byte) 0x3F, (byte) 0x45,
    (byte) 0xBB, (byte) 0x38, (byte) 0xD0, (byte) 0x5B,
    (byte) 0xE4, (byte) 0x63, (byte) 0x10, (byte) 0xBE,
    (byte) 0x78, (byte) 0x27, (byte) 0x55, (byte) 0x3B,
    (byte) 0x6F, (byte) 0xC9, (byte) 0xC1, (byte) 0xD6,
    (byte) 0x04, (byte) 0xA5, (byte) 0x5F, (byte) 0xB3,
    (byte) 0x7E, (byte) 0x3E, (byte) 0x99, (byte) 0x12,
    (byte) 0x6B, (byte) 0x91, (byte) 0x77, (byte) 0x93,
    (byte) 0xBE, (byte) 0x60, (byte) 0xE4, (byte) 0xBE,
    (byte) 0x9A, (byte) 0x0C, (byte) 0x1F, (byte) 0x21,
    (byte) 0xBB, (byte) 0xC7, (byte) 0x3C, (byte) 0x69,
    (byte) 0xAA, (byte) 0x28, (byte) 0xC3, (byte) 0x0A,
    (byte) 0x3C, (byte) 0x03, (byte) 0xD0, (byte) 0xEB,
    (byte) 0xEE, (byte) 0x32, (byte) 0xA7, (byte) 0x6F,
    (byte) 0x01, (byte) 0x97, (byte) 0x94, (byte) 0xA3,
    (byte) 0x8F, (byte) 0xD9, (byte) 0xC0, (byte) 0x79,
    (byte) 0x22, (byte) 0x2A, (byte) 0xE2, (byte) 0x50,
    (byte) 0x04, (byte) 0x61, (byte) 0xB7, (byte) 0x73,
    (byte) 0x69, (byte) 0x51, (byte) 0xC3, (byte) 0x0E,
    (byte) 0x7E, (byte) 0x90, (byte) 0x2E, (byte) 0x54,
    (byte) 0x66, (byte) 0x99, (byte) 0x4F, (byte) 0x9E,
    (byte) 0xED, (byte) 0x2F, (byte) 0xC7, (byte) 0x7D,
    (byte) 0x68, (byte) 0xE1, (byte) 0xCD, (byte) 0x5F,
    (byte) 0xFF, (byte) 0x46, (byte) 0x16, (byte) 0x55,
    (byte) 0x60, (byte) 0xD4, (byte) 0xEC, (byte) 0x23,
    (byte) 0xA9, (byte) 0x9D, (byte) 0x68, (byte) 0xE3,
    (byte) 0x82, (byte) 0x1F, (byte) 0xCF, (byte) 0xDF,
    (byte) 0x72, (byte) 0x15, (byte) 0x5E, (byte) 0x43,
    (byte) 0x70, (byte) 0x69, (byte) 0x7F, (byte) 0xBE,
    (byte) 0xB1, (byte) 0x1D, (byte) 0xA0, (byte) 0x27,
    (byte) 0x84, (byte) 0xD2, (byte) 0xB9, (byte) 0x8A,
    (byte) 0x13, (byte) 0xC7, (byte) 0x04, (byte) 0xE2,
    (byte) 0xC5, (byte) 0x3E, (byte) 0xA0, (byte) 0x2A,
    (byte) 0xCE, (byte) 0xAD, (byte) 0xFC, (byte) 0xDB,
    (byte) 0x1A, (byte) 0x90, (byte) 0x5E, (byte) 0x04,
    (byte) 0x79, (byte) 0x6D, (byte) 0x02, (byte) 0xD9
  };
  private static final byte[] RSA_SIGNATURE = {
    (byte) 0xA1, (byte) 0xCD, (byte) 0x8C, (byte) 0x58,
    (byte) 0x52, (byte) 0x9E, (byte) 0x23, (byte) 0xA5,
    (byte) 0x64, (byte) 0xF5, (byte) 0x4C, (byte) 0xC7,
    (byte) 0xDC, (byte) 0x07, (byte) 0x57, (byte) 0x43,
    (byte) 0xDD, (byte) 0x77, (byte) 0x3F, (byte) 0xD6,
    (byte) 0xD3, (byte) 0x2E, (byte) 0xF5, (byte) 0xC7,
    (byte) 0x38, (byte) 0x16, (byte) 0xA2, (byte) 0x56,
    (byte) 0x53, (byte) 0x6B, (byte) 0xDE, (byte) 0xA0,
    (byte) 0x0B, (byte) 0x8A, (byte) 0x30, (byte) 0xDB,
    (byte) 0xB9, (byte) 0x9C, (byte) 0xD0, (byte) 0x92,
    (byte) 0x0D, (byte) 0x0F, (byte) 0xE7, (byte) 0xD3,
    (byte) 0x2E, (byte) 0x19, (byte) 0x1E, (byte) 0xE2,
    (byte) 0xB5, (byte) 0x2B, (byte) 0x62, (byte) 0x72,
    (byte) 0x0D, (byte) 0xE8, (byte) 0xC7, (byte) 0x7D,
    (byte) 0x12, (byte) 0x0F, (byte) 0x6D, (byte) 0x91,
    (byte) 0x55, (byte) 0xF9, (byte) 0xA7, (byte) 0xEC,
    (byte) 0x87, (byte) 0x69, (byte) 0x4E, (byte) 0x6C,
    (byte) 0x90, (byte) 0x44, (byte) 0xA3, (byte) 0x7B,
    (byte) 0x35, (byte) 0xB7, (byte) 0x89, (byte) 0xFC,
    (byte) 0x00, (byte) 0x6A, (byte) 0x10, (byte) 0x8B,
    (byte) 0x5F, (byte) 0xEA, (byte) 0xBA, (byte) 0x65,
    (byte) 0x8F, (byte) 0x4B, (byte) 0x0D, (byte) 0xE9,
    (byte) 0x1D, (byte) 0xFF, (byte) 0x98, (byte) 0x62,
    (byte) 0x9E, (byte) 0x7C, (byte) 0x8A, (byte) 0x3D,
    (byte) 0xB3, (byte) 0x29, (byte) 0x2A, (byte) 0x78,
    (byte) 0x5B, (byte) 0x17, (byte) 0x30, (byte) 0x62,
    (byte) 0xB2, (byte) 0x9B, (byte) 0xB6, (byte) 0xCE,
    (byte) 0xF5, (byte) 0xEC, (byte) 0xC9, (byte) 0xB1,
    (byte) 0x93, (byte) 0xFE, (byte) 0x3C, (byte) 0x7A,
    (byte) 0xE3, (byte) 0x04, (byte) 0x10, (byte) 0xD9,
    (byte) 0xAF, (byte) 0x36, (byte) 0x97, (byte) 0x96,
    (byte) 0xE5, (byte) 0xCD, (byte) 0xED, (byte) 0x19,
    (byte) 0x7A, (byte) 0x02, (byte) 0xE6, (byte) 0xA0,
    (byte) 0x71, (byte) 0xC3, (byte) 0x4B, (byte) 0xE1,
    (byte) 0x78, (byte) 0x9F, (byte) 0x18, (byte) 0x9C,
    (byte) 0x67, (byte) 0xF0, (byte) 0x79, (byte) 0xDA,
    (byte) 0x8E, (byte) 0xC3, (byte) 0x08, (byte) 0xF3,
    (byte) 0x2C, (byte) 0xEF, (byte) 0x05, (byte) 0x42,
    (byte) 0xB4, (byte) 0xFE, (byte) 0x11, (byte) 0xA9,
    (byte) 0x17, (byte) 0x49, (byte) 0x81, (byte) 0xA2,
    (byte) 0x83, (byte) 0xB4, (byte) 0x57, (byte) 0xB4,
    (byte) 0xB7, (byte) 0xFE, (byte) 0x28, (byte) 0xDA,
    (byte) 0xAB, (byte) 0xD0, (byte) 0xB8, (byte) 0x46,
    (byte) 0x30, (byte) 0x8E, (byte) 0xFE, (byte) 0x04,
    (byte) 0xE4, (byte) 0x37, (byte) 0xB3, (byte) 0x6E,
    (byte) 0xCF, (byte) 0x6F, (byte) 0x84, (byte) 0x7B,
    (byte) 0xB6, (byte) 0xC1, (byte) 0xCC, (byte) 0x57,
    (byte) 0x80, (byte) 0x40, (byte) 0x1A, (byte) 0x5C,
    (byte) 0x38, (byte) 0x1E, (byte) 0x84, (byte) 0xF6,
    (byte) 0x20, (byte) 0x73, (byte) 0x39, (byte) 0x3F,
    (byte) 0x98, (byte) 0x46, (byte) 0x38, (byte) 0x73,
    (byte) 0x2F, (byte) 0x73, (byte) 0x45, (byte) 0xCA,
    (byte) 0x85, (byte) 0xDD, (byte) 0x73, (byte) 0x4F,
    (byte) 0x45, (byte) 0x74, (byte) 0x25, (byte) 0xE2,
    (byte) 0x7B, (byte) 0x0E, (byte) 0xC2, (byte) 0xEA,
    (byte) 0x43, (byte) 0x5C, (byte) 0xC2, (byte) 0xFE,
    (byte) 0x8C, (byte) 0xA8, (byte) 0x32, (byte) 0x16,
    (byte) 0x3A, (byte) 0x87, (byte) 0x4D, (byte) 0x12,
    (byte) 0x4D, (byte) 0x19, (byte) 0x91, (byte) 0xF0,
    (byte) 0x0C, (byte) 0x7A, (byte) 0xB9, (byte) 0x41,
    (byte) 0xD9, (byte) 0x68, (byte) 0x95, (byte) 0xB8,
    (byte) 0x21, (byte) 0xE0, (byte) 0x0D, (byte) 0xB5,
    (byte) 0x8F, (byte) 0x9E, (byte) 0x00, (byte) 0x85,
    (byte) 0x1A, (byte) 0x24, (byte) 0x67, (byte) 0x72
  };
  private static final byte[] RSA_PUBLIC_EXPONENT = {(byte) 0x01, (byte) 0x00, (byte) 0x01};
  private static final short LENGTH_RSA = (short) 256;

  private final ECParams p256;
  private final ECPointValidator validator;
  private final ECPrivateKey eccPrivate;
  private final ECPublicKey eccPublic;
  private final RSAPrivateKey rsaPrivate;
  private final RSAPublicKey rsaPublic;
  // #endif

  private final AESKey aesKey = PIVCrypto.buildTransientAes128Key();
  private final PIVCrypto crypto;

  /**
   * Allocates and loads the test keys at install time.
   *
   * @param crypto the applet instance's engines, which the CASTs exercise
   * @param curves the install-time curve registry supplying the P-256 domain parameters
   * @param validator the EC public-point validator used by the ECC CDH entry point
   */
  FipsPowerUpSelfTests(PIVCrypto crypto, ECCurveRegistry curves, ECPointValidator validator) {
    this.crypto = crypto;
    // #if FIPS_MODE
    p256 = curves.forMechanism(PIV.ID_ALG_ECC_P256);
    this.validator = validator;

    ECPrivateKey ecPrivate = null;
    ECPublicKey ecPublic = null;
    try {
      ecPrivate =
          (ECPrivateKey)
              KeyBuilder.buildKey(
                  KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
      ecPublic =
          (ECPublicKey)
              KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
      setDomainParameters(ecPrivate, p256);
      setDomainParameters(ecPublic, p256);
      ecPrivate.setS(ECC_P256_PRIVATE, (short) 0, (short) ECC_P256_PRIVATE.length);
      ecPublic.setW(ECC_P256_PUBLIC, (short) 0, (short) ECC_P256_PUBLIC.length);
    } catch (CryptoException e) {
      // The platform cannot build P-256 keys; runEcc() fails if it still offers the mechanism.
      ecPrivate = null;
      ecPublic = null;
    }
    eccPrivate = ecPrivate;
    eccPublic = ecPublic;

    RSAPrivateKey privateRsa = null;
    RSAPublicKey publicRsa = null;
    try {
      privateRsa =
          (RSAPrivateKey)
              KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_2048, false);
      publicRsa =
          (RSAPublicKey)
              KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
      privateRsa.setModulus(RSA_MODULUS, (short) 0, LENGTH_RSA);
      privateRsa.setExponent(RSA_PRIVATE_EXPONENT, (short) 0, LENGTH_RSA);
      publicRsa.setModulus(RSA_MODULUS, (short) 0, LENGTH_RSA);
      publicRsa.setExponent(RSA_PUBLIC_EXPONENT, (short) 0, (short) RSA_PUBLIC_EXPONENT.length);
    } catch (CryptoException e) {
      // The platform cannot build RSA-2048 keys; runRsa() fails if it still offers the mechanism.
      privateRsa = null;
      publicRsa = null;
    }
    rsaPrivate = privateRsa;
    rsaPublic = publicRsa;
    // #endif
  }

  /**
   * Runs every CAST of the compiled profile.
   *
   * @param scratch a transient buffer of at least {@link #LENGTH_SCRATCH} bytes
   * @return true only if every CAST produced its known answer; any exception is a failure
   */
  boolean run(byte[] scratch) {
    try {
      if (!runSymmetric(scratch)) return false;
      // #if FIPS_MODE
      if (!runEcc(scratch) || !runRsa(scratch)) return false;
      // #endif
      return true;
    } catch (RuntimeException e) {
      return false;
    }
  }

  // #if FIPS_MODE
  private static void setDomainParameters(ECKey key, ECParams params) {
    byte[] a = params.getA();
    byte[] b = params.getB();
    byte[] g = params.getG();
    byte[] p = params.getP();
    byte[] r = params.getN();
    key.setA(a, (short) 0, (short) a.length);
    key.setB(b, (short) 0, (short) b.length);
    key.setG(g, (short) 0, (short) g.length);
    key.setR(r, (short) 0, (short) r.length);
    key.setFieldFP(p, (short) 0, (short) p.length);
    key.setK(params.getH());
  }

  /** ECDSA P-256 signature verification and generation, and ECC CDH P-256 shared secret. */
  private boolean runEcc(byte[] scratch) {
    if (!crypto.supportsMechanism(PIV.ID_ALG_ECC_P256)) return true;
    if (eccPrivate == null) return false;
    short hashLength = (short) SHA256_ABC.length;

    // Each part runs when the platform offers the engine a P-256 key of that role uses
    // (PIVCrypto.supportsKeyRole), the same check that admits such a key definition.
    if (crypto.supportsKeyRole(PIV.ID_ALG_ECC_P256, PIVKeyObject.ROLE_SIGN)) {
      // Verification: the fixed signature must verify under the fixed public key.
      if (!crypto.doVerify(
          eccPublic,
          SHA256_ABC,
          (short) 0,
          hashLength,
          ECDSA_SIGNATURE,
          (short) 0,
          (short) ECDSA_SIGNATURE.length)) return false;

      // Generation: ECDSA uses a random per-message secret, so the generated signature is checked
      // by verification under the fixed public key rather than against a fixed value.
      short signatureLength =
          crypto.doSign(eccPrivate, SHA256_ABC, (short) 0, hashLength, scratch, (short) 0);
      if (!crypto.doVerify(
          eccPublic, SHA256_ABC, (short) 0, hashLength, scratch, (short) 0, signatureLength)) {
        return false;
      }
    }

    if (!crypto.supportsKeyRole(PIV.ID_ALG_ECC_P256, PIVKeyObject.ROLE_KEY_ESTABLISH)) {
      return true;
    }
    short length =
        crypto.doKeyAgreement(
            eccPrivate,
            ECC_CDH_PEER,
            (short) 0,
            (short) ECC_CDH_PEER.length,
            scratch,
            (short) 0,
            validator,
            p256);
    return length == (short) ECC_CDH_Z.length
        && PIVSecurityProvider.arrayEqualsConstantTime(
            scratch, (short) 0, ECC_CDH_Z, (short) 0, (short) ECC_CDH_Z.length);
  }

  /** RSA-2048 private-key primitive known answer and its public-key inverse. */
  private boolean runRsa(byte[] scratch) {
    if (!crypto.supportsMechanism(PIV.ID_ALG_RSA_2048)) return true;
    if (rsaPrivate == null) return false;
    for (short index = (short) 0; index < LENGTH_RSA; index++) {
      scratch[index] = (byte) index;
    }
    short length = crypto.doSign(rsaPrivate, scratch, (short) 0, LENGTH_RSA, scratch, LENGTH_RSA);
    if (length != LENGTH_RSA
        || !PIVSecurityProvider.arrayEqualsConstantTime(
            scratch, LENGTH_RSA, RSA_SIGNATURE, (short) 0, LENGTH_RSA)) return false;
    short recovered = (short) (LENGTH_RSA * (short) 2);
    length = crypto.doRsaPublic(rsaPublic, scratch, LENGTH_RSA, LENGTH_RSA, scratch, recovered);
    return length == LENGTH_RSA
        && PIVSecurityProvider.arrayEqualsConstantTime(
            scratch, recovered, scratch, (short) 0, LENGTH_RSA);
  }
  // #endif

  private boolean runSymmetric(byte[] scratch) {
    Util.arrayFillNonAtomic(scratch, (short) 0, (short) 64, (byte) 0);
    aesKey.setKey(scratch, (short) 0);
    short length =
        crypto.doAesEcbEncrypt(aesKey, scratch, (short) 0, (short) 16, scratch, (short) 16);
    if (length != PIVCrypto.LENGTH_BLOCK_AES
        || !PIVSecurityProvider.arrayEqualsConstantTime(
            scratch, (short) 16, AES_ENCRYPT_ZERO, (short) 0, (short) AES_ENCRYPT_ZERO.length))
      return false;

    // FIPS 140-3 IG 10.3.A Resolution 1 requires separate encryption and decryption CASTs.
    // CBC with an all-zero IV is used here so the test exercises the inverse cipher used by PIV SM.
    length =
        crypto.doAesCbcDecrypt(
            aesKey,
            scratch,
            (short) 48,
            PIVCrypto.LENGTH_BLOCK_AES,
            AES_DECRYPT_CIPHERTEXT,
            (short) 0,
            PIVCrypto.LENGTH_BLOCK_AES,
            scratch,
            (short) 32);
    if (length != PIVCrypto.LENGTH_BLOCK_AES
        || !PIVSecurityProvider.arrayEqualsConstantTime(
            scratch, (short) 32, AES_DECRYPT_PLAINTEXT, (short) 0, PIVCrypto.LENGTH_BLOCK_AES))
      return false;

    length = crypto.doAesCmac(aesKey, scratch, (short) 0, (short) 0, scratch, (short) 16);
    if (length != PIVCrypto.LENGTH_BLOCK_AES
        || !PIVSecurityProvider.arrayEqualsConstantTime(
            scratch, (short) 16, CMAC_EMPTY, (short) 0, (short) CMAC_EMPTY.length)) return false;

    scratch[0] = (byte) 'a';
    scratch[1] = (byte) 'b';
    scratch[2] = (byte) 'c';
    length = crypto.doSha256(scratch, (short) 0, (short) 3, scratch, (short) 16);
    if (length != (short) SHA256_ABC.length
        || !PIVSecurityProvider.arrayEqualsConstantTime(
            scratch, (short) 16, SHA256_ABC, (short) 0, (short) SHA256_ABC.length)) return false;

    // #if VCI_CS7
    // IG 10.3.A Resolution 2 requires SHA-384's own CAST when SHA-512 is not implemented.
    scratch[0] = (byte) 'a';
    scratch[1] = (byte) 'b';
    scratch[2] = (byte) 'c';
    length = crypto.doSha384(scratch, (short) 0, (short) 3, scratch, (short) 16);
    if (length != (short) SHA384_ABC.length
        || !PIVSecurityProvider.arrayEqualsConstantTime(
            scratch, (short) 16, SHA384_ABC, (short) 0, (short) SHA384_ABC.length)) return false;
    // #endif

    return true;
  }
}
