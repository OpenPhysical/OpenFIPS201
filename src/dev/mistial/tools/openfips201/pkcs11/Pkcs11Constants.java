/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

final class Pkcs11Constants {
  private Pkcs11Constants() {}

  static final long CKR_OK = 0x00000000L;
  static final long CKR_PIN_INCORRECT = 0x000000A0L;
  static final long CKR_SESSION_HANDLE_INVALID = 0x000000B3L;
  static final long CKR_USER_ALREADY_LOGGED_IN = 0x00000100L;
  static final long CKR_USER_NOT_LOGGED_IN = 0x00000101L;
  static final long CKR_CRYPTOKI_NOT_INITIALIZED = 0x00000190L;
  static final long CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191L;

  static final long CKF_TOKEN_PRESENT = 0x00000001L;
  static final long CKF_SERIAL_SESSION = 0x00000004L;
  static final long CKF_RW_SESSION = 0x00000002L;
  static final long CKF_SIGN = 0x00000800L;

  /** CK_TOKEN_INFO flags (PKCS#11 v2.40 section 3.2). */
  static final long CKF_USER_PIN_INITIALIZED = 0x00000008L;

  static final long CKF_TOKEN_INITIALIZED = 0x00000400L;

  static final long CKU_SO = 0L;
  static final long CKU_USER = 1L;

  /** Length of the blank-padded CK_TOKEN_INFO.label and C_InitToken pLabel fields. */
  static final int TOKEN_LABEL_LENGTH = 32;

  static final long CKO_CERTIFICATE = 0x00000001L;
  static final long CKO_PUBLIC_KEY = 0x00000002L;
  static final long CKO_PRIVATE_KEY = 0x00000003L;
  static final long CKO_SECRET_KEY = 0x00000004L;

  static final long CKC_X_509 = 0x00000000L;

  static final long CKK_EC = 0x00000003L;
  static final long CKK_AES = 0x0000001FL;

  static final long CKA_CLASS = 0x00000000L;
  static final long CKA_LABEL = 0x00000003L;
  static final long CKA_APPLICATION = 0x00000010L;
  static final long CKA_VALUE = 0x00000011L;
  static final long CKA_CERTIFICATE_TYPE = 0x00000080L;
  static final long CKA_ISSUER = 0x00000081L;
  static final long CKA_SERIAL_NUMBER = 0x00000082L;
  static final long CKA_ID = 0x00000102L;
  static final long CKA_SUBJECT = 0x00000101L;
  static final long CKA_TOKEN = 0x00000001L;
  static final long CKA_PRIVATE = 0x00000002L;
  static final long CKA_SENSITIVE = 0x00000103L;
  static final long CKA_ENCRYPT = 0x00000104L;
  static final long CKA_DECRYPT = 0x00000105L;
  static final long CKA_SIGN = 0x00000108L;
  static final long CKA_VERIFY = 0x0000010AL;
  static final long CKA_DERIVE = 0x0000010CL;
  static final long CKA_EXTRACTABLE = 0x00000162L;
  static final long CKA_EC_PARAMS = 0x00000180L;
  static final long CKA_EC_POINT = 0x00000181L;
  static final long CKA_KEY_TYPE = 0x00000100L;
  static final long CKA_VALUE_LEN = 0x00000161L;

  static final long CKM_ECDSA = 0x00001041L;
  static final long CKM_AES_CMAC = 0x0000108AL;
  static final long CKM_EC_KEY_PAIR_GEN = 0x00001040L;
  static final long CKM_AES_KEY_GEN = 0x00001080L;

  static final long CKR_ARGUMENTS_BAD = 0x00000007L;
  static final long CKR_ATTRIBUTE_READ_ONLY = 0x00000010L;
  static final long CKR_FUNCTION_NOT_SUPPORTED = 0x00000054L;
  static final long CKR_MECHANISM_INVALID = 0x00000070L;
  static final long CKR_MECHANISM_PARAM_INVALID = 0x00000071L;
  static final long CKR_TEMPLATE_INCONSISTENT = 0x000000D1L;
  static final long CKR_BUFFER_TOO_SMALL = 0x00000150L;

  static final long CKF_DERIVE = 0x00080000L;
  static final long CKF_WRAP = 0x00020000L;

  static final long CKO_DATA = 0x00000000L;

  static final long CKK_GENERIC_SECRET = 0x00000010L;

  static final long CKA_OBJECT_ID = 0x00000012L;
  static final long CKA_WRAP = 0x00000106L;
  static final long CKA_UNWRAP = 0x00000107L;
  static final long CKA_MODIFIABLE = 0x00000170L;

  static final long CKM_AES_ECB = 0x00001081L;
  static final long CKM_AES_KEY_WRAP = 0x00002109L;
  static final long CKM_ECDH1_DERIVE = 0x00001050L;
  static final long CKM_CONCATENATE_BASE_AND_DATA = 0x00000362L;
  static final long CKM_SHA256_KEY_DERIVATION = 0x00000393L;

  /** CK_EC_KDF_TYPE (PKCS#11 v2.40 section 2.3.10). */
  static final long CKD_NULL = 0x00000001L;

  /** ANSI X9.63 KDF with SHA-256: {@code SHA-256(Z || counter || sharedData)}, counter from 1. */
  static final long CKD_SHA256_KDF = 0x00000006L;
}
