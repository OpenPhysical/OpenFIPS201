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
  static final long CKR_USER_ALREADY_LOGGED_IN = 0x00000100L;
  static final long CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191L;

  static final long CKF_TOKEN_PRESENT = 0x00000001L;
  static final long CKF_SERIAL_SESSION = 0x00000004L;
  static final long CKF_RW_SESSION = 0x00000002L;
  static final long CKF_SIGN = 0x00000800L;

  static final long CKU_USER = 1L;

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
}
