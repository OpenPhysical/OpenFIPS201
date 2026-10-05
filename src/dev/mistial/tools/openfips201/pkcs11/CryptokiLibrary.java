/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

import com.sun.jna.Library;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;

interface CryptokiLibrary extends Library {
  NativeLong C_Initialize(Pointer initArgs);

  NativeLong C_Finalize(Pointer reserved);

  /**
   * @param label exactly 32 bytes, blank padded, not NUL terminated (PKCS#11 v2.40 section 5.5)
   */
  NativeLong C_InitToken(NativeLong slotId, byte[] soPin, NativeLong soPinLength, byte[] label);

  NativeLong C_InitPIN(NativeLong session, byte[] pin, NativeLong pinLength);

  NativeLong C_SetPIN(
      NativeLong session,
      byte[] oldPin,
      NativeLong oldPinLength,
      byte[] newPin,
      NativeLong newPinLength);

  NativeLong C_GetSessionInfo(NativeLong session, Pkcs11Structs.SessionInfo info);

  NativeLong C_CloseAllSessions(NativeLong slotId);

  NativeLong C_DestroyObject(NativeLong session, NativeLong object);

  NativeLong C_GetSlotList(byte tokenPresent, NativeLong[] slotList, NativeLongByReference count);

  NativeLong C_GetTokenInfo(NativeLong slotId, Pkcs11Structs.TokenInfo info);

  NativeLong C_GetMechanismInfo(
      NativeLong slotId, NativeLong type, Pkcs11Structs.MechanismInfo info);

  NativeLong C_OpenSession(
      NativeLong slotId,
      NativeLong flags,
      Pointer application,
      Pointer notify,
      NativeLongByReference session);

  NativeLong C_CloseSession(NativeLong session);

  NativeLong C_Login(NativeLong session, NativeLong userType, byte[] pin, NativeLong pinLength);

  NativeLong C_Logout(NativeLong session);

  NativeLong C_FindObjectsInit(NativeLong session, Pointer template, NativeLong attributeCount);

  NativeLong C_FindObjects(
      NativeLong session,
      NativeLong[] objects,
      NativeLong maxObjectCount,
      NativeLongByReference objectCount);

  NativeLong C_FindObjectsFinal(NativeLong session);

  NativeLong C_GetAttributeValue(
      NativeLong session, NativeLong object, Pointer template, NativeLong attributeCount);

  NativeLong C_CreateObject(
      NativeLong session,
      Pointer template,
      NativeLong attributeCount,
      NativeLongByReference object);

  NativeLong C_GenerateKey(
      NativeLong session,
      Pkcs11Structs.Mechanism mechanism,
      Pointer template,
      NativeLong attributeCount,
      NativeLongByReference key);

  NativeLong C_GenerateKeyPair(
      NativeLong session,
      Pkcs11Structs.Mechanism mechanism,
      Pointer publicKeyTemplate,
      NativeLong publicKeyAttributeCount,
      Pointer privateKeyTemplate,
      NativeLong privateKeyAttributeCount,
      NativeLongByReference publicKey,
      NativeLongByReference privateKey);

  NativeLong C_SignInit(NativeLong session, Pkcs11Structs.Mechanism mechanism, NativeLong key);

  NativeLong C_Sign(
      NativeLong session,
      byte[] data,
      NativeLong dataLength,
      byte[] signature,
      NativeLongByReference signatureLength);

  NativeLong C_GetMechanismList(
      NativeLong slotId, NativeLong[] mechanismList, NativeLongByReference count);

  NativeLong C_SetAttributeValue(
      NativeLong session, NativeLong object, Pointer template, NativeLong attributeCount);

  NativeLong C_EncryptInit(NativeLong session, Pkcs11Structs.Mechanism mechanism, NativeLong key);

  NativeLong C_Encrypt(
      NativeLong session,
      byte[] data,
      NativeLong dataLength,
      byte[] encrypted,
      NativeLongByReference encryptedLength);

  NativeLong C_DeriveKey(
      NativeLong session,
      Pkcs11Structs.Mechanism mechanism,
      NativeLong baseKey,
      Pointer template,
      NativeLong attributeCount,
      NativeLongByReference key);

  NativeLong C_WrapKey(
      NativeLong session,
      Pkcs11Structs.Mechanism mechanism,
      NativeLong wrappingKey,
      NativeLong key,
      byte[] wrappedKey,
      NativeLongByReference wrappedKeyLength);

  NativeLong C_UnwrapKey(
      NativeLong session,
      Pkcs11Structs.Mechanism mechanism,
      NativeLong unwrappingKey,
      byte[] wrappedKey,
      NativeLong wrappedKeyLength,
      Pointer template,
      NativeLong attributeCount,
      NativeLongByReference key);
}
