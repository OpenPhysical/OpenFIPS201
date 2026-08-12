/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;
import dev.mistial.tools.openfips201.common.HexUtil;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

final class Pkcs11Token implements AutoCloseable {
  private final CryptokiLibrary cryptoki;
  private final NativeLong slot;
  private final NativeLong session;
  private boolean closed;

  private Pkcs11Token(CryptokiLibrary cryptoki, NativeLong slot, NativeLong session) {
    this.cryptoki = cryptoki;
    this.slot = slot;
    this.session = session;
  }

  static Pkcs11Token open(Pkcs11Config config) {
    if (config.softhsmConfig != null && !config.softhsmConfig.isEmpty()) {
      setNativeEnvironment("SOFTHSM2_CONF", config.softhsmConfig);
    }
    CryptokiLibrary library = Native.load(config.module, CryptokiLibrary.class);
    long init = rv(library.C_Initialize(null));
    if (init != Pkcs11Constants.CKR_OK
        && init != Pkcs11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
      throw new Pkcs11Exception("C_Initialize", init);
    }
    return open(library, config);
  }

  static Pkcs11Token open(CryptokiLibrary library, Pkcs11Config config) {
    NativeLong slot = selectSlot(library, config);
    NativeLongByReference sessionRef = new NativeLongByReference();
    check(
        "C_OpenSession",
        library.C_OpenSession(
            slot,
            new NativeLong(Pkcs11Constants.CKF_SERIAL_SESSION | Pkcs11Constants.CKF_RW_SESSION),
            null,
            null,
            sessionRef));
    NativeLong session = sessionRef.getValue();
    char[] pinChars = config.readPin();
    byte[] pin = new String(pinChars).getBytes(StandardCharsets.UTF_8);
    Arrays.fill(pinChars, '\0');
    try {
      long login =
          rv(
              library.C_Login(
                  session,
                  new NativeLong(Pkcs11Constants.CKU_USER),
                  pin,
                  new NativeLong(pin.length)));
      if (login != Pkcs11Constants.CKR_OK && login != Pkcs11Constants.CKR_USER_ALREADY_LOGGED_IN) {
        throw new Pkcs11Exception("C_Login", login);
      }
      return new Pkcs11Token(library, slot, session);
    } finally {
      Arrays.fill(pin, (byte) 0);
    }
  }

  KeyHandle findPrivateKey(Pkcs11Config config) {
    KeyHandle handle =
        findOne(
            "private key",
            attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_PRIVATE_KEY),
            attribute(Pkcs11Constants.CKA_KEY_TYPE, Pkcs11Constants.CKK_EC),
            optionalLabel(config.keyAlias),
            optionalId(config.keyId));
    byte[] id = getAttribute(handle.handle, Pkcs11Constants.CKA_ID);
    return new KeyHandle(handle.handle, id, config.keyAlias);
  }

  KeyHandle findSecretAesKey(String label, String id) {
    return findOne(
        "AES secret key",
        attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_SECRET_KEY),
        attribute(Pkcs11Constants.CKA_KEY_TYPE, Pkcs11Constants.CKK_AES),
        optionalLabel(label),
        optionalId(id));
  }

  byte[] findCertificateValue(KeyHandle key, String label) {
    List<AttributeValue> attributes = new ArrayList<AttributeValue>();
    attributes.add(attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_CERTIFICATE));
    if (key.id != null && key.id.length > 0) {
      attributes.add(attribute(Pkcs11Constants.CKA_ID, key.id));
    } else if (label != null && !label.isEmpty()) {
      attributes.add(attribute(Pkcs11Constants.CKA_LABEL, label.getBytes(StandardCharsets.UTF_8)));
    } else {
      throw new IllegalArgumentException(
          "PKCS#11 signing key needs CKA_ID or label to find certificate");
    }
    KeyHandle certificate = findOne("certificate", attributes.toArray(new AttributeValue[0]));
    return getAttribute(certificate.handle, Pkcs11Constants.CKA_VALUE);
  }

  KeyHandle generateEcP256KeyPair(String label, byte[] id) {
    Pkcs11Structs.Mechanism mechanism =
        new Pkcs11Structs.Mechanism(Pkcs11Constants.CKM_EC_KEY_PAIR_GEN);
    mechanism.write();
    byte[] ecParams =
        new byte[] {0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x03, 0x01, 0x07};
    Pkcs11Structs.Attribute[] publicTemplate =
        writeTemplate(
            attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_PUBLIC_KEY),
            attribute(Pkcs11Constants.CKA_KEY_TYPE, Pkcs11Constants.CKK_EC),
            attribute(Pkcs11Constants.CKA_TOKEN, true),
            attribute(Pkcs11Constants.CKA_VERIFY, true),
            attribute(Pkcs11Constants.CKA_LABEL, label.getBytes(StandardCharsets.UTF_8)),
            attribute(Pkcs11Constants.CKA_ID, id),
            attribute(Pkcs11Constants.CKA_EC_PARAMS, ecParams));
    Pkcs11Structs.Attribute[] privateTemplate =
        writeTemplate(
            attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_PRIVATE_KEY),
            attribute(Pkcs11Constants.CKA_KEY_TYPE, Pkcs11Constants.CKK_EC),
            attribute(Pkcs11Constants.CKA_TOKEN, true),
            attribute(Pkcs11Constants.CKA_PRIVATE, true),
            attribute(Pkcs11Constants.CKA_SENSITIVE, true),
            attribute(Pkcs11Constants.CKA_EXTRACTABLE, false),
            attribute(Pkcs11Constants.CKA_SIGN, true),
            attribute(Pkcs11Constants.CKA_LABEL, label.getBytes(StandardCharsets.UTF_8)),
            attribute(Pkcs11Constants.CKA_ID, id));
    NativeLongByReference publicKey = new NativeLongByReference();
    NativeLongByReference privateKey = new NativeLongByReference();
    check(
        "C_GenerateKeyPair",
        cryptoki.C_GenerateKeyPair(
            session,
            mechanism,
            publicTemplate[0].getPointer(),
            new NativeLong(publicTemplate.length),
            privateTemplate[0].getPointer(),
            new NativeLong(privateTemplate.length),
            publicKey,
            privateKey));
    return new KeyHandle(privateKey.getValue(), id, label);
  }

  KeyHandle generateAesKey(String label, byte[] id, int bytes) {
    Pkcs11Structs.Mechanism mechanism =
        new Pkcs11Structs.Mechanism(Pkcs11Constants.CKM_AES_KEY_GEN);
    mechanism.write();
    Pkcs11Structs.Attribute[] template =
        writeTemplate(
            attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_SECRET_KEY),
            attribute(Pkcs11Constants.CKA_KEY_TYPE, Pkcs11Constants.CKK_AES),
            attribute(Pkcs11Constants.CKA_TOKEN, true),
            attribute(Pkcs11Constants.CKA_PRIVATE, true),
            attribute(Pkcs11Constants.CKA_SENSITIVE, true),
            attribute(Pkcs11Constants.CKA_EXTRACTABLE, false),
            attribute(Pkcs11Constants.CKA_SIGN, true),
            attribute(Pkcs11Constants.CKA_VALUE_LEN, bytes),
            attribute(Pkcs11Constants.CKA_LABEL, label.getBytes(StandardCharsets.UTF_8)),
            attribute(Pkcs11Constants.CKA_ID, id));
    NativeLongByReference key = new NativeLongByReference();
    check(
        "C_GenerateKey",
        cryptoki.C_GenerateKey(
            session, mechanism, template[0].getPointer(), new NativeLong(template.length), key));
    return new KeyHandle(key.getValue(), id, label);
  }

  void createCertificate(
      String label,
      byte[] id,
      byte[] subjectDer,
      byte[] issuerDer,
      byte[] serialDer,
      byte[] certificateDer) {
    Pkcs11Structs.Attribute[] template =
        writeTemplate(
            attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_CERTIFICATE),
            attribute(Pkcs11Constants.CKA_CERTIFICATE_TYPE, Pkcs11Constants.CKC_X_509),
            attribute(Pkcs11Constants.CKA_TOKEN, true),
            attribute(Pkcs11Constants.CKA_LABEL, label.getBytes(StandardCharsets.UTF_8)),
            attribute(Pkcs11Constants.CKA_ID, id),
            attribute(Pkcs11Constants.CKA_SUBJECT, subjectDer),
            attribute(Pkcs11Constants.CKA_ISSUER, issuerDer),
            attribute(Pkcs11Constants.CKA_SERIAL_NUMBER, serialDer),
            attribute(Pkcs11Constants.CKA_VALUE, certificateDer));
    NativeLongByReference object = new NativeLongByReference();
    check(
        "C_CreateObject(certificate)",
        cryptoki.C_CreateObject(
            session, template[0].getPointer(), new NativeLong(template.length), object));
  }

  PublicKey publicKey(String label, byte[] id) throws Exception {
    KeyHandle handle =
        findOne(
            "EC public key",
            attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_PUBLIC_KEY),
            attribute(Pkcs11Constants.CKA_KEY_TYPE, Pkcs11Constants.CKK_EC),
            optionalLabel(label),
            id == null ? null : attribute(Pkcs11Constants.CKA_ID, id));
    byte[] point = unwrapEcPoint(getAttribute(handle.handle, Pkcs11Constants.CKA_EC_POINT));
    int coordinateLength = (point.length - 1) / 2;
    java.math.BigInteger x =
        new java.math.BigInteger(1, Arrays.copyOfRange(point, 1, 1 + coordinateLength));
    java.math.BigInteger y =
        new java.math.BigInteger(1, Arrays.copyOfRange(point, 1 + coordinateLength, point.length));
    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
    parameters.init(new ECGenParameterSpec("secp256r1"));
    ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);
    return KeyFactory.getInstance("EC")
        .generatePublic(new ECPublicKeySpec(new ECPoint(x, y), spec));
  }

  byte[] sign(long mechanism, KeyHandle key, byte[] data) {
    requireSignMechanism(mechanism);
    Pkcs11Structs.Mechanism mech = new Pkcs11Structs.Mechanism(mechanism);
    mech.write();
    check("C_SignInit", cryptoki.C_SignInit(session, mech, key.handle));
    NativeLongByReference length = new NativeLongByReference();
    check(
        "C_Sign(length)",
        cryptoki.C_Sign(session, data, new NativeLong(data.length), null, length));
    byte[] signature = new byte[(int) length.getValue().longValue()];
    length.setValue(new NativeLong(signature.length));
    check("C_Sign", cryptoki.C_Sign(session, data, new NativeLong(data.length), signature, length));
    return Arrays.copyOf(signature, (int) length.getValue().longValue());
  }

  private void requireSignMechanism(long mechanism) {
    Pkcs11Structs.MechanismInfo info = new Pkcs11Structs.MechanismInfo();
    check("C_GetMechanismInfo", cryptoki.C_GetMechanismInfo(slot, new NativeLong(mechanism), info));
    info.read();
    if ((info.flags.longValue() & Pkcs11Constants.CKF_SIGN) == 0) {
      throw new IllegalArgumentException(
          "PKCS#11 mechanism does not support signing: " + String.format("0x%08X", mechanism));
    }
  }

  private KeyHandle findOne(String label, AttributeValue... requested) {
    AttributeValue[] attrs = compact(requested);
    Pkcs11Structs.Attribute[] template = writeTemplate(attrs);
    check(
        "C_FindObjectsInit",
        cryptoki.C_FindObjectsInit(
            session, template[0].getPointer(), new NativeLong(template.length)));
    try {
      NativeLong[] objects = new NativeLong[2];
      NativeLongByReference count = new NativeLongByReference();
      check("C_FindObjects", cryptoki.C_FindObjects(session, objects, new NativeLong(2), count));
      int found = (int) count.getValue().longValue();
      if (found == 0) {
        throw new IllegalArgumentException("PKCS#11 " + label + " was not found");
      }
      if (found > 1) {
        throw new IllegalArgumentException(
            "PKCS#11 " + label + " selection matched multiple objects");
      }
      return new KeyHandle(objects[0], null, null);
    } finally {
      check("C_FindObjectsFinal", cryptoki.C_FindObjectsFinal(session));
    }
  }

  private byte[] getAttribute(NativeLong object, long type) {
    Pkcs11Structs.Attribute[] first = writeTemplate(attribute(type, (byte[]) null));
    check(
        "C_GetAttributeValue(length)",
        cryptoki.C_GetAttributeValue(session, object, first[0].getPointer(), new NativeLong(1)));
    first[0].read();
    int length = (int) first[0].ulValueLen.longValue();
    if (length <= 0) {
      return new byte[0];
    }
    Memory memory = new Memory(length);
    Pkcs11Structs.Attribute[] second = writeTemplate(attribute(type, memory, length));
    check(
        "C_GetAttributeValue",
        cryptoki.C_GetAttributeValue(session, object, second[0].getPointer(), new NativeLong(1)));
    return memory.getByteArray(0, length);
  }

  @Override
  public void close() {
    if (closed) {
      return;
    }
    closed = true;
    cryptoki.C_Logout(session);
    cryptoki.C_CloseSession(session);
  }

  private static NativeLong selectSlot(CryptokiLibrary library, Pkcs11Config config) {
    if (config.slot != null) {
      return new NativeLong(config.slot.intValue());
    }
    NativeLongByReference count = new NativeLongByReference();
    check("C_GetSlotList(count)", library.C_GetSlotList((byte) 1, null, count));
    int slots = (int) count.getValue().longValue();
    NativeLong[] slotList = new NativeLong[slots];
    check("C_GetSlotList", library.C_GetSlotList((byte) 1, slotList, count));
    if (slots == 0) {
      throw new IllegalArgumentException("PKCS#11 module has no token-present slots");
    }
    if (config.tokenLabel == null || config.tokenLabel.isEmpty()) {
      if (slots > 1) {
        throw new IllegalArgumentException("PKCS#11 token label or slot is required");
      }
      return slotList[0];
    }
    NativeLong selected = null;
    for (NativeLong candidate : slotList) {
      Pkcs11Structs.TokenInfo info = new Pkcs11Structs.TokenInfo();
      check("C_GetTokenInfo", library.C_GetTokenInfo(candidate, info));
      info.read();
      if (config.tokenLabel.equals(trim(info.label))) {
        if (selected != null) {
          throw new IllegalArgumentException("PKCS#11 token label matched multiple slots");
        }
        selected = candidate;
      }
    }
    if (selected == null) {
      throw new IllegalArgumentException("PKCS#11 token label was not found: " + config.tokenLabel);
    }
    return selected;
  }

  private static String trim(byte[] value) {
    int end = value.length;
    while (end > 0 && (value[end - 1] == 0 || value[end - 1] == ' ')) {
      end--;
    }
    return new String(value, 0, end, StandardCharsets.US_ASCII);
  }

  private static Pkcs11Structs.Attribute[] writeTemplate(AttributeValue... values) {
    Pkcs11Structs.Attribute seed = new Pkcs11Structs.Attribute();
    Pkcs11Structs.Attribute[] attrs = (Pkcs11Structs.Attribute[]) seed.toArray(values.length);
    for (int i = 0; i < values.length; i++) {
      attrs[i].type = new NativeLong(values[i].type);
      attrs[i].pValue = values[i].pointer;
      attrs[i].ulValueLen = new NativeLong(values[i].length);
      attrs[i].write();
    }
    return attrs;
  }

  private static AttributeValue[] compact(AttributeValue... attrs) {
    List<AttributeValue> values = new ArrayList<AttributeValue>();
    for (AttributeValue attr : attrs) {
      if (attr != null) {
        values.add(attr);
      }
    }
    return values.toArray(new AttributeValue[0]);
  }

  private static AttributeValue optionalLabel(String value) {
    if (value == null || value.isEmpty()) {
      return null;
    }
    return attribute(Pkcs11Constants.CKA_LABEL, value.getBytes(StandardCharsets.UTF_8));
  }

  private static AttributeValue optionalId(String value) {
    if (value == null || value.isEmpty()) {
      return null;
    }
    return attribute(Pkcs11Constants.CKA_ID, HexUtil.parse(value));
  }

  private static AttributeValue attribute(long type, long value) {
    Memory memory = new Memory(NativeLong.SIZE);
    memory.setNativeLong(0, new NativeLong(value));
    return new AttributeValue(type, memory, NativeLong.SIZE);
  }

  private static AttributeValue attribute(long type, boolean value) {
    Memory memory = new Memory(1);
    memory.setByte(0, (byte) (value ? 1 : 0));
    return new AttributeValue(type, memory, 1);
  }

  private static AttributeValue attribute(long type, byte[] value) {
    if (value == null) {
      return new AttributeValue(type, null, 0);
    }
    Memory memory = new Memory(value.length);
    memory.write(0, value, 0, value.length);
    return new AttributeValue(type, memory, value.length);
  }

  private static AttributeValue attribute(long type, Memory memory, int length) {
    return new AttributeValue(type, memory, length);
  }

  private static void check(String operation, NativeLong result) {
    long rv = rv(result);
    if (rv != Pkcs11Constants.CKR_OK) {
      throw new Pkcs11Exception(operation, rv);
    }
  }

  private static byte[] unwrapEcPoint(byte[] encoded) {
    if (encoded.length == 65 && encoded[0] == 0x04) {
      return encoded;
    }
    if (encoded.length >= 2 && encoded[0] == 0x04 && (encoded[1] & 0x80) == 0) {
      return Arrays.copyOfRange(encoded, 2, encoded.length);
    }
    if (encoded.length >= 3 && encoded[0] == 0x04 && encoded[1] == (byte) 0x81) {
      return Arrays.copyOfRange(encoded, 3, encoded.length);
    }
    throw new IllegalArgumentException("Unsupported PKCS#11 EC point encoding");
  }

  private static long rv(NativeLong result) {
    return result.longValue() & 0xFFFFFFFFL;
  }

  private static void setNativeEnvironment(String name, String value) {
    try {
      CLibrary libc = Native.load("c", CLibrary.class);
      libc.setenv(name, value, 1);
    } catch (UnsatisfiedLinkError e) {
      throw new IllegalStateException("Unable to set native environment for PKCS#11", e);
    }
  }

  private interface CLibrary extends Library {
    int setenv(String name, String value, int overwrite);
  }

  static final class KeyHandle {
    final NativeLong handle;
    final byte[] id;
    final String label;

    KeyHandle(NativeLong handle, byte[] id, String label) {
      this.handle = handle;
      this.id = id == null ? null : id.clone();
      this.label = label;
    }
  }

  private static final class AttributeValue {
    final long type;
    final Pointer pointer;
    final int length;

    AttributeValue(long type, Pointer pointer, int length) {
      this.type = type;
      this.pointer = pointer;
      this.length = length;
    }
  }
}
