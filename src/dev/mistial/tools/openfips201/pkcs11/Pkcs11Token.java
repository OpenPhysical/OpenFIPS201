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
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
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
    return open(load(config), config);
  }

  /**
   * Loads {@code config.module} and initializes Cryptoki. {@code SOFTHSM2_CONF} is exported to the
   * native environment first when {@code config.softhsmConfig} is set; a module reads it once, at
   * its first {@code C_Initialize} in the process.
   */
  static CryptokiLibrary load(Pkcs11Config config) {
    if (config.module == null || config.module.isEmpty()) {
      throw new IllegalArgumentException("PKCS#11 module is required");
    }
    if (config.softhsmConfig != null && !config.softhsmConfig.isEmpty()) {
      setNativeEnvironment("SOFTHSM2_CONF", config.softhsmConfig);
    }
    CryptokiLibrary library = Native.load(config.module, CryptokiLibrary.class);
    long init = rv(library.C_Initialize(null));
    if (init != Pkcs11Constants.CKR_OK
        && init != Pkcs11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
      throw new Pkcs11Exception("C_Initialize", init);
    }
    return library;
  }

  static Pkcs11Token open(CryptokiLibrary library, Pkcs11Config config) {
    NativeLong slot = selectSlot(library, config);
    NativeLong session = openRwSession(library, slot);
    // Every failure after C_OpenSession closes the session it opened.
    try {
      login(library, session, config);
      return new Pkcs11Token(library, slot, session);
    } catch (RuntimeException | Error e) {
      long close = rv(library.C_CloseSession(session));
      if (close != Pkcs11Constants.CKR_OK) {
        e.addSuppressed(new Pkcs11Exception("C_CloseSession", close));
      }
      throw e;
    }
  }

  /**
   * Logs in as CKU_USER. The PIN goes from {@code char[]} to UTF-8 bytes through a {@link
   * java.nio.charset.CharsetEncoder}, with no intermediate {@code String}; both arrays and the
   * encoder buffer are wiped before return.
   */
  private static void login(CryptokiLibrary library, NativeLong session, Pkcs11Config config) {
    char[] pinChars = config.readPin();
    byte[] pin = null;
    try {
      pin = encodeUtf8(pinChars);
      login(library, session, Pkcs11Constants.CKU_USER, pin);
    } finally {
      Arrays.fill(pinChars, '\0');
      if (pin != null) {
        Arrays.fill(pin, (byte) 0);
      }
    }
  }

  private static void login(
      CryptokiLibrary library, NativeLong session, long userType, byte[] pin) {
    long login =
        rv(library.C_Login(session, new NativeLong(userType), pin, new NativeLong(pin.length)));
    if (login != Pkcs11Constants.CKR_OK && login != Pkcs11Constants.CKR_USER_ALREADY_LOGGED_IN) {
      throw new Pkcs11Exception("C_Login", login);
    }
  }

  /**
   * Returns the one slot whose token has {@code CKF_TOKEN_INITIALIZED} set and whose label equals
   * {@code label}, or {@code null} when there is none.
   *
   * @throws IllegalArgumentException when more than one initialized token carries the label
   */
  static NativeLong findInitializedTokenSlot(CryptokiLibrary library, String label) {
    NativeLong selected = null;
    for (NativeLong candidate : tokenSlots(library)) {
      Pkcs11Structs.TokenInfo info = tokenInfo(library, candidate);
      if ((info.flags.longValue() & Pkcs11Constants.CKF_TOKEN_INITIALIZED) != 0
          && label.equals(trim(info.label))) {
        if (selected != null) {
          throw new IllegalArgumentException(
              "PKCS#11 token label matched multiple slots: " + label);
        }
        selected = candidate;
      }
    }
    return selected;
  }

  /**
   * Returns the first token-present slot whose token does not have {@code CKF_TOKEN_INITIALIZED}
   * set, or {@code null} when there is none.
   */
  static NativeLong findUninitializedTokenSlot(CryptokiLibrary library) {
    for (NativeLong candidate : tokenSlots(library)) {
      if ((tokenInfo(library, candidate).flags.longValue() & Pkcs11Constants.CKF_TOKEN_INITIALIZED)
          == 0) {
        return candidate;
      }
    }
    return null;
  }

  /** Returns {@code CK_TOKEN_INFO.flags} of the token in {@code slot}. */
  static long tokenFlags(CryptokiLibrary library, NativeLong slot) {
    return tokenInfo(library, slot).flags.longValue();
  }

  /**
   * Initializes the token in {@code slot}: {@code C_InitToken} with {@code soPin} and {@code
   * label}, then an RW session, SO login, {@code C_InitPIN(userPin)} and logout. The session is
   * closed on every path. Both PIN arrays remain owned by the caller, which wipes them.
   */
  static void initToken(
      CryptokiLibrary library, NativeLong slot, byte[] soPin, byte[] userPin, String label) {
    reinitializeToken(library, slot, soPin, label);
    NativeLong session = openRwSession(library, slot);
    try {
      login(library, session, Pkcs11Constants.CKU_SO, soPin);
      check("C_InitPIN", library.C_InitPIN(session, userPin, new NativeLong(userPin.length)));
      check("C_Logout", library.C_Logout(session));
    } finally {
      library.C_CloseSession(session);
    }
  }

  /**
   * Runs {@code C_InitToken} on {@code slot}. For an initialized token {@code soPin} must be its
   * current SO PIN; the token then loses every object and its user PIN. {@code soPin} remains owned
   * by the caller.
   */
  static void reinitializeToken(
      CryptokiLibrary library, NativeLong slot, byte[] soPin, String label) {
    check(
        "C_InitToken",
        library.C_InitToken(slot, soPin, new NativeLong(soPin.length), paddedLabel(label)));
  }

  /** Encodes {@code label} as the 32-byte blank-padded UTF-8 CK_UTF8CHAR label field. */
  static byte[] paddedLabel(String label) {
    byte[] encoded = label.getBytes(StandardCharsets.UTF_8);
    if (encoded.length == 0 || encoded.length > Pkcs11Constants.TOKEN_LABEL_LENGTH) {
      throw new IllegalArgumentException("PKCS#11 token label must be 1 to 32 UTF-8 bytes");
    }
    byte[] padded = new byte[Pkcs11Constants.TOKEN_LABEL_LENGTH];
    Arrays.fill(padded, (byte) ' ');
    System.arraycopy(encoded, 0, padded, 0, encoded.length);
    return padded;
  }

  private static NativeLong openRwSession(CryptokiLibrary library, NativeLong slot) {
    NativeLongByReference sessionRef = new NativeLongByReference();
    check(
        "C_OpenSession",
        library.C_OpenSession(
            slot,
            new NativeLong(Pkcs11Constants.CKF_SERIAL_SESSION | Pkcs11Constants.CKF_RW_SESSION),
            null,
            null,
            sessionRef));
    return sessionRef.getValue();
  }

  private static NativeLong[] tokenSlots(CryptokiLibrary library) {
    NativeLongByReference count = new NativeLongByReference();
    check("C_GetSlotList(count)", library.C_GetSlotList((byte) 1, null, count));
    NativeLong[] slotList = new NativeLong[(int) count.getValue().longValue()];
    if (slotList.length == 0) {
      return slotList;
    }
    check("C_GetSlotList", library.C_GetSlotList((byte) 1, slotList, count));
    return Arrays.copyOf(slotList, (int) count.getValue().longValue());
  }

  private static Pkcs11Structs.TokenInfo tokenInfo(CryptokiLibrary library, NativeLong slot) {
    Pkcs11Structs.TokenInfo info = new Pkcs11Structs.TokenInfo();
    check("C_GetTokenInfo", library.C_GetTokenInfo(slot, info));
    info.read();
    return info;
  }

  static byte[] encodeUtf8(char[] value) {
    ByteBuffer encoded;
    try {
      encoded =
          StandardCharsets.UTF_8
              .newEncoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .onUnmappableCharacter(CodingErrorAction.REPORT)
              .encode(CharBuffer.wrap(value));
    } catch (CharacterCodingException e) {
      throw new IllegalArgumentException("PKCS#11 PIN is not valid Unicode text");
    }
    byte[] out = new byte[encoded.remaining()];
    encoded.get(out);
    if (encoded.hasArray()) {
      Arrays.fill(encoded.array(), (byte) 0);
    }
    return out;
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

  /** Returns every EC private key labelled {@code label}, each with its CKA_ID. */
  List<KeyHandle> findEcPrivateKeys(String label) {
    return withIds(
        findAll(
            attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_PRIVATE_KEY),
            attribute(Pkcs11Constants.CKA_KEY_TYPE, Pkcs11Constants.CKK_EC),
            attribute(Pkcs11Constants.CKA_LABEL, label.getBytes(StandardCharsets.UTF_8))),
        label);
  }

  /** Returns every AES secret key labelled {@code label}, each with its CKA_ID. */
  List<KeyHandle> findAesKeys(String label) {
    return withIds(
        findAll(
            attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_SECRET_KEY),
            attribute(Pkcs11Constants.CKA_KEY_TYPE, Pkcs11Constants.CKK_AES),
            attribute(Pkcs11Constants.CKA_LABEL, label.getBytes(StandardCharsets.UTF_8))),
        label);
  }

  /** Returns every X.509 certificate object whose CKA_ID equals {@code id}. */
  List<NativeLong> findCertificates(byte[] id) {
    return findAll(
        attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_CERTIFICATE),
        attribute(Pkcs11Constants.CKA_ID, id));
  }

  /** Returns the CKA_VALUE of {@code object}. */
  byte[] value(NativeLong object) {
    return getAttribute(object, Pkcs11Constants.CKA_VALUE);
  }

  void destroyObject(NativeLong object) {
    check("C_DestroyObject", cryptoki.C_DestroyObject(session, object));
  }

  NativeLong slot() {
    return slot;
  }

  NativeLong sessionHandle() {
    return session;
  }

  CryptokiLibrary library() {
    return cryptoki;
  }

  private List<KeyHandle> withIds(List<NativeLong> handles, String label) {
    List<KeyHandle> keys = new ArrayList<KeyHandle>();
    for (NativeLong handle : handles) {
      keys.add(new KeyHandle(handle, getAttribute(handle, Pkcs11Constants.CKA_ID), label));
    }
    return keys;
  }

  KeyHandle generateEcP256KeyPair(String label, byte[] id) {
    return generateEcP256KeyPair(label, id, false);
  }

  /**
   * Generates a token-resident P-256 key pair. The private key is sensitive and non-extractable; it
   * may sign ({@code derive} false) or only derive ({@code derive} true, an ECDH key).
   */
  KeyHandle generateEcP256KeyPair(String label, byte[] id, boolean derive) {
    Pkcs11Structs.Mechanism mechanism =
        new Pkcs11Structs.Mechanism(Pkcs11Constants.CKM_EC_KEY_PAIR_GEN);
    mechanism.write();
    Pkcs11Structs.Attribute[] publicTemplate =
        writeTemplate(
            attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_PUBLIC_KEY),
            attribute(Pkcs11Constants.CKA_KEY_TYPE, Pkcs11Constants.CKK_EC),
            attribute(Pkcs11Constants.CKA_TOKEN, true),
            attribute(Pkcs11Constants.CKA_VERIFY, !derive),
            attribute(Pkcs11Constants.CKA_LABEL, label.getBytes(StandardCharsets.UTF_8)),
            attribute(Pkcs11Constants.CKA_ID, id),
            attribute(Pkcs11Constants.CKA_EC_PARAMS, P256_PARAMS.clone()));
    Pkcs11Structs.Attribute[] privateTemplate =
        writeTemplate(
            attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_PRIVATE_KEY),
            attribute(Pkcs11Constants.CKA_KEY_TYPE, Pkcs11Constants.CKK_EC),
            attribute(Pkcs11Constants.CKA_TOKEN, true),
            attribute(Pkcs11Constants.CKA_PRIVATE, true),
            attribute(Pkcs11Constants.CKA_SENSITIVE, true),
            attribute(Pkcs11Constants.CKA_EXTRACTABLE, false),
            attribute(Pkcs11Constants.CKA_SIGN, !derive),
            attribute(Pkcs11Constants.CKA_DERIVE, derive),
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

  /** Reports whether the slot lists {@code mechanism} ({@code C_GetMechanismList}). */
  boolean supportsMechanism(long mechanism) {
    NativeLongByReference count = new NativeLongByReference();
    check("C_GetMechanismList(count)", cryptoki.C_GetMechanismList(slot, null, count));
    NativeLong[] list = new NativeLong[(int) count.getValue().longValue()];
    if (list.length == 0) {
      return false;
    }
    check("C_GetMechanismList", cryptoki.C_GetMechanismList(slot, list, count));
    for (int i = 0; i < (int) count.getValue().longValue(); i++) {
      if ((list[i].longValue() & 0xFFFFFFFFL) == mechanism) {
        return true;
      }
    }
    return false;
  }

  /** Single-part {@code C_EncryptInit}/{@code C_Encrypt} with a parameterless mechanism. */
  byte[] encrypt(long mechanism, NativeLong key, byte[] data) {
    Pkcs11Structs.Mechanism mech = new Pkcs11Structs.Mechanism(mechanism);
    mech.write();
    check("C_EncryptInit", cryptoki.C_EncryptInit(session, mech, key));
    byte[] out = new byte[data.length + 16];
    NativeLongByReference length = new NativeLongByReference(new NativeLong(out.length));
    check("C_Encrypt", cryptoki.C_Encrypt(session, data, new NativeLong(data.length), out, length));
    int produced = (int) length.getValue().longValue();
    byte[] result = Arrays.copyOf(out, produced);
    Arrays.fill(out, (byte) 0);
    return result;
  }

  /**
   * Generates a token-resident AES key of {@code bytes} bytes: private, sensitive, {@code
   * CKA_EXTRACTABLE} true so that it can leave the token only wrapped, {@code CKA_ENCRYPT} true and
   * every other usage false.
   */
  KeyHandle generateWrappableAesKey(String label, byte[] id, int bytes) {
    Pkcs11Structs.Mechanism mechanism =
        new Pkcs11Structs.Mechanism(Pkcs11Constants.CKM_AES_KEY_GEN);
    mechanism.write();
    Pkcs11Structs.Attribute[] template = writeTemplate(wrappableAesTemplate(label, id, bytes));
    NativeLongByReference key = new NativeLongByReference();
    check(
        "C_GenerateKey",
        cryptoki.C_GenerateKey(
            session, mechanism, template[0].getPointer(), new NativeLong(template.length), key));
    return new KeyHandle(key.getValue(), id, label);
  }

  /**
   * Imports {@code value} as a token-resident AES key with the attributes of {@link
   * #generateWrappableAesKey(String, byte[], int)}. The native copy of the value is cleared after
   * {@code C_CreateObject}; {@code value} stays owned by the caller.
   */
  KeyHandle importWrappableAesKey(String label, byte[] id, byte[] value) {
    AttributeValue secret = attribute(Pkcs11Constants.CKA_VALUE, value);
    List<AttributeValue> attrs =
        new ArrayList<AttributeValue>(Arrays.asList(wrappableAesTemplate(label, id, value.length)));
    attrs.remove(attrs.size() - 1);
    attrs.add(secret);
    try {
      return new KeyHandle(createObject("AES key", attrs), id, label);
    } finally {
      clear(secret);
    }
  }

  private static AttributeValue[] wrappableAesTemplate(String label, byte[] id, int bytes) {
    return new AttributeValue[] {
      attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_SECRET_KEY),
      attribute(Pkcs11Constants.CKA_KEY_TYPE, Pkcs11Constants.CKK_AES),
      attribute(Pkcs11Constants.CKA_TOKEN, true),
      attribute(Pkcs11Constants.CKA_PRIVATE, true),
      attribute(Pkcs11Constants.CKA_SENSITIVE, true),
      attribute(Pkcs11Constants.CKA_EXTRACTABLE, true),
      attribute(Pkcs11Constants.CKA_ENCRYPT, true),
      attribute(Pkcs11Constants.CKA_DECRYPT, false),
      attribute(Pkcs11Constants.CKA_SIGN, false),
      attribute(Pkcs11Constants.CKA_WRAP, false),
      attribute(Pkcs11Constants.CKA_UNWRAP, false),
      attribute(Pkcs11Constants.CKA_DERIVE, false),
      attribute(Pkcs11Constants.CKA_LABEL, label.getBytes(StandardCharsets.UTF_8)),
      attribute(Pkcs11Constants.CKA_ID, id),
      // Last entry: replaced by CKA_VALUE on import.
      attribute(Pkcs11Constants.CKA_VALUE_LEN, bytes)
    };
  }

  /**
   * Generates a session (CKA_TOKEN false) P-256 key pair whose private key may only derive. Returns
   * the private key handle, the public key handle and the uncompressed public point.
   */
  EphemeralEcKey generateEphemeralEcP256() {
    Pkcs11Structs.Mechanism mechanism =
        new Pkcs11Structs.Mechanism(Pkcs11Constants.CKM_EC_KEY_PAIR_GEN);
    mechanism.write();
    Pkcs11Structs.Attribute[] publicTemplate =
        writeTemplate(
            attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_PUBLIC_KEY),
            attribute(Pkcs11Constants.CKA_KEY_TYPE, Pkcs11Constants.CKK_EC),
            attribute(Pkcs11Constants.CKA_TOKEN, false),
            attribute(Pkcs11Constants.CKA_EC_PARAMS, P256_PARAMS.clone()));
    Pkcs11Structs.Attribute[] privateTemplate =
        writeTemplate(
            attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_PRIVATE_KEY),
            attribute(Pkcs11Constants.CKA_KEY_TYPE, Pkcs11Constants.CKK_EC),
            attribute(Pkcs11Constants.CKA_TOKEN, false),
            attribute(Pkcs11Constants.CKA_PRIVATE, true),
            attribute(Pkcs11Constants.CKA_SENSITIVE, true),
            attribute(Pkcs11Constants.CKA_EXTRACTABLE, false),
            attribute(Pkcs11Constants.CKA_SIGN, false),
            attribute(Pkcs11Constants.CKA_DERIVE, true));
    NativeLongByReference publicKey = new NativeLongByReference();
    NativeLongByReference privateKey = new NativeLongByReference();
    check(
        "C_GenerateKeyPair(ephemeral)",
        cryptoki.C_GenerateKeyPair(
            session,
            mechanism,
            publicTemplate[0].getPointer(),
            new NativeLong(publicTemplate.length),
            privateTemplate[0].getPointer(),
            new NativeLong(privateTemplate.length),
            publicKey,
            privateKey));
    return new EphemeralEcKey(
        privateKey.getValue(), publicKey.getValue(), ecPoint(publicKey.getValue()));
  }

  /**
   * Imports a session P-256 private key with scalar {@code d} that may only derive. Used to replay
   * fixed-key test vectors through the token.
   */
  NativeLong importEcP256DeriveKey(byte[] d) {
    AttributeValue secret = attribute(Pkcs11Constants.CKA_VALUE, d);
    try {
      return createObject(
          "EC private key",
          Arrays.asList(
              attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_PRIVATE_KEY),
              attribute(Pkcs11Constants.CKA_KEY_TYPE, Pkcs11Constants.CKK_EC),
              attribute(Pkcs11Constants.CKA_TOKEN, false),
              attribute(Pkcs11Constants.CKA_PRIVATE, true),
              attribute(Pkcs11Constants.CKA_SENSITIVE, true),
              attribute(Pkcs11Constants.CKA_DERIVE, true),
              attribute(Pkcs11Constants.CKA_EC_PARAMS, P256_PARAMS.clone()),
              secret));
    } finally {
      clear(secret);
    }
  }

  /** Uncompressed point of the EC public key object {@code publicKey}. */
  byte[] ecPoint(NativeLong publicKey) {
    return unwrapEcPoint(getAttribute(publicKey, Pkcs11Constants.CKA_EC_POINT));
  }

  /** The labels of every AES secret key visible in the session (an unlabelled key yields ""). */
  List<String> aesKeyLabels() {
    List<String> labels = new ArrayList<String>();
    for (NativeLong key :
        findAll(
            attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_SECRET_KEY),
            attribute(Pkcs11Constants.CKA_KEY_TYPE, Pkcs11Constants.CKK_AES))) {
      labels.add(new String(getAttribute(key, Pkcs11Constants.CKA_LABEL), StandardCharsets.UTF_8));
    }
    return labels;
  }

  /** The uncompressed points of every EC public key visible in the session. */
  List<byte[]> ecPublicPoints() {
    List<byte[]> points = new ArrayList<byte[]>();
    for (NativeLong key :
        findAll(
            attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_PUBLIC_KEY),
            attribute(Pkcs11Constants.CKA_KEY_TYPE, Pkcs11Constants.CKK_EC))) {
      points.add(ecPoint(key));
    }
    return points;
  }

  /** Returns the EC public key objects labelled {@code label}. */
  List<NativeLong> findEcPublicKeys(String label) {
    return findAll(
        attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_PUBLIC_KEY),
        attribute(Pkcs11Constants.CKA_KEY_TYPE, Pkcs11Constants.CKK_EC),
        attribute(Pkcs11Constants.CKA_LABEL, label.getBytes(StandardCharsets.UTF_8)));
  }

  /**
   * {@code CKM_ECDH1_DERIVE} with {@code kdf} and {@code sharedData} into a session secret key.
   *
   * @param aesKek true: a 32-byte CKK_AES key, sensitive and non-extractable, that may only wrap
   *     and unwrap; false: a 32-byte CKK_GENERIC_SECRET whose sensitivity is {@code sensitive}
   */
  NativeLong deriveEcdh(
      NativeLong privateKey,
      byte[] peerPoint,
      long kdf,
      byte[] sharedData,
      boolean aesKek,
      boolean sensitive) {
    Memory publicData = new Memory(peerPoint.length);
    publicData.write(0, peerPoint, 0, peerPoint.length);
    Pkcs11Structs.EcdhDeriveParams params = new Pkcs11Structs.EcdhDeriveParams();
    params.kdf = new NativeLong(kdf);
    params.ulPublicDataLen = new NativeLong(peerPoint.length);
    params.pPublicData = publicData;
    if (sharedData == null || sharedData.length == 0) {
      params.ulSharedDataLen = new NativeLong(0);
      params.pSharedData = null;
    } else {
      Memory shared = new Memory(sharedData.length);
      shared.write(0, sharedData, 0, sharedData.length);
      params.ulSharedDataLen = new NativeLong(sharedData.length);
      params.pSharedData = shared;
    }
    Pkcs11Structs.Mechanism mechanism =
        new Pkcs11Structs.Mechanism(Pkcs11Constants.CKM_ECDH1_DERIVE, params);
    mechanism.write();
    return derive("C_DeriveKey(ECDH1)", mechanism, privateKey, secretTemplate(aesKek, sensitive));
  }

  /**
   * {@code CKM_CONCATENATE_BASE_AND_DATA}: a session generic secret holding {@code base || data},
   * sensitive.
   */
  NativeLong deriveConcatenateBaseAndData(NativeLong base, byte[] data, int resultLength) {
    Memory memory = new Memory(data.length);
    memory.write(0, data, 0, data.length);
    Pkcs11Structs.KeyDerivationStringData params = new Pkcs11Structs.KeyDerivationStringData();
    params.pData = memory;
    params.ulLen = new NativeLong(data.length);
    Pkcs11Structs.Mechanism mechanism =
        new Pkcs11Structs.Mechanism(Pkcs11Constants.CKM_CONCATENATE_BASE_AND_DATA, params);
    mechanism.write();
    return derive(
        "C_DeriveKey(CONCATENATE_BASE_AND_DATA)",
        mechanism,
        base,
        new AttributeValue[] {
          attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_SECRET_KEY),
          attribute(Pkcs11Constants.CKA_KEY_TYPE, Pkcs11Constants.CKK_GENERIC_SECRET),
          attribute(Pkcs11Constants.CKA_TOKEN, false),
          attribute(Pkcs11Constants.CKA_SENSITIVE, true),
          attribute(Pkcs11Constants.CKA_EXTRACTABLE, false),
          attribute(Pkcs11Constants.CKA_DERIVE, true),
          attribute(Pkcs11Constants.CKA_VALUE_LEN, resultLength)
        });
  }

  /** {@code CKM_SHA256_KEY_DERIVATION}: a session AES-256 KEK equal to SHA-256 of {@code base}. */
  NativeLong deriveSha256AesKek(NativeLong base) {
    Pkcs11Structs.Mechanism mechanism =
        new Pkcs11Structs.Mechanism(Pkcs11Constants.CKM_SHA256_KEY_DERIVATION);
    mechanism.write();
    return derive(
        "C_DeriveKey(SHA256_KEY_DERIVATION)", mechanism, base, secretTemplate(true, true));
  }

  /**
   * Imports {@code value} (32 bytes) as a session AES KEK, sensitive and non-extractable, that may
   * only wrap and unwrap. The native copy is cleared; {@code value} stays owned by the caller.
   */
  NativeLong importSessionAesKek(byte[] value) {
    AttributeValue secret = attribute(Pkcs11Constants.CKA_VALUE, value);
    try {
      List<AttributeValue> attrs =
          new ArrayList<AttributeValue>(Arrays.asList(secretTemplate(true, true)));
      attrs.remove(attrs.size() - 1);
      attrs.add(secret);
      return createObject("AES KEK", attrs);
    } finally {
      clear(secret);
    }
  }

  /**
   * Imports {@code value} as a session CKK_GENERIC_SECRET, extractable so that it can be wrapped.
   */
  NativeLong importSessionSecret(byte[] value) {
    AttributeValue secret = attribute(Pkcs11Constants.CKA_VALUE, value);
    try {
      return createObject(
          "generic secret",
          Arrays.asList(
              attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_SECRET_KEY),
              attribute(Pkcs11Constants.CKA_KEY_TYPE, Pkcs11Constants.CKK_GENERIC_SECRET),
              attribute(Pkcs11Constants.CKA_TOKEN, false),
              attribute(Pkcs11Constants.CKA_SENSITIVE, true),
              attribute(Pkcs11Constants.CKA_EXTRACTABLE, true),
              secret));
    } finally {
      clear(secret);
    }
  }

  /** {@code C_WrapKey} of {@code key} under {@code wrappingKey} with a parameterless mechanism. */
  byte[] wrapKey(long mechanism, NativeLong wrappingKey, NativeLong key) {
    Pkcs11Structs.Mechanism mech = new Pkcs11Structs.Mechanism(mechanism);
    mech.write();
    NativeLongByReference length = new NativeLongByReference();
    check("C_WrapKey(length)", cryptoki.C_WrapKey(session, mech, wrappingKey, key, null, length));
    byte[] wrapped = new byte[(int) length.getValue().longValue()];
    length.setValue(new NativeLong(wrapped.length));
    check("C_WrapKey", cryptoki.C_WrapKey(session, mech, wrappingKey, key, wrapped, length));
    return Arrays.copyOf(wrapped, (int) length.getValue().longValue());
  }

  /**
   * {@code C_UnwrapKey} into a session CKK_GENERIC_SECRET that is not sensitive, reads its value
   * and destroys it. The caller owns (and wipes) the returned array.
   */
  byte[] unwrapToBytes(long mechanism, NativeLong unwrappingKey, byte[] wrapped) {
    NativeLong key =
        unwrap(
            mechanism,
            unwrappingKey,
            wrapped,
            new AttributeValue[] {
              attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_SECRET_KEY),
              attribute(Pkcs11Constants.CKA_KEY_TYPE, Pkcs11Constants.CKK_GENERIC_SECRET),
              attribute(Pkcs11Constants.CKA_TOKEN, false),
              attribute(Pkcs11Constants.CKA_SENSITIVE, false),
              attribute(Pkcs11Constants.CKA_EXTRACTABLE, true)
            });
    try {
      return getAttribute(key, Pkcs11Constants.CKA_VALUE);
    } finally {
      destroyQuietly(key);
    }
  }

  /**
   * {@code C_UnwrapKey} into a token-resident AES key with the attributes of {@link
   * #generateWrappableAesKey(String, byte[], int)}.
   */
  KeyHandle unwrapWrappableAesKey(
      long mechanism, NativeLong unwrappingKey, byte[] wrapped, String label, byte[] id) {
    AttributeValue[] template = wrappableAesTemplate(label, id, 0);
    return new KeyHandle(
        unwrap(mechanism, unwrappingKey, wrapped, Arrays.copyOf(template, template.length - 1)),
        id,
        label);
  }

  /** Returns the CKA_VALUE of an extractable, non-sensitive object. */
  byte[] extractValue(NativeLong object) {
    return getAttribute(object, Pkcs11Constants.CKA_VALUE);
  }

  /** Returns the CKA_ID of {@code object}. */
  byte[] id(NativeLong object) {
    return getAttribute(object, Pkcs11Constants.CKA_ID);
  }

  /** Replaces the CKA_ID of {@code object}. */
  void setId(NativeLong object, byte[] id) {
    setAttribute(object, attribute(Pkcs11Constants.CKA_ID, id));
  }

  /**
   * Creates a token-resident, private, modifiable CKO_DATA object with {@code label}, {@code
   * application} and {@code value}.
   */
  NativeLong createData(String label, String application, byte[] value) {
    return createObject(
        "data object",
        Arrays.asList(
            attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_DATA),
            attribute(Pkcs11Constants.CKA_TOKEN, true),
            attribute(Pkcs11Constants.CKA_PRIVATE, true),
            attribute(Pkcs11Constants.CKA_MODIFIABLE, true),
            attribute(Pkcs11Constants.CKA_LABEL, label.getBytes(StandardCharsets.UTF_8)),
            attribute(
                Pkcs11Constants.CKA_APPLICATION, application.getBytes(StandardCharsets.UTF_8)),
            attribute(Pkcs11Constants.CKA_VALUE, value)));
  }

  /** Returns the CKO_DATA objects with {@code label} and {@code application}. */
  List<NativeLong> findData(String label, String application) {
    return findAll(
        attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_DATA),
        attribute(Pkcs11Constants.CKA_LABEL, label.getBytes(StandardCharsets.UTF_8)),
        attribute(Pkcs11Constants.CKA_APPLICATION, application.getBytes(StandardCharsets.UTF_8)));
  }

  /**
   * Replaces the CKA_VALUE of the CKO_DATA object {@code object} with {@code C_SetAttributeValue}.
   * A token that treats CKA_VALUE as read-only ({@code CKR_ATTRIBUTE_READ_ONLY}) gets a new object
   * with the same label and application first, then the old one is destroyed; an interruption
   * between the two leaves two objects, which {@link #findData(String, String)} callers refuse.
   */
  void updateData(NativeLong object, String label, String application, byte[] value) {
    try {
      setAttribute(object, attribute(Pkcs11Constants.CKA_VALUE, value));
    } catch (Pkcs11Exception e) {
      if (e.rv() != Pkcs11Constants.CKR_ATTRIBUTE_READ_ONLY) {
        throw e;
      }
      createData(label, application, value);
      destroyObject(object);
    }
  }

  /** Destroys {@code object}, ignoring failures; for cleanup of session objects. */
  void destroyQuietly(NativeLong object) {
    if (object != null) {
      cryptoki.C_DestroyObject(session, object);
    }
  }

  private NativeLong derive(
      String operation,
      Pkcs11Structs.Mechanism mechanism,
      NativeLong base,
      AttributeValue[] attributes) {
    Pkcs11Structs.Attribute[] template = writeTemplate(attributes);
    NativeLongByReference key = new NativeLongByReference();
    check(
        operation,
        cryptoki.C_DeriveKey(
            session,
            mechanism,
            base,
            template[0].getPointer(),
            new NativeLong(template.length),
            key));
    return key.getValue();
  }

  private NativeLong unwrap(
      long mechanism, NativeLong unwrappingKey, byte[] wrapped, AttributeValue[] attributes) {
    Pkcs11Structs.Mechanism mech = new Pkcs11Structs.Mechanism(mechanism);
    mech.write();
    Pkcs11Structs.Attribute[] template = writeTemplate(attributes);
    NativeLongByReference key = new NativeLongByReference();
    check(
        "C_UnwrapKey",
        cryptoki.C_UnwrapKey(
            session,
            mech,
            unwrappingKey,
            wrapped,
            new NativeLong(wrapped.length),
            template[0].getPointer(),
            new NativeLong(template.length),
            key));
    return key.getValue();
  }

  private NativeLong createObject(String what, List<AttributeValue> attributes) {
    Pkcs11Structs.Attribute[] template = writeTemplate(attributes.toArray(new AttributeValue[0]));
    NativeLongByReference object = new NativeLongByReference();
    check(
        "C_CreateObject(" + what + ")",
        cryptoki.C_CreateObject(
            session, template[0].getPointer(), new NativeLong(template.length), object));
    return object.getValue();
  }

  private void setAttribute(NativeLong object, AttributeValue value) {
    Pkcs11Structs.Attribute[] template = writeTemplate(value);
    check(
        "C_SetAttributeValue",
        cryptoki.C_SetAttributeValue(session, object, template[0].getPointer(), new NativeLong(1)));
  }

  /**
   * Session secret template; the last entry is CKA_VALUE_LEN (32), replaced by CKA_VALUE on import.
   */
  private static AttributeValue[] secretTemplate(boolean aesKek, boolean sensitive) {
    if (aesKek) {
      return new AttributeValue[] {
        attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_SECRET_KEY),
        attribute(Pkcs11Constants.CKA_KEY_TYPE, Pkcs11Constants.CKK_AES),
        attribute(Pkcs11Constants.CKA_TOKEN, false),
        attribute(Pkcs11Constants.CKA_SENSITIVE, true),
        attribute(Pkcs11Constants.CKA_EXTRACTABLE, false),
        attribute(Pkcs11Constants.CKA_ENCRYPT, false),
        attribute(Pkcs11Constants.CKA_DECRYPT, false),
        attribute(Pkcs11Constants.CKA_WRAP, true),
        attribute(Pkcs11Constants.CKA_UNWRAP, true),
        attribute(Pkcs11Constants.CKA_VALUE_LEN, 32)
      };
    }
    return new AttributeValue[] {
      attribute(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_SECRET_KEY),
      attribute(Pkcs11Constants.CKA_KEY_TYPE, Pkcs11Constants.CKK_GENERIC_SECRET),
      attribute(Pkcs11Constants.CKA_TOKEN, false),
      attribute(Pkcs11Constants.CKA_SENSITIVE, sensitive),
      attribute(Pkcs11Constants.CKA_EXTRACTABLE, !sensitive),
      attribute(Pkcs11Constants.CKA_DERIVE, true),
      attribute(Pkcs11Constants.CKA_VALUE_LEN, 32)
    };
  }

  private static void clear(AttributeValue value) {
    if (value.pointer instanceof Memory) {
      ((Memory) value.pointer).clear();
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

  private List<NativeLong> findAll(AttributeValue... requested) {
    Pkcs11Structs.Attribute[] template = writeTemplate(compact(requested));
    check(
        "C_FindObjectsInit",
        cryptoki.C_FindObjectsInit(
            session, template[0].getPointer(), new NativeLong(template.length)));
    List<NativeLong> found = new ArrayList<NativeLong>();
    try {
      NativeLong[] objects = new NativeLong[16];
      NativeLongByReference count = new NativeLongByReference();
      while (true) {
        check(
            "C_FindObjects",
            cryptoki.C_FindObjects(session, objects, new NativeLong(objects.length), count));
        int batch = (int) count.getValue().longValue();
        for (int i = 0; i < batch; i++) {
          found.add(objects[i]);
        }
        if (batch < objects.length) {
          return found;
        }
      }
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
    if (config.tokenLabel == null || config.tokenLabel.isEmpty()) {
      NativeLong[] slotList = tokenSlots(library);
      if (slotList.length == 0) {
        throw new IllegalArgumentException("PKCS#11 module has no token-present slots");
      }
      if (slotList.length > 1) {
        throw new IllegalArgumentException("PKCS#11 token label or slot is required");
      }
      return slotList[0];
    }
    NativeLong selected = findInitializedTokenSlot(library, config.tokenLabel);
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

  /** DER OID secp256r1 (1.2.840.10045.3.1.7), the CKA_EC_PARAMS of every P-256 key. */
  private static final byte[] P256_PARAMS = {
    0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x03, 0x01, 0x07
  };

  /** A session P-256 key pair from {@link #generateEphemeralEcP256()}. */
  static final class EphemeralEcKey {
    final NativeLong privateKey;
    final NativeLong publicKey;
    /** Uncompressed point {@code 04 || X || Y}, 65 bytes. */
    final byte[] point;

    EphemeralEcKey(NativeLong privateKey, NativeLong publicKey, byte[] point) {
      this.privateKey = privateKey;
      this.publicKey = publicKey;
      this.point = point;
    }
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
