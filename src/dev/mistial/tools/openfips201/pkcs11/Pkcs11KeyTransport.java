/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

import com.sun.jna.NativeLong;
import dev.mistial.tools.openfips201.crypto.EcdhKeyTransport;
import java.util.Arrays;
import java.util.List;

/**
 * {@link EcdhKeyTransport} on a PKCS#11 token: ECDH with a token key, the X9.63 SHA-256 KDF and RFC
 * 3394 AES Key Wrap ({@code CKM_AES_KEY_WRAP}).
 *
 * <p>KEK derivation, in order of preference ({@link KdfPath}):
 *
 * <ol>
 *   <li>{@link KdfPath#TOKEN_X963}: {@code CKM_ECDH1_DERIVE} with {@code CKD_SHA256_KDF} and the
 *       SharedInfo as shared data, into a sensitive, non-extractable AES-256 session key.
 *   <li>{@link KdfPath#TOKEN_CONCAT_SHA256}: {@code CKM_ECDH1_DERIVE} with {@code CKD_NULL} into a
 *       sensitive generic secret Z, {@code CKM_CONCATENATE_BASE_AND_DATA} with {@code 00000001 ||
 *       SharedInfo}, then {@code CKM_SHA256_KEY_DERIVATION} into the AES-256 KEK; used when the
 *       token rejects {@code CKD_SHA256_KDF} and lists both mechanisms.
 *   <li>{@link KdfPath#HOST_X963}: {@code CKD_NULL} into an extractable Z that is read, run through
 *       the KDF on the host, imported as a session KEK and wiped. Permitted only when the instance
 *       was created with {@code allowHostKdf} (development SoftHSM custody); otherwise the
 *       operation fails before Z is derived.
 * </ol>
 *
 * <p>Every ephemeral key, Z, intermediate secret and KEK is a session object destroyed before
 * return.
 */
public final class Pkcs11KeyTransport {
  /** How the KEK was derived. */
  public enum KdfPath {
    TOKEN_X963,
    TOKEN_CONCAT_SHA256,
    HOST_X963
  }

  /** An ECDH-transported key: the sender's ephemeral public point and the RFC 3394 output. */
  public static final class Wrapped {
    /** Uncompressed P-256 point, 65 bytes. */
    public final byte[] ephemeralPublicKey;
    /** RFC 3394 output: 8 bytes longer than the transported key. */
    public final byte[] wrappedKey;

    public final KdfPath kdfPath;

    Wrapped(byte[] ephemeralPublicKey, byte[] wrappedKey, KdfPath kdfPath) {
      this.ephemeralPublicKey = ephemeralPublicKey.clone();
      this.wrappedKey = wrappedKey.clone();
      this.kdfPath = kdfPath;
    }
  }

  private final Pkcs11Session session;
  private final boolean allowHostKdf;
  private KdfPath path;

  /**
   * @param allowHostKdf true only for development SoftHSM custody: permits {@link
   *     KdfPath#HOST_X963} when the token offers no on-token X9.63 KDF
   */
  public Pkcs11KeyTransport(Pkcs11Session session, boolean allowHostKdf) {
    this.session = session;
    this.allowHostKdf = allowHostKdf;
  }

  /** The KEK derivation used by the last operation, or {@code null} before the first. */
  public KdfPath kdfPath() {
    return path;
  }

  /**
   * Wraps the token AES key labelled {@code fpeKeyLabel} (32 bytes) to a SAM transport key: a fresh
   * session P-256 key {@code e} is generated on the token, {@code KEK = X9.63-SHA256(ECDH(e,
   * samTransportPub), "OPSAMKT1" || samTransportPub || ePub || ASCII(IIII))} and the key is wrapped
   * with RFC 3394. Returns {@code (ePub, wrapped40)} for PUT PARAMETERS v5 {@code wrappedFpeKey}.
   */
  public Wrapped wrapForSam(String fpeKeyLabel, byte[] samTransportPub, int iin) {
    EcdhKeyTransport.requireP256Point(samTransportPub);
    Pkcs11Token token = session.token();
    NativeLong key = oneAesKey(fpeKeyLabel);
    Pkcs11Token.EphemeralEcKey ephemeral = token.generateEphemeralEcP256();
    try {
      byte[] sharedInfo =
          EcdhKeyTransport.samTransportSharedInfo(samTransportPub, ephemeral.point, iin);
      return wrapWith(ephemeral.privateKey, ephemeral.point, samTransportPub, sharedInfo, key);
    } finally {
      token.destroyQuietly(ephemeral.privateKey);
      token.destroyQuietly(ephemeral.publicKey);
    }
  }

  /**
   * Wraps the token key labelled {@code keyLabel} to {@code recipientPub} under a fresh session
   * ephemeral key with the given {@code sharedInfo} (for example {@link
   * EcdhKeyTransport#backupSharedInfo(byte[], int)}).
   */
  public Wrapped wrapTo(String keyLabel, byte[] recipientPub, byte[] sharedInfo) {
    EcdhKeyTransport.requireP256Point(recipientPub);
    NativeLong key = oneAesKey(keyLabel);
    return wrapUnderEphemeral(recipientPub, sharedInfo, key);
  }

  /**
   * Wraps {@code secret} (a multiple of 8 bytes, at least 16) to {@code recipientPub}: it is
   * imported as a session generic secret, wrapped and destroyed. Serves the station handoff with
   * {@link EcdhKeyTransport#handoffSharedInfo(byte[], byte[])}. {@code secret} stays owned by the
   * caller.
   */
  public Wrapped wrapBytesTo(byte[] secret, byte[] recipientPub, byte[] sharedInfo) {
    if (secret == null || secret.length < 16 || secret.length % 8 != 0) {
      throw new IllegalArgumentException("RFC 3394 input must be a multiple of 8 bytes, >= 16");
    }
    EcdhKeyTransport.requireP256Point(recipientPub);
    Pkcs11Token token = session.token();
    NativeLong object = token.importSessionSecret(secret);
    try {
      return wrapUnderEphemeral(recipientPub, sharedInfo, object);
    } finally {
      token.destroyQuietly(object);
    }
  }

  /**
   * Recipient side of {@link #wrapBytesTo(byte[], byte[], byte[])}: derives the KEK from the token
   * ECDH key labelled {@code recipientKeyLabel} and {@code ephemeralPub}, unwraps into a session
   * object and returns its value, which the caller wipes. An integrity failure throws {@link
   * Pkcs11Exception}.
   */
  public byte[] unwrapBytesFrom(
      String recipientKeyLabel, byte[] ephemeralPub, byte[] wrapped, byte[] sharedInfo) {
    EcdhKeyTransport.requireP256Point(ephemeralPub);
    Pkcs11Token token = session.token();
    NativeLong kek = deriveKek(oneEcPrivateKey(recipientKeyLabel), ephemeralPub, sharedInfo);
    try {
      return token.unwrapToBytes(Pkcs11Constants.CKM_AES_KEY_WRAP, kek, wrapped);
    } finally {
      token.destroyQuietly(kek);
    }
  }

  /**
   * Fixed-key replay of {@link #wrapForSam(String, byte[], int)} with an imported ephemeral scalar
   * {@code d}; for the cross-implementation test vector only.
   */
  Wrapped wrapForSamWithEphemeral(
      byte[] d, byte[] ephemeralPub, String fpeKeyLabel, byte[] samTransportPub, int iin) {
    Pkcs11Token token = session.token();
    NativeLong privateKey = token.importEcP256DeriveKey(d);
    try {
      byte[] sharedInfo =
          EcdhKeyTransport.samTransportSharedInfo(samTransportPub, ephemeralPub, iin);
      return wrapWith(
          privateKey, ephemeralPub, samTransportPub, sharedInfo, oneAesKey(fpeKeyLabel));
    } finally {
      token.destroyQuietly(privateKey);
    }
  }

  private Wrapped wrapUnderEphemeral(byte[] recipientPub, byte[] sharedInfo, NativeLong key) {
    Pkcs11Token token = session.token();
    Pkcs11Token.EphemeralEcKey ephemeral = token.generateEphemeralEcP256();
    try {
      return wrapWith(ephemeral.privateKey, ephemeral.point, recipientPub, sharedInfo, key);
    } finally {
      token.destroyQuietly(ephemeral.privateKey);
      token.destroyQuietly(ephemeral.publicKey);
    }
  }

  private Wrapped wrapWith(
      NativeLong privateKey,
      byte[] ownPoint,
      byte[] recipientPub,
      byte[] sharedInfo,
      NativeLong key) {
    Pkcs11Token token = session.token();
    NativeLong kek = deriveKek(privateKey, recipientPub, sharedInfo);
    try {
      byte[] wrapped = token.wrapKey(Pkcs11Constants.CKM_AES_KEY_WRAP, kek, key);
      return new Wrapped(ownPoint, wrapped, path);
    } finally {
      token.destroyQuietly(kek);
    }
  }

  /** Derives the session AES-256 KEK by the first {@link KdfPath} the token supports. */
  private NativeLong deriveKek(NativeLong privateKey, byte[] peer, byte[] sharedInfo) {
    Pkcs11Token token = session.token();
    if (path == null || path == KdfPath.TOKEN_X963) {
      try {
        NativeLong kek =
            token.deriveEcdh(
                privateKey, peer, Pkcs11Constants.CKD_SHA256_KDF, sharedInfo, true, true);
        path = KdfPath.TOKEN_X963;
        return kek;
      } catch (Pkcs11Exception e) {
        if (path == KdfPath.TOKEN_X963 || !kdfUnsupported(e.rv())) {
          throw e;
        }
      }
      path =
          token.supportsMechanism(Pkcs11Constants.CKM_CONCATENATE_BASE_AND_DATA)
                  && token.supportsMechanism(Pkcs11Constants.CKM_SHA256_KEY_DERIVATION)
              ? KdfPath.TOKEN_CONCAT_SHA256
              : KdfPath.HOST_X963;
    }
    if (path == KdfPath.TOKEN_CONCAT_SHA256) {
      return deriveConcatSha256(privateKey, peer, sharedInfo);
    }
    return deriveOnHost(privateKey, peer, sharedInfo);
  }

  private NativeLong deriveConcatSha256(NativeLong privateKey, byte[] peer, byte[] sharedInfo) {
    Pkcs11Token token = session.token();
    byte[] suffix = new byte[4 + sharedInfo.length];
    suffix[3] = 1;
    System.arraycopy(sharedInfo, 0, suffix, 4, sharedInfo.length);
    NativeLong z = null;
    NativeLong input = null;
    try {
      z = token.deriveEcdh(privateKey, peer, Pkcs11Constants.CKD_NULL, null, false, true);
      input =
          token.deriveConcatenateBaseAndData(z, suffix, EcdhKeyTransport.Z_LENGTH + suffix.length);
      return token.deriveSha256AesKek(input);
    } finally {
      token.destroyQuietly(input);
      token.destroyQuietly(z);
    }
  }

  private NativeLong deriveOnHost(NativeLong privateKey, byte[] peer, byte[] sharedInfo) {
    if (!allowHostKdf) {
      throw new IllegalStateException(
          "PKCS#11 token offers neither CKD_SHA256_KDF nor CONCATENATE_BASE_AND_DATA +"
              + " SHA256_KEY_DERIVATION; host-side KDF is refused outside --dev-softhsm custody");
    }
    Pkcs11Token token = session.token();
    NativeLong zObject =
        token.deriveEcdh(privateKey, peer, Pkcs11Constants.CKD_NULL, null, false, false);
    byte[] z = null;
    byte[] kek = null;
    try {
      z = token.extractValue(zObject);
      if (z.length != EcdhKeyTransport.Z_LENGTH) {
        throw new IllegalStateException("ECDH returned " + z.length + " bytes");
      }
      kek = EcdhKeyTransport.x963Sha256(z, sharedInfo);
      return token.importSessionAesKek(kek);
    } finally {
      token.destroyQuietly(zObject);
      if (z != null) {
        Arrays.fill(z, (byte) 0);
      }
      if (kek != null) {
        Arrays.fill(kek, (byte) 0);
      }
    }
  }

  private NativeLong oneAesKey(String label) {
    List<Pkcs11Token.KeyHandle> keys = session.token().findAesKeys(label);
    if (keys.size() != 1) {
      throw new IllegalArgumentException(
          "PKCS#11 token must hold exactly one AES key labelled "
              + label
              + "; found "
              + keys.size());
    }
    return keys.get(0).handle;
  }

  private NativeLong oneEcPrivateKey(String label) {
    List<Pkcs11Token.KeyHandle> keys = session.token().findEcPrivateKeys(label);
    if (keys.size() != 1) {
      throw new IllegalArgumentException(
          "PKCS#11 token must hold exactly one EC key labelled "
              + label
              + "; found "
              + keys.size());
    }
    return keys.get(0).handle;
  }

  private static boolean kdfUnsupported(long rv) {
    return rv == Pkcs11Constants.CKR_MECHANISM_PARAM_INVALID
        || rv == Pkcs11Constants.CKR_ARGUMENTS_BAD
        || rv == Pkcs11Constants.CKR_MECHANISM_INVALID
        || rv == Pkcs11Constants.CKR_FUNCTION_NOT_SUPPORTED
        || rv == Pkcs11Constants.CKR_TEMPLATE_INCONSISTENT;
  }
}
