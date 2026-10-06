/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

import java.util.Objects;

/**
 * One logged-in PKCS#11 session, held for the duration of one command.
 *
 * <p>Contract: {@link #open(Pkcs11Config)} selects the token, opens one RW session and logs in as
 * CKU_USER with the PIN named by the config, which is read exactly once. Every signing key, AES
 * CMAC and key-management operation issued through this object uses that session; nothing opens a
 * second session or logs in again. {@link #close()} logs out and closes the session; it is
 * idempotent, and every operation after it fails. Use it with try-with-resources.
 */
public final class Pkcs11Session implements AutoCloseable {
  private final Pkcs11Config config;
  private final Pkcs11Token token;
  private boolean closed;

  private Pkcs11Session(Pkcs11Config config, Pkcs11Token token) {
    this.config = config;
    this.token = token;
  }

  public static Pkcs11Session open(Pkcs11Config config) {
    Pkcs11Config copy = config.copy();
    return new Pkcs11Session(copy, Pkcs11Token.open(copy));
  }

  static Pkcs11Session open(CryptokiLibrary library, Pkcs11Config config) {
    Pkcs11Config copy = config.copy();
    return new Pkcs11Session(copy, Pkcs11Token.open(library, copy));
  }

  /** Returns a copy of the token selection and PIN source this session was opened with. */
  public Pkcs11Config config() {
    return config.copy();
  }

  /**
   * Returns the EC signing key selected by {@code selection.keyAlias}/{@code selection.keyId},
   * bound to this session, together with the certificate stored on the token for it.
   */
  public Pkcs11SigningKey signingKey(Pkcs11Config selection) throws Exception {
    requireSameToken(selection);
    return new Pkcs11SigningKey(this, selection);
  }

  /** AES-CMAC of {@code message} under the AES key selected by {@code label}/{@code id}. */
  public byte[] aesCmac(String label, String id, byte[] message) {
    Pkcs11Token selected = token();
    return selected.sign(
        Pkcs11Constants.CKM_AES_CMAC, selected.findSecretAesKey(label, id), message);
  }

  /**
   * Returns an {@link Pkcs11AesBlock} over the one AES key labelled {@code label}.
   *
   * @throws IllegalArgumentException when no key or more than one key carries the label
   */
  public Pkcs11AesBlock aesBlock(String label) {
    java.util.List<Pkcs11Token.KeyHandle> keys = token().findAesKeys(label);
    if (keys.size() != 1) {
      throw new IllegalArgumentException(
          "PKCS#11 token must hold exactly one AES key labelled "
              + label
              + "; found "
              + keys.size());
    }
    return new Pkcs11AesBlock(this, keys.get(0).handle, label);
  }

  /**
   * Fails unless {@code selection} names the same module and token as this session. A selection
   * field that is unset does not constrain the match.
   */
  public void requireSameToken(Pkcs11Config selection) {
    if (!empty(selection.module) && !selection.module.equals(config.module)) {
      throw new IllegalArgumentException("PKCS#11 key selection names a different module");
    }
    if (!empty(selection.tokenLabel) && !selection.tokenLabel.equals(config.tokenLabel)) {
      throw new IllegalArgumentException("PKCS#11 key selection names a different token");
    }
    if (selection.slot != null
        && config.slot != null
        && !Objects.equals(selection.slot, config.slot)) {
      throw new IllegalArgumentException("PKCS#11 key selection names a different slot");
    }
  }

  Pkcs11Token token() {
    if (closed) {
      throw new IllegalStateException("PKCS#11 session is closed");
    }
    return token;
  }

  @Override
  public void close() {
    if (closed) {
      return;
    }
    closed = true;
    token.close();
  }

  private static boolean empty(String value) {
    return value == null || value.isEmpty();
  }
}
