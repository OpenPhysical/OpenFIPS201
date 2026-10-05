/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import dev.mistial.tools.openfips201.crypto.SigningKey;
import dev.mistial.tools.openfips201.opid.OpidCipher;
import java.security.cert.X509Certificate;

/**
 * The root station's key custody: the root CA key, the per-IIN FF1 keys (which leave it only
 * wrapped) and the allocation registry head.
 */
public interface RootKeys {
  /** The root CA signer, bound to {@link #rootCertificate()}. */
  SigningKey rootSigner() throws Exception;

  X509Certificate rootCertificate();

  /** Ensures the FF1 key of {@code iin} exists; returns its key check value (hex). */
  String ensureIinKey(int iin);

  /** FF1 through the key of {@code iin}; the key never leaves the custody. */
  OpidCipher iinCipher(int iin);

  /**
   * Wraps the FF1 key of {@code iin} to a SAM transport key (ECDH + X9.63 SHA-256 with SharedInfo
   * {@code "OPSAMKT1" || samTransportPub || ephPub || ASCII(IIII)}, then RFC 3394).
   */
  WrappedKey wrapIinKeyForSam(int iin, byte[] samTransportPub);

  /** Wraps {@code secret} to {@code recipientPub} under a fresh ephemeral key. */
  WrappedKey wrapSecret(byte[] secret, byte[] recipientPub, byte[] sharedInfo);

  /** The registry head held by the custody ({@code seq(4) || headHash(32)}), or null. */
  byte[] readRegistryHead();

  void writeRegistryHead(byte[] head);

  /** Whether the keys are in development custody. */
  boolean isDevelopment();

  /** An ECDH-transported key: the sender's ephemeral point and the RFC 3394 output. */
  final class WrappedKey {
    private final byte[] ephemeralPublicKey;
    private final byte[] wrapped;

    public WrappedKey(byte[] ephemeralPublicKey, byte[] wrapped) {
      this.ephemeralPublicKey = ephemeralPublicKey.clone();
      this.wrapped = wrapped.clone();
    }

    public byte[] ephemeralPublicKey() {
      return ephemeralPublicKey.clone();
    }

    public byte[] wrapped() {
      return wrapped.clone();
    }
  }
}
