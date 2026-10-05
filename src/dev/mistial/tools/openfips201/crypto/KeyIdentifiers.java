/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.crypto;

import java.security.PublicKey;
import java.util.Arrays;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.digests.SHA256Digest;

/** X.509 key identifiers. */
public final class KeyIdentifiers {
  /** Length in bytes of an RFC 7093 section 2 method 1 key identifier (160 bits). */
  public static final int SKI_LENGTH = 20;

  private KeyIdentifiers() {}

  /**
   * RFC 7093 section 2 method 1: "The keyIdentifier is composed of the leftmost 160-bits of the
   * SHA-256 hash of the value of the BIT STRING subjectPublicKey (excluding the tag, length, and
   * number of unused bits)."
   */
  public static byte[] ski(PublicKey publicKey) {
    return ski(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
  }

  /** {@link #ski(PublicKey)} of an encoded SubjectPublicKeyInfo. */
  public static byte[] ski(SubjectPublicKeyInfo publicKeyInfo) {
    byte[] subjectPublicKey = publicKeyInfo.getPublicKeyData().getBytes();
    SHA256Digest digest = new SHA256Digest();
    digest.update(subjectPublicKey, 0, subjectPublicKey.length);
    byte[] hash = new byte[digest.getDigestSize()];
    digest.doFinal(hash, 0);
    return Arrays.copyOf(hash, SKI_LENGTH);
  }

  /** The SubjectKeyIdentifier extension value carrying {@link #ski(PublicKey)}. */
  public static SubjectKeyIdentifier subjectKeyIdentifier(PublicKey publicKey) {
    return new SubjectKeyIdentifier(ski(publicKey));
  }
}
