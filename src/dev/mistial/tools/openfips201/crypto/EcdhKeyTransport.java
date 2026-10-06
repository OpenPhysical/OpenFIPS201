/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.crypto;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.util.Arrays;
import java.util.Locale;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESWrapEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECPoint;

/**
 * ECDH key transport shared by the host token, the SAM and the station handoff.
 *
 * <p>Construction (the wire contract, byte-identical with the SAM's PUT PARAMETERS v5):
 *
 * <ol>
 *   <li>{@code Z} = the x-coordinate of {@code d * Q} on P-256, 32 bytes (ECDH primitive, SEC 1
 *       section 3.3.1; {@code ALG_EC_SVDP_DH_PLAIN}).
 *   <li>{@code KEK = SHA-256(Z || 00000001 || SharedInfo)}: the ANSI X9.63 KDF with SHA-256 for a
 *       32-byte output (PKCS#11 {@code CKD_SHA256_KDF}).
 *   <li>The wrapped key is RFC 3394 AES Key Wrap under the AES-256 KEK with the default IV {@code
 *       A6A6A6A6A6A6A6A6}.
 * </ol>
 *
 * <p>SharedInfo:
 *
 * <ul>
 *   <li>SAM transport: {@code "OPSAMKT1" || samTransportPub(65) || hostEphPub(65) || ASCII(IIII)}.
 *   <li>Station handoff: {@code "OPSAMHO1" || samId || stationSki}.
 *   <li>FF1 key backup: {@code "OPFPEBK1" || backupPub(65) || ASCII(IIII)}.
 * </ul>
 *
 * <p>This class is the software reference: the host performs the same steps on a PKCS#11 token
 * ({@code Pkcs11KeyTransport}).
 */
public final class EcdhKeyTransport {
  public static final int POINT_LENGTH = 65;
  public static final int Z_LENGTH = 32;
  public static final int KEK_LENGTH = 32;

  private static final byte[] SAM_TRANSPORT = ascii("OPSAMKT1");
  private static final byte[] HANDOFF = ascii("OPSAMHO1");
  private static final byte[] BACKUP = ascii("OPFPEBK1");
  private static final X9ECParameters P256 = ECNamedCurveTable.getByName("secp256r1");

  private EcdhKeyTransport() {}

  /** {@code "OPSAMKT1" || samTransportPub || hostEphPub || ASCII(IIII)}. */
  public static byte[] samTransportSharedInfo(byte[] samTransportPub, byte[] hostEphPub, int iin) {
    requireP256Point(samTransportPub);
    requireP256Point(hostEphPub);
    return concat(SAM_TRANSPORT, samTransportPub, hostEphPub, iinAscii(iin));
  }

  /** {@code "OPSAMHO1" || samId || stationSki}. */
  public static byte[] handoffSharedInfo(byte[] samId, byte[] stationSki) {
    if (samId == null || samId.length == 0 || stationSki == null || stationSki.length == 0) {
      throw new IllegalArgumentException("samId and station SKI are required");
    }
    return concat(HANDOFF, samId, stationSki);
  }

  /** {@code "OPFPEBK1" || backupPub || ASCII(IIII)}. */
  public static byte[] backupSharedInfo(byte[] backupPub, int iin) {
    requireP256Point(backupPub);
    return concat(BACKUP, backupPub, iinAscii(iin));
  }

  /** {@code SHA-256(Z || 00000001 || sharedInfo)}, 32 bytes. */
  public static byte[] x963Sha256(byte[] z, byte[] sharedInfo) {
    SHA256Digest digest = new SHA256Digest();
    digest.update(z, 0, z.length);
    digest.update(new byte[] {0, 0, 0, 1}, 0, 4);
    digest.update(sharedInfo, 0, sharedInfo.length);
    byte[] out = new byte[KEK_LENGTH];
    digest.doFinal(out, 0);
    return out;
  }

  /** ECDH primitive: the 32-byte x-coordinate of {@code d * peer}. */
  public static byte[] ecdh(BigInteger d, byte[] peer) {
    ECPoint shared = decode(peer).multiply(d).normalize();
    if (shared.isInfinity()) {
      throw new IllegalArgumentException("ECDH produced the point at infinity");
    }
    return shared.getAffineXCoord().getEncoded();
  }

  /** ECDH primitive with a JCA P-256 private key. */
  public static byte[] ecdh(PrivateKey privateKey, byte[] peer) {
    if (!(privateKey instanceof ECPrivateKey)) {
      throw new IllegalArgumentException("ECDH needs an EC private key");
    }
    return ecdh(((ECPrivateKey) privateKey).getS(), peer);
  }

  /** Uncompressed point {@code d * G}. */
  public static byte[] publicPoint(BigInteger d) {
    return P256.getG().multiply(d).normalize().getEncoded(false);
  }

  /** Uncompressed point of a P-256 public key. */
  public static byte[] point(PublicKey publicKey) {
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
    byte[] point = spki.getPublicKeyData().getBytes();
    requireP256Point(point);
    return point;
  }

  /**
   * Fails unless {@code point} is a 65-byte uncompressed P-256 point on the curve and not the point
   * at infinity.
   */
  public static void requireP256Point(byte[] point) {
    decode(point);
  }

  /**
   * RFC 3394 AES Key Wrap of {@code key} (a multiple of 8 bytes, at least 16) under {@code kek}.
   */
  public static byte[] wrap(byte[] kek, byte[] key) {
    AESWrapEngine engine = new AESWrapEngine();
    engine.init(true, new KeyParameter(kek));
    return engine.wrap(key, 0, key.length);
  }

  /** RFC 3394 AES Key Unwrap; fails on an integrity check failure. */
  public static byte[] unwrap(byte[] kek, byte[] wrapped) {
    AESWrapEngine engine = new AESWrapEngine();
    engine.init(false, new KeyParameter(kek));
    try {
      return engine.unwrap(wrapped, 0, wrapped.length);
    } catch (InvalidCipherTextException e) {
      throw new IllegalArgumentException("AES key unwrap integrity check failed");
    }
  }

  /**
   * Software unwrap at the recipient: {@code unwrap(KDF(ECDH(recipient, ephPub), sharedInfo),
   * wrapped)}. Intermediate secrets are wiped; the caller wipes the result.
   */
  public static byte[] unwrapFrom(
      BigInteger recipient, byte[] ephemeralPub, byte[] wrapped, byte[] sharedInfo) {
    byte[] z = ecdh(recipient, ephemeralPub);
    byte[] kek = x963Sha256(z, sharedInfo);
    try {
      return unwrap(kek, wrapped);
    } finally {
      Arrays.fill(z, (byte) 0);
      Arrays.fill(kek, (byte) 0);
    }
  }

  /**
   * Software wrap with a caller-chosen ephemeral scalar: {@code wrap(KDF(ECDH(ephemeral,
   * recipientPub), sharedInfo), key)}. For reference vectors; production wraps on a token.
   */
  public static byte[] wrapWith(
      BigInteger ephemeral, byte[] recipientPub, byte[] key, byte[] sharedInfo) {
    byte[] z = ecdh(ephemeral, recipientPub);
    byte[] kek = x963Sha256(z, sharedInfo);
    try {
      return wrap(kek, key);
    } finally {
      Arrays.fill(z, (byte) 0);
      Arrays.fill(kek, (byte) 0);
    }
  }

  /** {@code ASCII(IIII)}: the IIN as four ASCII digits. */
  public static byte[] iinAscii(int iin) {
    if (iin < 0 || iin > 9999) {
      throw new IllegalArgumentException("IIN must be 0..9999");
    }
    return ascii(String.format(Locale.ROOT, "%04d", iin));
  }

  private static ECPoint decode(byte[] point) {
    if (point == null || point.length != POINT_LENGTH || point[0] != 0x04) {
      throw new IllegalArgumentException("expected a 65-byte uncompressed P-256 point");
    }
    ECPoint decoded;
    try {
      decoded = P256.getCurve().decodePoint(point);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("point is not on P-256");
    }
    if (decoded.isInfinity() || !decoded.isValid()) {
      throw new IllegalArgumentException("point is not a valid P-256 public key");
    }
    return decoded;
  }

  private static byte[] concat(byte[]... parts) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (byte[] part : parts) {
      out.write(part, 0, part.length);
    }
    return out.toByteArray();
  }

  private static byte[] ascii(String value) {
    return value.getBytes(StandardCharsets.US_ASCII);
  }
}
