/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import dev.mistial.tools.openfips201.common.ByteArrays;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

/** Byte and P-256 helpers shared by the issuance wire contract. */
public final class IssuanceCrypto {
  /** Length of an uncompressed P-256 point {@code 04 || X || Y}. */
  public static final int POINT_LENGTH = 65;

  private IssuanceCrypto() {}

  public static byte[] sha256(byte[]... parts) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      for (byte[] part : parts) {
        digest.update(part);
      }
      return digest.digest();
    } catch (Exception e) {
      throw new IllegalStateException("SHA-256 is unavailable", e);
    }
  }

  /** Big-endian unsigned encoding of {@code value} in {@code length} octets. */
  public static byte[] unsigned(long value, int length) {
    byte[] out = new byte[length];
    for (int i = 0; i < length; i++) {
      out[i] = (byte) (value >>> (8 * (length - 1 - i)));
    }
    return out;
  }

  /** Big-endian unsigned value of {@code length} octets at {@code offset}. */
  public static long unsigned(byte[] data, int offset, int length) {
    if (length > 8 || offset < 0 || offset + length > data.length) {
      throw new IllegalArgumentException("unsigned field out of bounds");
    }
    long value = 0;
    for (int i = 0; i < length; i++) {
      value = (value << 8) | (data[offset + i] & 0xFF);
    }
    return value;
  }

  /** SubjectPublicKeyInfo for an uncompressed P-256 point. */
  public static PublicKey publicKey(byte[] point) {
    if (point == null || point.length != POINT_LENGTH || point[0] != 0x04) {
      throw new IllegalArgumentException("P-256 point must be 65 octets beginning with 04");
    }
    try {
      SubjectPublicKeyInfo spki =
          new SubjectPublicKeyInfo(
              new AlgorithmIdentifier(
                  X9ObjectIdentifiers.id_ecPublicKey, X9ObjectIdentifiers.prime256v1),
              point);
      return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spki.getEncoded()));
    } catch (Exception e) {
      throw new IllegalArgumentException("P-256 point is not on the curve", e);
    }
  }

  /** The uncompressed point of a P-256 public key. */
  public static byte[] point(PublicKey key) {
    if (!(key instanceof ECPublicKey)) {
      throw new IllegalArgumentException("public key is not an EC key");
    }
    ECPublicKey ec = (ECPublicKey) key;
    if (ec.getParams().getCurve().getField().getFieldSize() != 256) {
      throw new IllegalArgumentException("public key is not on P-256");
    }
    return ByteArrays.concat(
        new byte[] {0x04}, fixed(ec.getW().getAffineX(), 32), fixed(ec.getW().getAffineY(), 32));
  }

  /** ECDSA P-256 / SHA-256 over {@code message}; a malformed signature does not verify. */
  public static boolean verify(PublicKey key, byte[] message, byte[] signature) {
    try {
      Signature verifier = Signature.getInstance("SHA256withECDSA");
      verifier.initVerify(key);
      verifier.update(message);
      return verifier.verify(signature);
    } catch (Exception e) {
      return false;
    }
  }

  private static byte[] fixed(BigInteger value, int length) {
    return ByteArrays.unsignedFixed(value, length);
  }
}
