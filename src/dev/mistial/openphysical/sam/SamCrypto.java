/******************************************************************************
 * MIT License
 *
 * Project: OpenPhysical Issuer SAM
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ******************************************************************************/

package dev.mistial.openphysical.sam;

import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * The SAM's cryptographic objects, each allocated once at install.
 *
 * <p>One {@link Signature} (ECDSA P-256 with SHA-256) serves every sign and verify operation and is
 * re-initialized per use. Java Card 3.0.5 offers no transient EC public key, so the root key and
 * the per-issuance F9 key are persistent key objects; the F9 key holds only the public point of the
 * card being issued.
 */
final class SamCrypto {
  final Signature signature;
  final MessageDigest sha256;
  final RandomData random;
  final ECPrivateKey samPrivate;
  final ECPublicKey samPublic;
  final KeyPair samKeyPair;
  final ECPublicKey rootPublic;
  final ECPublicKey f9Public;
  // FF1 key (AES-256) and the AES-CBC engine used as the FF1 PRF (CBC-MAC with a zero IV).
  final AESKey fpeKey;
  final Cipher fpeCipher;
  // One-time P-256 transport key pair for the FF1 key, the ECDH engine, the transient KEK and the
  // AES-ECB engine for RFC 3394 unwrapping.
  final ECPrivateKey transportPrivate;
  final ECPublicKey transportPublic;
  final KeyPair transportKeyPair;
  final KeyAgreement keyAgreement;
  final AESKey kek;
  final Cipher kwCipher;
  private final ECParamsP256 params;
  private final ECPointValidator pointValidator;

  /**
   * @param workspace transient array of at least {@link ECPointValidator#WORKSPACE_LENGTH} octets
   *     used by point validation; its first WORKSPACE_LENGTH octets are clobbered by {@link
   *     #isValidPoint}
   */
  SamCrypto(byte[] workspace) {
    params = new ECParamsP256();
    pointValidator = new ECPointValidator(workspace);
    samPrivate =
        (ECPrivateKey)
            KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
    samPublic =
        (ECPublicKey)
            KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
    rootPublic =
        (ECPublicKey)
            KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
    f9Public =
        (ECPublicKey)
            KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
    setDomain(samPrivate);
    setDomain(samPublic);
    setDomain(rootPublic);
    setDomain(f9Public);
    samKeyPair = new KeyPair(samPublic, samPrivate);
    signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    // A platform without AES-256 fails installation here with CryptoException.NO_SUCH_ALGORITHM.
    fpeKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
    fpeCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
    transportPrivate =
        (ECPrivateKey)
            KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
    transportPublic =
        (ECPublicKey)
            KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
    setDomain(transportPrivate);
    setDomain(transportPublic);
    transportKeyPair = new KeyPair(transportPublic, transportPrivate);
    keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
    kek =
        (AESKey)
            KeyBuilder.buildKey(
                KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
    kwCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
  }

  private void setDomain(ECKey key) {
    byte[] p = params.getP();
    byte[] a = params.getA();
    byte[] b = params.getB();
    byte[] g = params.getG();
    byte[] n = params.getN();
    key.setFieldFP(p, (short) 0, (short) p.length);
    key.setA(a, (short) 0, (short) a.length);
    key.setB(b, (short) 0, (short) b.length);
    key.setG(g, (short) 0, (short) g.length);
    key.setR(n, (short) 0, (short) n.length);
    key.setK(params.getH());
  }

  /**
   * Validates an uncompressed P-256 point (SEC 1 Section 3.2.2.1 partial public-key validation:
   * coordinates in [0, p-1] and the curve equation).
   */
  boolean isValidPoint(byte[] point, short offset, short length) {
    return pointValidator.isValid(point, offset, length, params);
  }

  /** Generates a fresh SAM key pair on the card. */
  void generateSamKey() {
    samKeyPair.genKeyPair();
  }

  /** Clears the SAM private key and the FF1 key; afterwards the SAM can sign and issue nothing. */
  void clearSamKey() {
    clearTransportKey();
    samPrivate.clearKey();
    fpeKey.clearKey();
  }

  /** Generates a fresh one-time transport key pair, replacing any previous one. */
  void generateTransportKey() {
    transportKeyPair.genKeyPair();
  }

  boolean hasTransportKey() {
    return transportPrivate.isInitialized();
  }

  /** Destroys the transport key pair. */
  void clearTransportKey() {
    transportPrivate.clearKey();
    transportPublic.clearKey();
    setDomain(transportPrivate);
    setDomain(transportPublic);
  }

  /**
   * Recovers the FF1 key carried by PUT PARAMETERS v5.
   *
   * <ol>
   *   <li>Z = ECDH(transportPriv, hostEph), the 32-octet x-coordinate (ALG_EC_SVDP_DH_PLAIN); the
   *       caller has validated hostEph on P-256.
   *   <li>KEK = SHA-256(Z | 00000001 | SharedInfo) (ANSI X9.63 KDF, one block) with SharedInfo =
   *       "OPSAMKT1" | samTransportPub(65) | hostEphPub(65) | ASCII(IIN)(4).
   *   <li>The 32-octet key = RFC 3394 AES-256 key unwrap of the 40-octet wrapped key.
   * </ol>
   *
   * The work regions are the S_KW_* offsets of {@code work}; on success the key is at {@link
   * SamConst#S_KW_KEY} and every other region is zeroized. On failure everything is zeroized.
   *
   * @return false when the RFC 3394 integrity check fails
   */
  boolean unwrapTransportedKey(
      byte[] hostEph,
      short hostEphOffset,
      byte[] wrapped,
      short wrappedOffset,
      byte[] iinAscii,
      short iinOffset,
      byte[] work) {
    keyAgreement.init(transportPrivate);
    keyAgreement.generateSecret(
        hostEph, hostEphOffset, SamConst.LENGTH_POINT, work, SamConst.S_KW_Z);
    transportPublic.getW(work, SamConst.S_KW_POINT);
    x963Kdf(
        work,
        SamConst.S_KW_Z,
        work,
        SamConst.S_KW_POINT,
        hostEph,
        hostEphOffset,
        iinAscii,
        iinOffset,
        work,
        SamConst.S_KW_KEK);
    Util.arrayFillNonAtomic(work, SamConst.S_KW_Z, SamConst.LENGTH_HASH, (byte) 0);
    boolean valid =
        aesKeyUnwrap(
            work,
            SamConst.S_KW_KEK,
            wrapped,
            wrappedOffset,
            work,
            SamConst.S_KW_REGISTER,
            work,
            SamConst.S_KW_BLOCK);
    Util.arrayFillNonAtomic(work, SamConst.S_KW_POINT, SamConst.LENGTH_POINT, (byte) 0);
    Util.arrayFillNonAtomic(work, SamConst.S_KW_KEK, SamConst.LENGTH_HASH, (byte) 0);
    Util.arrayFillNonAtomic(work, SamConst.S_KW_REGISTER, (short) 8, (byte) 0);
    Util.arrayFillNonAtomic(work, SamConst.S_KW_BLOCK, (short) 16, (byte) 0);
    if (!valid) Util.arrayFillNonAtomic(work, SamConst.S_KW_KEY, (short) 32, (byte) 0);
    return valid;
  }

  /**
   * ANSI X9.63 KDF with SHA-256 for one 32-octet block: SHA-256(Z(32) | 00000001 | "OPSAMKT1" |
   * transportPub(65) | hostEph(65) | ASCII(IIN)(4)).
   */
  void x963Kdf(
      byte[] z,
      short zOffset,
      byte[] transportPub,
      short transportOffset,
      byte[] hostEph,
      short hostEphOffset,
      byte[] iinAscii,
      short iinOffset,
      byte[] out,
      short outOffset) {
    sha256.reset();
    sha256.update(z, zOffset, SamConst.LENGTH_HASH);
    sha256.update(SamConst.KDF_COUNTER_1, (short) 0, (short) SamConst.KDF_COUNTER_1.length);
    sha256.update(SamConst.PREFIX_TRANSPORT, (short) 0, (short) SamConst.PREFIX_TRANSPORT.length);
    sha256.update(transportPub, transportOffset, SamConst.LENGTH_POINT);
    sha256.update(hostEph, hostEphOffset, SamConst.LENGTH_POINT);
    sha256.doFinal(iinAscii, iinOffset, SamConst.ISSUER_DIGITS, out, outOffset);
  }

  /**
   * RFC 3394 Section 2.2.2 key unwrap (index-based form) of a 256-bit key (n = 4) under a 256-bit
   * KEK: A = C0, R[i] = C[i]; for j = 5..0, for i = 4..1: B = AES-1(K, (A ^ t) | R[i]) with t = n j
   * + i, A = MSB64(B), R[i] = LSB64(B). The result is valid only if A equals the default IV
   * A6A6A6A6A6A6A6A6 (Section 2.2.3.1).
   *
   * @param register 40 octets receiving A | R1..R4; the key is R1..R4 at register + 8
   * @param block 16 octets of work area
   * @return true when the integrity check passes
   */
  boolean aesKeyUnwrap(
      byte[] kekBytes,
      short kekOffset,
      byte[] wrapped,
      short wrappedOffset,
      byte[] register,
      short registerOffset,
      byte[] block,
      short blockOffset) {
    kek.setKey(kekBytes, kekOffset);
    kwCipher.init(kek, Cipher.MODE_DECRYPT);
    Util.arrayCopyNonAtomic(
        wrapped, wrappedOffset, register, registerOffset, SamConst.LENGTH_WRAPPED_KEY);
    short a = registerOffset;
    for (short j = 5; j >= 0; j--) {
      for (short i = 4; i >= 1; i--) {
        // t = 4 j + i <= 24 changes only the last octet of A.
        register[(short) (a + 7)] = (byte) (register[(short) (a + 7)] ^ (byte) (4 * j + i));
        short r = (short) (registerOffset + 8 * i);
        Util.arrayCopyNonAtomic(register, a, block, blockOffset, (short) 8);
        Util.arrayCopyNonAtomic(register, r, block, (short) (blockOffset + 8), (short) 8);
        kwCipher.doFinal(block, blockOffset, (short) 16, block, blockOffset);
        Util.arrayCopyNonAtomic(block, blockOffset, register, a, (short) 8);
        Util.arrayCopyNonAtomic(block, (short) (blockOffset + 8), register, r, (short) 8);
      }
    }
    kek.clearKey();
    Util.arrayFillNonAtomic(block, blockOffset, (short) 16, (byte) 0);
    return Util.arrayCompare(register, a, SamConst.KW_IV, (short) 0, (short) 8) == (byte) 0;
  }

  /**
   * Writes the 16-octet FF1 key check value {@code SHA-256("OPSAMFPEKCV1" ||
   * AES-256-ECB_K(0^16))[0..16)} at {@code work[offset]}; shared wire contract with the host.
   *
   * @param work 60 octets of work area; on return only the first 16 are non-zero
   */
  void fpeKcv(byte[] work, short offset) {
    short prefix = (short) SamConst.PREFIX_KCV.length;
    Util.arrayCopyNonAtomic(SamConst.PREFIX_KCV, (short) 0, work, offset, prefix);
    short block = (short) (offset + prefix);
    Util.arrayFillNonAtomic(work, block, (short) 16, (byte) 0);
    // One block of CBC with a zero IV is ECB.
    fpeCipher.init(fpeKey, Cipher.MODE_ENCRYPT);
    fpeCipher.doFinal(work, block, (short) 16, work, block);
    short hash = (short) (block + 16);
    digest(work, offset, (short) (prefix + 16), work, hash);
    Util.arrayCopyNonAtomic(work, hash, work, offset, SamConst.LENGTH_KCV);
    Util.arrayFillNonAtomic(
        work,
        (short) (offset + SamConst.LENGTH_KCV),
        (short) (prefix + 16 + SamConst.LENGTH_HASH - SamConst.LENGTH_KCV),
        (byte) 0);
  }

  boolean isSamKeyInitialized() {
    return samPrivate.isInitialized();
  }

  /** Writes {@code SHA-256(in[offset..offset+length))} at out[outOffset]. */
  void digest(byte[] in, short offset, short length, byte[] out, short outOffset) {
    sha256.reset();
    sha256.doFinal(in, offset, length, out, outOffset);
  }

  /**
   * Writes the RFC 7093 Section 2 method 1 key identifier: the leftmost 160 bits of the SHA-256
   * hash of the subjectPublicKey BIT STRING value (the 65-octet point).
   *
   * @param hash 32-octet work area; out may lie inside it
   */
  void keyIdentifier(
      byte[] point, short pointOffset, byte[] hash, short hashOffset, byte[] out, short outOffset) {
    digest(point, pointOffset, SamConst.LENGTH_POINT, hash, hashOffset);
    Util.arrayCopyNonAtomic(hash, hashOffset, out, outOffset, SamConst.LENGTH_SKI);
  }

  /** Signs a 32-octet SHA-256 hash with the SAM key; returns the DER signature length. */
  short signHash(byte[] hash, short hashOffset, byte[] out, short outOffset) {
    signature.init(samPrivate, Signature.MODE_SIGN);
    return signature.signPreComputedHash(hash, hashOffset, SamConst.LENGTH_HASH, out, outOffset);
  }

  /**
   * Signs {@code prefix | first | second} with the SAM key (ECDSA P-256 / SHA-256 over the
   * concatenation); returns the DER signature length.
   */
  short signConcatenation(
      byte[] prefix,
      byte[] first,
      short firstOffset,
      short firstLength,
      byte[] second,
      short secondOffset,
      short secondLength,
      byte[] out,
      short outOffset) {
    signature.init(samPrivate, Signature.MODE_SIGN);
    signature.update(prefix, (short) 0, (short) prefix.length);
    signature.update(first, firstOffset, firstLength);
    return signature.sign(second, secondOffset, secondLength, out, outOffset);
  }

  /**
   * Verifies an ECDSA P-256 / SHA-256 signature over a message.
   *
   * <p>A signature outside 8..72 octets, or one the platform rejects as malformed, is a failed
   * verification.
   */
  boolean verify(
      ECPublicKey key,
      byte[] message,
      short messageOffset,
      short messageLength,
      byte[] sig,
      short sigOffset,
      short sigLength) {
    if (sigLength < SamConst.LENGTH_SIGNATURE_MIN || sigLength > SamConst.LENGTH_SIGNATURE_MAX) {
      return false;
    }
    try {
      signature.init(key, Signature.MODE_VERIFY);
      return signature.verify(message, messageOffset, messageLength, sig, sigOffset, sigLength);
    } catch (CryptoException e) {
      return false;
    }
  }

  void randomBytes(byte[] out, short offset, short length) {
    random.generateData(out, offset, length);
  }
}
