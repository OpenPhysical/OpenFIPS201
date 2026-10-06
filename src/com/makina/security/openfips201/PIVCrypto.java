/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2017 Commonwealth of Australia
 * Author: Kim O'Sullivan - Makina (kim@makina.com.au)
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

package com.makina.security.openfips201;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.SecretKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * The cryptographic engines of one applet instance.
 *
 * <p>Goals of this class:
 *
 * <ul>
 *   <li>Provide a simple way to access the required PIV crypto operations.
 *   <li>Prevent encryption keys from being generally exposed to the PIV application.
 *   <li>Keep the engines out of static fields, so primitives cannot be reached from outside the
 *       owning instance (for example to start an operation, switch applets and abuse the engine
 *       mid-operation).
 * </ul>
 *
 * <p>The applet constructor creates one instance at install and passes it to every object that
 * needs it. No static field references an engine, so JCRE 3.0.5 Section 11.3.4.2 ("An object owned
 * by the applet instance is referenced from a static field on any package on the card") never
 * blocks deleting the instance, the engines are released together with it, and a second instance of
 * the package owns engines of its own.
 *
 * <p>An engine the platform does not provide is left null and the mechanisms that need it are
 * reported as unsupported by {@link #supportsMechanism} and {@link #supportsKeyRole}.
 */
final class PIVCrypto {

  //
  // Crypto Constants
  //
  static final short LENGTH_BLOCK_AES = (short) 16;
  static final short LENGTH_BLOCK_TDEA = (short) 8;

  //
  // Crypto Providers
  //
  private final Cipher cspTDEA;
  private final Cipher cspRSA;
  private final Cipher cspAES;
  private final Cipher cspAESCBC;

  private final MessageDigest cspSHA256;
  // #if VCI_CS7
  private final MessageDigest cspSHA384;
  // #endif

  private final KeyAgreement cspECDH;

  private final Signature cspECCSHA256;
  private final Signature cspECCSHA384;
  private final Signature cspAESCMAC;
  private final Signature cspAESResponseCMAC;

  private final RandomData cspRNG;

  /**
   * Creates the engines. Called once, from the applet constructor at install.
   *
   * @throws ISOException {@link ISO7816#SW_FUNC_NOT_SUPPORTED} if the platform has no secure random
   *     number generator, which every PIV operation depends on
   */
  PIVCrypto() {
    RandomData rng = null;
    try {
      rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    } catch (CryptoException ex) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }
    cspRNG = rng;

    cspTDEA = cipher(Cipher.ALG_DES_ECB_NOPAD);
    cspAES = cipher(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD);
    cspAESCBC = cipher(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD);
    cspRSA = cipher(Cipher.ALG_RSA_NOPAD);

    KeyAgreement ecdh = null;
    try {
      ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
    } catch (CryptoException ex) {
      // Not provided by the platform: the ECDH mechanisms are reported as unsupported.
    }
    cspECDH = ecdh;

    cspECCSHA256 = signature(Signature.ALG_ECDSA_SHA_256);
    cspECCSHA384 = signature(Signature.ALG_ECDSA_SHA_384);
    cspAESCMAC = signature(Signature.ALG_AES_CMAC_128);
    cspAESResponseCMAC = signature(Signature.ALG_AES_CMAC_128);

    cspSHA256 = digest(MessageDigest.ALG_SHA_256);
    // #if VCI_CS7
    cspSHA384 = digest(MessageDigest.ALG_SHA_384);
    // #endif
  }

  /** Returns the cipher engine for the algorithm, or null if the platform does not provide it. */
  private static Cipher cipher(byte algorithm) {
    try {
      return Cipher.getInstance(algorithm, false);
    } catch (CryptoException ex) {
      return null;
    }
  }

  /**
   * Returns the signature engine for the algorithm, or null if the platform does not provide it.
   */
  private static Signature signature(byte algorithm) {
    try {
      return Signature.getInstance(algorithm, false);
    } catch (CryptoException ex) {
      return null;
    }
  }

  /** Returns the digest engine for the algorithm, or null if the platform does not provide it. */
  private static MessageDigest digest(byte algorithm) {
    try {
      return MessageDigest.getInstance(algorithm, false);
    } catch (CryptoException ex) {
      return null;
    }
  }

  boolean pairwiseAgreementTest(
      ECPrivateKey privateKey,
      ECPublicKey publicKey,
      ECParams params,
      byte[] scratch,
      short offset) {
    short fieldLength = (short) (privateKey.getSize() >> 3);
    cspECDH.init(privateKey);
    short secretOffset = (short) (offset + params.getG().length);
    short secretLength =
        cspECDH.generateSecret(
            params.getG(), (short) 0, (short) params.getG().length, scratch, secretOffset);
    short pointLength = publicKey.getW(scratch, offset);
    return secretLength == fieldLength
        && pointLength == (short) (fieldLength * (short) 2 + (short) 1)
        && PIVSecurityProvider.arrayEqualsConstantTime(
            scratch, secretOffset, scratch, (short) (offset + 1), fieldLength);
  }

  boolean supportsMechanism(byte mechanism) {

    if (!FipsPolicy.allowsMechanism(mechanism)) return false;

    switch (mechanism) {
      case PIV.ID_ALG_DEFAULT:
      case PIV.ID_ALG_TDEA_3KEY:
        return (cspTDEA != null);

      case PIV.ID_ALG_AES_128:
      case PIV.ID_ALG_AES_192:
      case PIV.ID_ALG_AES_256:
        return (cspAES != null);

      case PIV.ID_ALG_RSA_1024:
      case PIV.ID_ALG_RSA_2048:
      case PIV.ID_ALG_RSA_3072:
        return (cspRSA != null);

      case PIV.ID_ALG_ECC_P256:
      case PIV.ID_ALG_ECC_P384:
        // SP 800-78 permits only ECDSA P-256 with SHA-256 and P-384 with SHA-384, so SHA-1 and
        // SHA-512 ECDSA engines are not provided. The curve's ECDSA engine or ECDH satisfies the
        // mechanism; supportsKeyRole() checks the engine each role needs.
        return ((ecdsaForMechanism(mechanism) != null) || (cspECDH != null));

      case PIV.ID_ALG_ECC_CS2:
        // #if VCI_CS2
        // OPACITY needs ECDH, AES (ECB/CBC/CMAC), and the suite hash (SHA-256 or SHA-384).
        return (cspECDH != null
            && cspAES != null
            && cspAESCBC != null
            && cspAESCMAC != null
            && cspAESResponseCMAC != null
            && cspSHA256 != null);
        // #else
        return false;
        // #endif

      case PIV.ID_ALG_ECC_CS7:
        // #if VCI_CS7
        return (cspECDH != null
            && cspAES != null
            && cspAESCBC != null
            && cspAESCMAC != null
            && cspAESResponseCMAC != null
            && cspSHA384 != null);
        // #else
        return false;
        // #endif

      default:
        return false;
    }
  }

  /**
   * Returns whether the platform provides the engine every role of a key definition needs.
   *
   * <p>An ECC signing key needs its curve's ECDSA engine (P-256 with SHA-256, P-384 with SHA-384)
   * and a key-establishment key needs ECDH, so a definition the card could never use is rejected
   * when it is created rather than failing at GENERAL AUTHENTICATE.
   */
  boolean supportsKeyRole(byte mechanism, byte role) {
    switch (mechanism) {
      case PIV.ID_ALG_ECC_P256:
      case PIV.ID_ALG_ECC_P384:
        if ((role & PIVKeyObject.ROLE_SIGN) != (byte) 0 && ecdsaForMechanism(mechanism) == null) {
          return false;
        }
        return (role & PIVKeyObject.ROLE_KEY_ESTABLISH) == (byte) 0 || cspECDH != null;

      default:
        return true;
    }
  }

  private Signature ecdsaForMechanism(byte mechanism) {
    return (mechanism == PIV.ID_ALG_ECC_P384) ? cspECCSHA384 : cspECCSHA256;
  }

  static boolean isSymmetricMechanism(byte mechanism) {

    switch (mechanism) {
      case PIV.ID_ALG_DEFAULT:
      case PIV.ID_ALG_TDEA_3KEY:
      case PIV.ID_ALG_AES_128:
      case PIV.ID_ALG_AES_192:
      case PIV.ID_ALG_AES_256:
        return true;

      default:
        return false;
    }
  }

  /**
   * Performs a symmetric encryption operation on the supplied data
   *
   * @param theKey The key to perform the operation with
   * @param inBuffer contains the precomputed hash
   * @param inOffset the location of the first byte of the hash
   * @param inLength the length og the computed hash
   * @param outBuffer the buffer to contain the signature
   * @param outOffset the location of the first byte of the signature
   * @return the length of the encrypted block
   */
  short doEncrypt(
      SecretKey theKey,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset)
      throws ISOException {

    // PRE-CONDITION 1 - If the input and output buffers are equal, we must not clobber the input
    // From the Javacard Cipher documentation:
    // When using block-aligned data (multiple of block size), if the input buffer, inBuff and
    // the output buffer, outBuff are the same array, then the output data area must not
    // partially overlap the input data area such that the input data is modified before it is
    // used; if inBuff==outBuff and inOffset < outOffset < inOffset+inLength, incorrect output
    // may result.
    if ((inBuffer == outBuffer)
        && (inOffset < outOffset)
        && (outOffset < (short) (inOffset + inLength))) {
      // Internal buffer misuse, not a property of the command: ISO/IEC 7816-4 Table 6 '6F00'.
      ISOException.throwIt(ISO7816.SW_UNKNOWN);
    }

    Cipher cipher = null;

    // Select by concrete key type, not key-interface checks.
    // A key object may implement multiple key interfaces, which makes interface dispatch
    // ambiguous and can route a valid key to the wrong cipher.
    switch (theKey.getType()) {
      case KeyBuilder.TYPE_DES:
      case KeyBuilder.TYPE_DES_TRANSIENT_DESELECT:
      case KeyBuilder.TYPE_DES_TRANSIENT_RESET:
        cipher = cspTDEA;
        break;

      case KeyBuilder.TYPE_AES:
      case KeyBuilder.TYPE_AES_TRANSIENT_DESELECT:
      case KeyBuilder.TYPE_AES_TRANSIENT_RESET:
        cipher = cspAES;
        break;

      default:
        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        return (short) 0;
    }

    cipher.init(theKey, Cipher.MODE_ENCRYPT);
    return cipher.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  /**
   * Signs the passed precomputed hash
   *
   * @param theKey The key to perform the operation with
   * @param inBuffer contains the precomputed hash
   * @param inOffset the location of the first byte of the hash
   * @param inLength the length og the computed hash
   * @param outBuffer the buffer to contain the signature
   * @param outOffset the location of the first byte of the signature
   * @return the length of the signature
   */
  short doSign(
      ECPrivateKey theKey,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset) {
    Signature signer = null;

    switch (inLength) {
      case MessageDigest.LENGTH_SHA_256:
        signer = cspECCSHA256;
        break;
      case MessageDigest.LENGTH_SHA_384:
        signer = cspECCSHA384;
        break;
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        return (short) 0; // Keep compiler happy
    }

    signer.init(theKey, Signature.MODE_SIGN);
    return signer.signPreComputedHash(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  boolean doVerify(
      ECPublicKey theKey,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] signature,
      short signatureOffset,
      short signatureLength) {
    Signature verifier = null;

    switch (inLength) {
      case MessageDigest.LENGTH_SHA_256:
        verifier = cspECCSHA256;
        break;
      case MessageDigest.LENGTH_SHA_384:
        verifier = cspECCSHA384;
        break;
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        return false;
    }

    verifier.init(theKey, Signature.MODE_VERIFY);
    return verifier.verifyPreComputedHash(
        inBuffer, inOffset, inLength, signature, signatureOffset, signatureLength);
  }

  short doSha256(
      byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
    return cspSHA256.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  // #if VCI_CS7
  short doSha384(
      byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
    return cspSHA384.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }
  // #endif

  /**
   * Suite hash for OPACITY KDF: SHA-256 when {@code fieldLen == 32} (CS2), SHA-384 when {@code
   * fieldLen == 48} (CS7).
   */
  short doSha(
      short fieldLen,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset) {
    // #if VCI_CS2
    return doSha256(inBuffer, inOffset, inLength, outBuffer, outOffset);
    // #else
    if (fieldLen == (short) 32) {
      return doSha256(inBuffer, inOffset, inLength, outBuffer, outOffset);
    }
    return doSha384(inBuffer, inOffset, inLength, outBuffer, outOffset);
    // #endif
  }

  short doAesCmac(
      SecretKey key,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset) {
    requireAesCmac(ISO7816.SW_FUNC_NOT_SUPPORTED);
    cspAESCMAC.init(key, Signature.MODE_SIGN);
    return cspAESCMAC.sign(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  void doAesCmacInit(SecretKey key) {
    requireAesCmac(ISO7816.SW_FUNC_NOT_SUPPORTED);
    cspAESCMAC.init(key, Signature.MODE_SIGN);
  }

  void doAesCmacUpdate(byte[] inBuffer, short inOffset, short inLength) {
    if (inLength != (short) 0) {
      cspAESCMAC.update(inBuffer, inOffset, inLength);
    }
  }

  short doAesCmacFinal(
      byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
    requireAesCmac(ISO7816.SW_FUNC_NOT_SUPPORTED);
    return cspAESCMAC.sign(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  void doAesResponseCmacInit(SecretKey key) {
    requireAesCmac(ISO7816.SW_FUNC_NOT_SUPPORTED);
    cspAESResponseCMAC.init(key, Signature.MODE_SIGN);
  }

  void doAesResponseCmacUpdate(byte[] inBuffer, short inOffset, short inLength) {
    if (inLength != (short) 0) cspAESResponseCMAC.update(inBuffer, inOffset, inLength);
  }

  short doAesResponseCmacFinal(
      byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
    requireAesCmac(ISO7816.SW_FUNC_NOT_SUPPORTED);
    return cspAESResponseCMAC.sign(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  void requireAesCmac(short sw) {
    if (cspAESCMAC == null || cspAESResponseCMAC == null) ISOException.throwIt(sw);
  }

  short doAesEcbEncrypt(
      SecretKey key,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset) {
    cspAES.init(key, Cipher.MODE_ENCRYPT);
    return cspAES.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  short doAesCbcDecrypt(
      SecretKey key,
      byte[] iv,
      short ivOffset,
      short ivLength,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset) {
    cspAESCBC.init(key, Cipher.MODE_DECRYPT, iv, ivOffset, ivLength);
    return cspAESCBC.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  /**
   * Starts stateful AES-CBC decryption for protected data that spans APDU frames.
   *
   * <p>SP 800-73-5 Part 2, Section 4.2.2 encrypts the padded command data with AES-CBC. The caller
   * supplies the session encryption key and the command IV derived for that logical command.
   *
   * @param key active session encryption key
   * @param iv initialization-vector buffer
   * @param ivOffset first IV octet
   * @param ivLength IV length, which must equal one AES block
   */
  void doAesCbcDecryptInit(SecretKey key, byte[] iv, short ivOffset, short ivLength) {
    cspAESCBC.init(key, Cipher.MODE_DECRYPT, iv, ivOffset, ivLength);
  }

  /**
   * Decrypts one or more non-final AES-CBC blocks and preserves cipher state.
   *
   * @return number of plaintext octets written
   */
  short doAesCbcDecryptUpdate(
      byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
    return cspAESCBC.update(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  /**
   * Decrypts the final AES-CBC blocks and closes the stateful cipher operation.
   *
   * @return number of plaintext octets written
   */
  short doAesCbcDecryptFinal(
      byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
    return cspAESCBC.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  static AESKey buildTransientAes128Key() {
    return buildTransientAesKey(KeyBuilder.LENGTH_AES_128);
  }

  /** Builds a clear-on-deselect AES key of the given bit length (128 or 256). */
  static AESKey buildTransientAesKey(short keyLengthBits) {
    return (AESKey)
        KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, keyLengthBits, false);
  }

  /**
   * Builds a clear-on-reset AES key for PIV secure-messaging session keys.
   *
   * <p>SP 800-73-5 Part 2 Section 3.1.1 keeps all security status indicators unchanged when the PIV
   * Card Application is reselected, and JCRE 3.0.5 Section 5.1 clears CLEAR_ON_DESELECT memory on
   * reselection. The owner clears these keys explicitly on a genuine deselect.
   */
  static AESKey buildSessionAesKey(short keyLengthBits) {
    return (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, keyLengthBits, false);
  }

  /**
   * Signs a pre-formatted block of data using a raw RSA private key operation.
   *
   * <p>PIV supplies the complete encoded message representative, so Java Card signature primitives
   * would hash or pad data that is already formatted. Raw private-key RSA is the required
   * operation.
   *
   * @param theKey The key to perform the operation with
   * @param inBuffer contains the precomputed hash
   * @param inOffset the location of the first byte of the hash
   * @param inLength the length og the computed hash
   * @param outBuffer the buffer to contain the signature
   * @param outOffset the location of the first byte of the signature
   * @return the length of the signature
   */
  short doSign(
      RSAPrivateKey theKey,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset) {
    cspRSA.init(theKey, Cipher.MODE_ENCRYPT);
    return cspRSA.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  /**
   * Performs a key agreement operation
   *
   * @param theKey The key to perform the operation with
   * @param inBuffer the input to the key agreement operation
   * @param inOffset the the location of first byte of the key agreement input
   * @param inLength the length of the key agreement input
   * @param outBuffer the key agreement output
   * @param outOffset the location of the first byte of the key agreement output
   * @return the length of the key agreement output
   */
  short doKeyAgreement(
      ECPrivateKey theKey,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset,
      ECPointValidator validator,
      ECParams params) {

    // Reject malformed points before invoking providers whose length handling varies by platform.
    // The canonical validator checks the 04 || X || Y encoding, its length for the key's curve,
    // the coordinate range and the curve equation. SP 800-73-5 Part 2 Table 16 C4: "Return
    // '6A 80' if public-key validation fails."
    if (!validator.isValid(inBuffer, inOffset, inLength, params)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    cspECDH.init(theKey);
    return cspECDH.generateSecret(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  /**
   * Performs an RSA Key Transport operation, which is effectively a decryption of a pre-formatted
   * RSA block with the private key.
   *
   * @param theKey The key to perform the operation with
   * @param inBuffer the input to the key agreement operation
   * @param inOffset the the location of first byte of the key agreement input
   * @param inLength the length of the key agreement input
   * @param outBuffer the key agreement output
   * @param outOffset the location of the first byte of the key agreement output
   * @return the length of the key agreement output
   */
  short doKeyTransport(
      RSAPrivateKey theKey,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset) {
    short comparisonLength = (short) (theKey.getSize() >> (short) 3); // divide by 8
    // Reject malformed blocks before invoking providers whose length handling varies by platform.
    if (inLength != comparisonLength) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      return (short) 0; // Keep compiler happy
    } else {
      cspRSA.init(theKey, Cipher.MODE_DECRYPT);
      return cspRSA.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
    }
  }

  short doRsaPublic(
      RSAPublicKey key,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset) {
    cspRSA.init(key, Cipher.MODE_DECRYPT);
    return cspRSA.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  /**
   * Generates a number of random bytes using the SECURE_RANDOM generator
   *
   * @param buffer The buffer to write the random data to
   * @param offset The starting offset to write the random data
   * @param length The number of bytes to generate
   */
  void doGenerateRandom(byte[] buffer, short offset, short length) {
    cspRNG.generateData(buffer, offset, length);
  }
}
