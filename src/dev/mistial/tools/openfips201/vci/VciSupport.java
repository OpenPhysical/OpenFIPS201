/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
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

package dev.mistial.tools.openfips201.vci;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Host-side helpers for the PIV VCI (secure messaging, OPACITY ZKM) flow used by the VCI tool and
 * known-answer vector tests.
 *
 * <p>This deliberately mirrors the byte-level contract implemented by the applet ({@code
 * PIV.generalAuthenticateCase1A} / {@code PIVSecureMessaging}) and by the OpenPhysical .NET stack
 * ({@code PivSecureMessagingBootstrapper} / {@code PivSecureMessagingProvider}).
 *
 * <p>Cipher Suite 2 (ECC P-256, AES-128, SHA-256) and Cipher Suite 7 (ECC P-384, AES-256, SHA-384)
 * match the applet's OPACITY/SM implementation. Host tools may still default to CS2 for
 * provisioning; CS7 is fully supported for known-answer tests and SM wrap/unwrap.
 *
 * <p>The CVC profile is the cross-repo contract documented in the VCI plan: a {@code 7F21} card
 * verifiable certificate carrying the card SM public key in {@code 7F49/86} and an ECDSA signature
 * in {@code 5F37} over all preceding bytes of the {@code 7F21} value.
 */
final class VciSupport {

  static final byte ALG_CS2 = (byte) 0x27;
  static final byte ALG_CS7 = (byte) 0x2E;
  static final byte KEY_REF_SECURE_MESSAGING = (byte) 0x04;

  // CVC tags (SP 800-73-4-shaped).
  static final int TAG_CVC = 0x7F21;
  static final int TAG_CVC_PROFILE = 0x5F29;
  static final int TAG_CVC_ISSUER_ID = 0x42;
  static final int TAG_CVC_SUBJECT_ID = 0x5F20;
  static final int TAG_CVC_PUBLIC_KEY = 0x7F49;
  static final int TAG_CVC_PUBLIC_KEY_OID = 0x06;
  static final int TAG_CVC_PUBLIC_POINT = 0x86;
  static final int TAG_CVC_ROLE = 0x5F4C;
  static final int TAG_CVC_SIGNATURE = 0x5F37;
  static final byte CVC_PROFILE_IDENTIFIER = (byte) 0x80;

  // Role byte per the secure-messaging CVC profile, matching production PIV cards (0x00).
  static final byte CVC_ROLE_KEY_ESTABLISHMENT = (byte) 0x00;

  // Named-curve OID content in 7F49/06 (production cards).
  private static final byte[] CURVE_OID_P256 = {
    0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x03, 0x01, 0x07
  }; // prime256v1
  private static final byte[] CURVE_OID_P384 = {0x2B, (byte) 0x81, 0x04, 0x00, 0x22}; // secp384r1

  private static final byte[] KEY_CONFIRMATION_CONTEXT = {0x4B, 0x43, 0x5F, 0x31, 0x5F, 0x56};
  private static final int COORD_LENGTH_CS2 = 32;
  private static final int COORD_LENGTH_CS7 = 48;

  private VciSupport() {}

  static boolean isCs2(byte suite) {
    return suite == ALG_CS2;
  }

  static boolean isCs7(byte suite) {
    return suite == ALG_CS7;
  }

  /** ECC field length in bytes: 32 (CS2) or 48 (CS7). */
  static int coordLength(byte suite) {
    if (isCs2(suite)) {
      return COORD_LENGTH_CS2;
    }
    if (isCs7(suite)) {
      return COORD_LENGTH_CS7;
    }
    throw new IllegalArgumentException(
        "Unsupported cipher suite 0x" + Integer.toHexString(suite & 0xFF));
  }

  /** AES session-key length: field − 16 (16 for CS2, 32 for CS7). */
  static int sessionKeyLength(byte suite) {
    return coordLength(suite) - 16;
  }

  /** OtherInfo algorithmID second byte: 0x09 (CS2) or 0x0D (CS7). */
  private static byte opacityAlgIdByte(byte suite) {
    return (byte) (coordLength(suite) == COORD_LENGTH_CS2 ? 0x09 : 0x0D);
  }

  // ---------------------------------------------------------------------------------------------
  // CVC build / verify
  // ---------------------------------------------------------------------------------------------

  /**
   * Builds the CVC body (value of outer {@code 7F21}) for the card SM public point. Curve OID is
   * selected from point length (65 → P-256/CS2, 97 → P-384/CS7).
   */
  static byte[] buildCvcBody(byte[] cardPublicPoint, byte[] issuerId, byte[] subjectId) {
    byte[] curveOid =
        cardPublicPoint.length == 1 + COORD_LENGTH_CS7 * 2 ? CURVE_OID_P384 : CURVE_OID_P256;
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    writeTlv(body, TAG_CVC_PROFILE, new byte[] {CVC_PROFILE_IDENTIFIER});
    writeTlv(body, TAG_CVC_ISSUER_ID, issuerId);
    writeTlv(body, TAG_CVC_SUBJECT_ID, subjectId);
    ByteArrayOutputStream keyTemplate = new ByteArrayOutputStream();
    writeTlv(keyTemplate, TAG_CVC_PUBLIC_KEY_OID, curveOid);
    writeTlv(keyTemplate, TAG_CVC_PUBLIC_POINT, cardPublicPoint);
    writeTlv(body, TAG_CVC_PUBLIC_KEY, keyTemplate.toByteArray());
    writeTlv(body, TAG_CVC_ROLE, new byte[] {CVC_ROLE_KEY_ESTABLISHMENT});
    return body.toByteArray();
  }

  /** Assembles a CVC with ECDSA-SHA256 (CS2 default). */
  static byte[] assembleCvc(byte[] cvcBody, byte[] ecdsaSigValueDer) {
    return assembleCvc(cvcBody, ecdsaSigValueDer, ALG_CS2);
  }

  /**
   * Assembles {@code 7F21} with {@code 5F37} as AlgorithmIdentifier + BIT STRING(ECDSA-Sig-Value).
   * CS2 uses ecdsa-with-SHA256; CS7 uses ecdsa-with-SHA384.
   */
  static byte[] assembleCvc(byte[] cvcBody, byte[] ecdsaSigValueDer, byte suite) {
    try {
      ByteArrayOutputStream value = new ByteArrayOutputStream();
      value.write(cvcBody, 0, cvcBody.length);

      ASN1EncodableVector algorithmId = new ASN1EncodableVector();
      algorithmId.add(
          isCs7(suite)
              ? X9ObjectIdentifiers.ecdsa_with_SHA384
              : X9ObjectIdentifiers.ecdsa_with_SHA256);
      ASN1EncodableVector signatureValue = new ASN1EncodableVector();
      signatureValue.add(new DERSequence(algorithmId));
      signatureValue.add(new DERBitString(ecdsaSigValueDer));
      byte[] wrapped = new DERSequence(signatureValue).getEncoded("DER");

      byte[] sigTlv = tlv(TAG_CVC_SIGNATURE, wrapped);
      value.write(sigTlv, 0, sigTlv.length);
      return tlv(TAG_CVC, value.toByteArray());
    } catch (Exception e) {
      throw new IllegalStateException("Failed to assemble CVC signature value", e);
    }
  }

  /**
   * Verifies a card CVC against the signer public key. Accepts ECDSA-SHA256 or ECDSA-SHA384 (CS2 /
   * CS7 production encodings).
   */
  static boolean verifyCvc(byte[] cvc, PublicKey signerPublicKey) {
    try {
      int[] outer = locateTlv(cvc, 0, TAG_CVC);
      if (outer == null) {
        return false;
      }
      int valueOffset = outer[1];
      int valueLength = outer[2];

      int[] signature = locateTlv(cvc, valueOffset, TAG_CVC_SIGNATURE);
      if (signature == null) {
        return false;
      }
      int signatureTagOffset = signature[0];
      if (signature[1] + signature[2] != valueOffset + valueLength) {
        return false;
      }

      int signedLength = signatureTagOffset - valueOffset;
      byte[] signatureField = Arrays.copyOfRange(cvc, signature[1], signature[1] + signature[2]);
      byte[] rawSig = unwrapCvcSignature(signatureField);
      // Try both suite hashes; production CS2=SHA256, CS7=SHA384.
      for (String jca : new String[] {"SHA256withECDSA", "SHA384withECDSA"}) {
        try {
          Signature verifier = Signature.getInstance(jca);
          verifier.initVerify(signerPublicKey);
          verifier.update(cvc, valueOffset, signedLength);
          if (verifier.verify(rawSig)) {
            return true;
          }
        } catch (Exception ignored) {
          // try next
        }
      }
      return false;
    } catch (Exception e) {
      return false;
    }
  }

  /**
   * Returns the raw ECDSA-Sig-Value (DER {@code SEQUENCE&#123;r,s&#125;}) from a {@code 5F37}
   * signature field that is either that raw value or a DER-wrapped X.509 SignatureValue ({@code
   * SEQUENCE&#123;AlgorithmIdentifier, BIT STRING&#123;ECDSA-Sig-Value&#125;&#125;}).
   */
  private static byte[] unwrapCvcSignature(byte[] signatureField) {
    try {
      ASN1Primitive parsed = ASN1Primitive.fromByteArray(signatureField);
      if (parsed instanceof ASN1Sequence) {
        ASN1Sequence sequence = (ASN1Sequence) parsed;
        if (sequence.size() == 2
            && sequence.getObjectAt(0) instanceof ASN1Sequence
            && sequence.getObjectAt(1) instanceof ASN1BitString) {
          return ((ASN1BitString) sequence.getObjectAt(1)).getOctets();
        }
      }
    } catch (Exception e) {
      // Not DER-wrapped; treat the field as a raw ECDSA-Sig-Value.
    }
    return signatureField;
  }

  /** Extracts the uncompressed card SM public point ({@code 04 || X || Y}) from a CVC. */
  static byte[] extractCardPublicPoint(byte[] cvc) {
    int[] outer = locateTlv(cvc, 0, TAG_CVC);
    if (outer == null) {
      throw new IllegalArgumentException("CVC missing 7F21");
    }
    int[] keyTemplate = locateTlv(cvc, outer[1], TAG_CVC_PUBLIC_KEY);
    if (keyTemplate == null) {
      throw new IllegalArgumentException("CVC missing 7F49 public key template");
    }
    int[] point = locateTlv(cvc, keyTemplate[1], TAG_CVC_PUBLIC_POINT);
    if (point == null) {
      throw new IllegalArgumentException("CVC missing 86 public point");
    }
    return Arrays.copyOfRange(cvc, point[1], point[1] + point[2]);
  }

  // ---------------------------------------------------------------------------------------------
  // OPACITY CS2 establishment (host side)
  // ---------------------------------------------------------------------------------------------

  /** Result of a successful OPACITY establishment: the four 16-byte session keys. */
  static final class SessionKeys {
    final byte[] skCfrm;
    final byte[] skMac;
    final byte[] skEnc;
    final byte[] skRmac;

    SessionKeys(byte[] skCfrm, byte[] skMac, byte[] skEnc, byte[] skRmac) {
      this.skCfrm = skCfrm;
      this.skMac = skMac;
      this.skEnc = skEnc;
      this.skRmac = skRmac;
    }
  }

  static X9ECParameters p256() {
    return SECNamedCurves.getByName("secp256r1");
  }

  static X9ECParameters p384() {
    return SECNamedCurves.getByName("secp384r1");
  }

  static X9ECParameters curveForSuite(byte suite) {
    return isCs7(suite) ? p384() : p256();
  }

  /** Uncompressed {@code 04 || X || Y} for P-256 or P-384. */
  static byte[] encodePoint(ECPoint point) {
    return point.getEncoded(false);
  }

  /** Witness body: {@code idH(8 zeros) || Q_eH}. Caller prefixes CB_H (0x00). */
  static byte[] buildWitness(byte[] hostPublicPoint) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(new byte[8], 0, 8);
    out.write(hostPublicPoint, 0, hostPublicPoint.length);
    return out.toByteArray();
  }

  /** JCA signature algorithm for signing a CVC of the given suite. */
  static String cvcSignatureAlgorithm(byte suite) {
    return isCs7(suite) ? "SHA384withECDSA" : "SHA256withECDSA";
  }

  /** Named curve for suite CA / host ephemeral keys. */
  static String namedCurve(byte suite) {
    return isCs7(suite) ? "secp384r1" : "secp256r1";
  }

  /** SHA-256 of the raw CVC bytes, first 8 bytes (idSicc). */
  static byte[] computeIdSicc(byte[] cvcRaw) {
    return Arrays.copyOf(sha256(cvcRaw), 8);
  }

  /**
   * Derives CS2 session keys (AES-128 / SHA-256).
   *
   * @see #deriveSessionKeys(byte, byte[], byte[], byte[], byte[], byte[])
   */
  static SessionKeys deriveSessionKeys(
      byte[] sharedSecret, byte[] idH, byte[] hostPublicPoint, byte[] idSicc, byte[] nIcc) {
    return deriveSessionKeys(ALG_CS2, sharedSecret, idH, hostPublicPoint, idSicc, nIcc);
  }

  /**
   * Derives OPACITY session keys for CS2 or CS7 (Part 2 Section 4.1.6). One path for both suites;
   * geometry follows ECC field length (32 → SHA-256/AES-128, 48 → SHA-384/AES-256).
   */
  static SessionKeys deriveSessionKeys(
      byte suite,
      byte[] sharedSecret,
      byte[] idH,
      byte[] hostPublicPoint,
      byte[] idSicc,
      byte[] nIcc) {
    int field = coordLength(suite);
    int keyLen = sessionKeyLength(suite);
    int totalLen = keyLen * 4;
    byte[] otherInfo = buildOtherInfo(suite, idH, hostPublicPoint, idSicc, nIcc);
    byte[] derived = new byte[totalLen];
    int written = 0;
    for (int i = 1; written < totalLen; i++) {
      byte[] hash = kdfRound(suite, i, sharedSecret, otherInfo);
      int toCopy = Math.min(hash.length, totalLen - written);
      System.arraycopy(hash, 0, derived, written, toCopy);
      written += toCopy;
    }
    return new SessionKeys(
        Arrays.copyOfRange(derived, 0, keyLen),
        Arrays.copyOfRange(derived, keyLen, keyLen * 2),
        Arrays.copyOfRange(derived, keyLen * 2, keyLen * 3),
        Arrays.copyOfRange(derived, keyLen * 3, keyLen * 4));
  }

  /** Builds OPACITY OtherInfo (algorithmID || PartyUInfo || PartyVInfo). */
  static byte[] buildOtherInfo(
      byte suite, byte[] idH, byte[] hostPublicPoint, byte[] idSicc, byte[] nIcc) {
    byte alg = opacityAlgIdByte(suite);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(0x04);
    out.write(alg);
    out.write(alg);
    out.write(alg);
    out.write(alg);
    out.write(0x08);
    out.write(idH, 0, 8);
    out.write(0x01);
    out.write(0x00);
    out.write(0x10);
    out.write(hostPublicPoint, 1, 16); // T16(QeH)
    out.write(0x08);
    out.write(idSicc, 0, 8);
    out.write(nIcc.length);
    out.write(nIcc, 0, nIcc.length);
    out.write(0x01);
    out.write(0x00);
    return out.toByteArray();
  }

  /** Single KDF round: Hash(counter_be32 || Z || OtherInfo); hash follows field length. */
  static byte[] kdfRound(byte suite, int counter, byte[] sharedSecret, byte[] otherInfo) {
    ByteArrayOutputStream input = new ByteArrayOutputStream();
    input.write((counter >> 24) & 0xFF);
    input.write((counter >> 16) & 0xFF);
    input.write((counter >> 8) & 0xFF);
    input.write(counter & 0xFF);
    input.write(sharedSecret, 0, sharedSecret.length);
    input.write(otherInfo, 0, otherInfo.length);
    return coordLength(suite) == COORD_LENGTH_CS2
        ? sha256(input.toByteArray())
        : sha384(input.toByteArray());
  }

  /**
   * Computes the host's expected card authentication cryptogram: CMAC(skCfrm, "KC_1_V" || idSicc ||
   * idH || Xeh || Yeh).
   */
  static byte[] computeAuthCryptogram(
      byte[] skCfrm, byte[] idSicc, byte[] idH, byte[] hostPublicPoint) {
    ByteArrayOutputStream input = new ByteArrayOutputStream();
    input.write(KEY_CONFIRMATION_CONTEXT, 0, KEY_CONFIRMATION_CONTEXT.length);
    input.write(idSicc, 0, 8);
    input.write(idH, 0, 8);
    // Xeh || Yeh = hostPublicPoint without the leading 0x04
    input.write(hostPublicPoint, 1, hostPublicPoint.length - 1);
    return aesCmac(skCfrm, input.toByteArray());
  }

  // ---------------------------------------------------------------------------------------------
  // SM wrap / unwrap (host side; mirrors PIVSecureMessaging and PivSecureMessagingProvider)
  // ---------------------------------------------------------------------------------------------

  /** Mutable SM session counters/MCVs for a host-side client. */
  static final class SmSession {
    final byte[] skMac;
    final byte[] skEnc;
    final byte[] skRmac;
    final byte[] commandMcv = new byte[16];
    final byte[] responseMcv = new byte[16];
    final byte[] encCounter = new byte[16];
    byte lastCla;
    byte lastIns;

    SmSession(SessionKeys keys) {
      this.skMac = keys.skMac;
      this.skEnc = keys.skEnc;
      this.skRmac = keys.skRmac;
      encCounter[15] = 1;
    }
  }

  /**
   * Wraps a plaintext APDU (header + optional data + Le) into an SM-protected command APDU with CLA
   * 0x0C. Uses short or extended length encoding depending on the SM data field size.
   */
  static byte[] wrapCommand(
      SmSession session, byte ins, byte p1, byte p2, byte[] data, boolean expectLe) {
    session.lastCla = (byte) 0x0C;
    session.lastIns = ins;

    ByteArrayOutputStream dataField = new ByteArrayOutputStream();
    ByteArrayOutputStream macInput = new ByteArrayOutputStream();
    macInput.write(session.commandMcv, 0, 16);
    byte[] header = new byte[16];
    header[0] = 0x0C;
    header[1] = ins;
    header[2] = p1;
    header[3] = p2;
    header[4] = (byte) 0x80;
    macInput.write(header, 0, 16);

    if (data != null && data.length > 0) {
      byte[] iv = computeIv(session, false);
      byte[] padded = isoPad(data);
      byte[] ciphertext = aesCbc(true, session.skEnc, iv, padded);
      byte[] value = new byte[ciphertext.length + 1];
      value[0] = 0x01;
      System.arraycopy(ciphertext, 0, value, 1, ciphertext.length);
      byte[] encTlv = tlv(0x87, value);
      dataField.write(encTlv, 0, encTlv.length);
      macInput.write(encTlv, 0, encTlv.length);
    }

    if (expectLe) {
      byte[] leTlv = tlv(0x97, new byte[] {0x00});
      dataField.write(leTlv, 0, leTlv.length);
      macInput.write(leTlv, 0, leTlv.length);
    }

    byte[] fullMac = aesCmac(session.skMac, macInput.toByteArray());
    System.arraycopy(fullMac, 0, session.commandMcv, 0, 16);
    byte[] macTlv = tlv(0x8E, Arrays.copyOf(fullMac, 8));
    dataField.write(macTlv, 0, macTlv.length);

    byte[] body = dataField.toByteArray();
    ByteArrayOutputStream apdu = new ByteArrayOutputStream();
    apdu.write(0x0C);
    apdu.write(ins & 0xFF);
    apdu.write(p1 & 0xFF);
    apdu.write(p2 & 0xFF);
    if (body.length <= 255) {
      apdu.write(body.length);
      apdu.write(body, 0, body.length);
      apdu.write(0x00); // short Le = 256
    } else {
      // Extended length: outer Le of 0x0100 requests 256 bytes (matching production captures and
      // the OpenPhysical.Net SM provider). Note Le=0x0000 means 65536, not 256.
      apdu.write(0x00);
      apdu.write((body.length >> 8) & 0xFF);
      apdu.write(body.length & 0xFF);
      apdu.write(body, 0, body.length);
      apdu.write(0x01);
      apdu.write(0x00);
    }
    return apdu.toByteArray();
  }

  /**
   * Parses a plaintext command APDU into INS/P1/P2/data/Le for re-wrapping.
   *
   * @return {@code {ins, p1, p2, data, hasLe}} where data is a byte[] and hasLe is Boolean
   */
  static Object[] parsePlainCommand(byte[] plain) {
    if (plain == null) {
      throw new IllegalArgumentException("plain command is null");
    }
    if (plain.length < 4) {
      throw new IllegalArgumentException("plain command too short");
    }
    byte ins = plain[1];
    byte p1 = plain[2];
    byte p2 = plain[3];
    byte[] data = new byte[0];
    boolean hasLe = false;
    if (plain.length == 4) {
      // Case 1: no Lc, no Le
    } else if (plain.length == 5) {
      hasLe = true; // Case 2: Le only
    } else if (plain[4] == 0x00) {
      // Extended length
      if (plain.length < 7) {
        throw new IllegalArgumentException("extended plain command too short");
      }
      int lc = ((plain[5] & 0xFF) << 8) | (plain[6] & 0xFF);
      if (lc == 0) {
        if (plain.length != 7) {
          throw new IllegalArgumentException("extended Le-only command has trailing bytes");
        }
        hasLe = true;
        return new Object[] {ins, p1, p2, data, hasLe};
      }
      if (plain.length < 7 + lc) {
        throw new IllegalArgumentException("extended plain command truncated");
      }
      data = Arrays.copyOfRange(plain, 7, 7 + lc);
      if (plain.length == 7 + lc) {
        hasLe = false;
      } else if (plain.length == 7 + lc + 2) {
        hasLe = true;
      } else {
        throw new IllegalArgumentException("extended plain command has invalid Le length");
      }
    } else {
      int lc = plain[4] & 0xFF;
      if (plain.length < 5 + lc) {
        throw new IllegalArgumentException("short plain command truncated");
      }
      data = Arrays.copyOfRange(plain, 5, 5 + lc);
      if (plain.length == 5 + lc) {
        hasLe = false;
      } else if (plain.length == 5 + lc + 1) {
        hasLe = true;
      } else {
        throw new IllegalArgumentException("short plain command has trailing bytes");
      }
    }
    return new Object[] {ins, p1, p2, data, hasLe};
  }

  /** Holds the plaintext result of an unwrapped SM response. */
  static final class SmResponse {
    final byte[] data;
    final int statusWord;

    SmResponse(byte[] data, int statusWord) {
      this.data = data;
      this.statusWord = statusWord;
    }
  }

  /** Unwraps an SM response APDU (data || SW). Verifies the RMAC and decrypts. */
  static SmResponse unwrapResponse(SmSession session, byte[] response) {
    if (response.length < 2) {
      throw new IllegalArgumentException("SM response too short");
    }
    int sw = ((response[response.length - 2] & 0xFF) << 8) | (response[response.length - 1] & 0xFF);
    byte[] body = Arrays.copyOf(response, response.length - 2);
    if (sw != 0x9000) {
      // Errors may be returned unwrapped by the transport; surface as-is.
      return new SmResponse(new byte[0], sw);
    }

    int cursor = 0;
    int end = body.length;
    int encOffset = -1;
    int encLength = 0;
    int statusOffset = -1;
    int macValueOffset = -1;
    ByteArrayOutputStream rmacInput = new ByteArrayOutputStream();
    rmacInput.write(session.responseMcv, 0, 16);

    while (cursor < end) {
      BerTlvReader.Tlv tlv = BerTlvReader.read(body, cursor, end);
      if (tlv.tag == 0x87) {
        encOffset = tlv.valueOffset;
        encLength = tlv.length;
        rmacInput.write(body, cursor, tlv.nextOffset - cursor);
      } else if (tlv.tag == 0x99) {
        statusOffset = tlv.valueOffset;
        rmacInput.write(body, cursor, tlv.nextOffset - cursor);
      } else if (tlv.tag == 0x8E) {
        macValueOffset = tlv.valueOffset;
      }
      cursor = tlv.nextOffset;
    }

    if (macValueOffset < 0 || statusOffset < 0) {
      throw new IllegalStateException("SM response missing status or MAC");
    }
    byte[] fullRmac = aesCmac(session.skRmac, rmacInput.toByteArray());
    for (int i = 0; i < 8; i++) {
      if (fullRmac[i] != body[macValueOffset + i]) {
        throw new IllegalStateException("SM response MAC mismatch");
      }
    }
    System.arraycopy(fullRmac, 0, session.responseMcv, 0, 16);

    int statusSw = ((body[statusOffset] & 0xFF) << 8) | (body[statusOffset + 1] & 0xFF);

    byte[] plaintext = new byte[0];
    if (encOffset >= 0) {
      if (body[encOffset] != 0x01) {
        throw new IllegalStateException("SM response bad padding indicator");
      }
      byte[] iv = computeIv(session, true);
      byte[] ciphertext = Arrays.copyOfRange(body, encOffset + 1, encOffset + encLength);
      byte[] decrypted = aesCbc(false, session.skEnc, iv, ciphertext);
      plaintext = isoUnpad(decrypted);
    }

    if (shouldIncrementCounter(session)) {
      incrementCounter(session.encCounter);
    }
    return new SmResponse(plaintext, statusSw);
  }

  private static boolean shouldIncrementCounter(SmSession session) {
    if ((session.lastIns & 0xFF) == 0xC0) {
      return false;
    }
    return session.lastCla != (byte) 0x1C;
  }

  private static byte[] computeIv(SmSession session, boolean response) {
    byte[] counter = Arrays.copyOf(session.encCounter, 16);
    if (response) {
      counter[0] = (byte) (counter[0] | 0x80);
    }
    return aesEcbBlock(session.skEnc, counter);
  }

  private static void incrementCounter(byte[] counter) {
    for (int i = 15; i >= 0; i--) {
      counter[i]++;
      if (counter[i] != 0) {
        return;
      }
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Primitives
  // ---------------------------------------------------------------------------------------------

  static byte[] sha256(byte[] input) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(input);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  static byte[] sha384(byte[] input) {
    try {
      return MessageDigest.getInstance("SHA-384").digest(input);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  static byte[] aesCmac(byte[] key, byte[] data) {
    CMac mac = new CMac(AESEngine.newInstance());
    mac.init(new KeyParameter(key));
    mac.update(data, 0, data.length);
    byte[] out = new byte[mac.getMacSize()];
    mac.doFinal(out, 0);
    return out;
  }

  private static byte[] aesEcbBlock(byte[] key, byte[] block) {
    try {
      Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
      return cipher.doFinal(block);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static byte[] aesCbc(boolean encrypt, byte[] key, byte[] iv, byte[] input) {
    try {
      Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
      cipher.init(
          encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
          new SecretKeySpec(key, "AES"),
          new IvParameterSpec(iv));
      return cipher.doFinal(input);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static byte[] isoPad(byte[] input) {
    int paddingLength = 16 - (input.length % 16);
    byte[] padded = new byte[input.length + paddingLength];
    System.arraycopy(input, 0, padded, 0, input.length);
    padded[input.length] = (byte) 0x80;
    return padded;
  }

  private static byte[] isoUnpad(byte[] input) {
    for (int i = input.length - 1; i >= 0; i--) {
      if (input[i] == (byte) 0x80) {
        return Arrays.copyOf(input, i);
      }
      if (input[i] != 0x00) {
        break;
      }
    }
    throw new IllegalStateException("Invalid ISO 7816 padding");
  }

  // ---------------------------------------------------------------------------------------------
  // Minimal BER-TLV (single/double-byte tags, up to 3-byte length)
  // ---------------------------------------------------------------------------------------------

  static byte[] tlv(int tag, byte[] value) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    writeTlv(out, tag, value);
    return out.toByteArray();
  }

  private static void writeTlv(ByteArrayOutputStream out, int tag, byte[] value) {
    if (tag > 0xFF) {
      out.write((tag >> 8) & 0xFF);
    }
    out.write(tag & 0xFF);
    int length = value.length;
    if (length < 0x80) {
      out.write(length);
    } else if (length <= 0xFF) {
      out.write(0x81);
      out.write(length);
    } else {
      out.write(0x82);
      out.write((length >> 8) & 0xFF);
      out.write(length & 0xFF);
    }
    out.write(value, 0, value.length);
  }

  /**
   * Locates the first TLV with the given tag scanning forward from {@code offset}; returns {@code
   * {tagOffset, valueOffset, length}} or null.
   */
  static int[] locateTlv(byte[] data, int offset, int tag) {
    BerTlvReader.Tlv tlv = BerTlvReader.locate(data, offset, tag);
    return tlv == null ? null : new int[] {tlv.tagOffset, tlv.valueOffset, tlv.length};
  }

  static byte[] issuerIdFromPublicKey(PublicKey signerPublicKey) {
    // issuer-id = SHA-256(SubjectPublicKeyInfo)[0:8]
    return Arrays.copyOf(sha256(signerPublicKey.getEncoded()), 8);
  }
}
